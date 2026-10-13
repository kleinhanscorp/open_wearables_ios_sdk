import Foundation

/// The SDK's own account of its credentials. Persisted, so a lockout discovered at 04:00 by a
/// background wake is still visible to the host app at 08:00 — the host does not have to have
/// been alive to hear an `onAuthError`.
///
/// - `ok`:              the pair is believed good (or has just been repaired).
/// - `recovering`:      the refresh token was rejected; a renewal is in flight or backing off.
/// - `reauthRequired`:  refresh AND renewal are exhausted; only the host can re-vend.
public enum OWAuthState: String {
    case ok = "ok"
    case recovering = "recovering"
    case reauthRequired = "reauth_required"
}

/// Gutsy fork — AUTH SELF-HEALING WITHOUT A HOST RUNTIME.
///
/// Open Wearables rotates refresh tokens strictly: `POST /token/refresh` revokes the presented
/// token and mints a new one, with no grace window (the-momentum/open-wearables#1379,
/// open_wearables_ios_sdk#40). The moment the server answers 200, the old token is dead. If this
/// process is suspended before the new pair is persisted — routine during HealthKit background
/// delivery — the device holds a revoked token and every later request is a 401, forever. The
/// only recovery upstream offers is a fresh sign-in from the host app, which is exactly what a
/// suspended background process cannot perform.
///
/// This extension closes that with three layers, each independent of the host:
///   1. **Double-check before despair.** A rejected refresh is re-read from the Keychain; if a
///      concurrent writer already installed a newer pair, that pair is used (#40's race).
///   2. **Native renewal.** A long-lived, non-rotating renewal credential handed over by the host
///      at sign-in can mint a fresh pair at a host-owned endpoint — no JS, no member action.
///   3. **A sticky state ledger** the host reads at launch, so a lockout survives the process that
///      discovered it.
///
/// Stored properties live on the main class (`renewalLock`, `isRenewing`, `renewalCallbacks`,
/// `onAuthStateChanged`, `onAuthRecovered`) — Swift extensions cannot declare storage.
extension OpenWearablesHealthSDK {

    internal enum RenewalOutcome {
        /// A fresh pair was minted and persisted.
        case renewed
        /// The renewal credential itself was rejected (401/403/410) — terminal for this layer.
        case rejected
        /// Network / 5xx / 429 / kill switch — try again on a later trigger.
        case transient
        /// No renewal credential is installed on this device.
        case unavailable
    }

    /// Minimum spacing between renewal calls. A refresh storm must never become a renewal storm.
    private static let renewalMinGap: TimeInterval = 60
    /// Consecutive rejections after which the SDK stops asking and reports `reauthRequired`.
    private static let renewalMaxConsecutiveRejections = 2
    /// Access tokens that expire inside this window are refreshed proactively by `ensureFreshSession`.
    private static let freshnessHorizon: TimeInterval = 5 * 60

    // MARK: - Public API

    /// Install (or replace) the renewal credential. Clears any prior renewal backoff and lifts a
    /// `reauthRequired` verdict — the host is telling us it has a new lever to pull.
    public func setRenewalCredential(url: String, token: String) {
        OpenWearablesHealthSdkKeychain.saveRenewalCredential(url: url, token: token)
        OpenWearablesHealthSdkKeychain.setRenewalFailures(0)
        OpenWearablesHealthSdkKeychain.setLastRenewalAttemptAt(nil)
        if authState == .reauthRequired && hasAuth {
            transitionAuthState(.ok)
        }
        logMessage("Renewal credential installed")
    }

    /// Remove the renewal credential (the host disconnected, or is rotating it).
    public func clearRenewalCredential() {
        OpenWearablesHealthSdkKeychain.clearRenewalCredential()
        logMessage("Renewal credential cleared")
    }

    /// Whether a renewal credential is installed.
    public var hasRenewalCredential: Bool {
        return OpenWearablesHealthSdkKeychain.hasRenewalCredential()
    }

    /// The persisted auth verdict.
    public var authState: OWAuthState {
        return OWAuthState(rawValue: OpenWearablesHealthSdkKeychain.getAuthState()) ?? .ok
    }

    /// Snapshot for bridges: state, timestamps, whether renewal exists, and when the access token
    /// expires (decoded from the JWT — no network).
    public func getAuthState() -> [String: Any?] {
        let iso = ISO8601DateFormatter()
        return [
            "state": authState.rawValue,
            "deviceLeaseRejected": OpenWearablesHealthSdkKeychain.deviceLeaseRejected(),
            "lastAuthErrorAt": OpenWearablesHealthSdkKeychain.getLastAuthErrorAt().map { iso.string(from: $0) },
            "lastRecoveredAt": OpenWearablesHealthSdkKeychain.getLastRecoveredAt().map { iso.string(from: $0) },
            "hasRenewalCredential": !OpenWearablesHealthSdkKeychain.connectionBlocked() && hasRenewalCredential,
            "renewalFailures": OpenWearablesHealthSdkKeychain.getRenewalFailures(),
            "accessTokenExpiresAt": OpenWearablesHealthSdkKeychain.connectionBlocked() ? nil : accessTokenExpiry().map { iso.string(from: $0) },
            "hasSession": OpenWearablesHealthSdkKeychain.hasSession()
        ]
    }

    /// Prove — or repair — the session NOW, on the host's schedule (typically app foreground).
    ///
    /// Refresh tokens are single-use, so this is the ONLY sanctioned way for a host to "check"
    /// them: the SDK refreshes under its own single-flight lock and, if the server rejects the
    /// token, walks the recovery ladder itself. The host never touches a refresh token.
    ///
    /// Completion values: `"ok"` (nothing to do) · `"refreshed"` · `"recovered"` (via renewal) ·
    /// `"reauth_required"` · `"network_error"` · `"no_session"` · `"api_key"`.
    public func ensureFreshSession(expectedGeneration: String? = nil, completion: @escaping (String) -> Void) {
        OpenWearablesHealthSdkKeychain.connectionLock.lock()
        defer { OpenWearablesHealthSdkKeychain.connectionLock.unlock() }
        let owner = OpenWearablesHealthSdkKeychain.connectionOwner()
        guard OpenWearablesHealthSdkKeychain.isCurrent(owner),
              expectedGeneration == nil || expectedGeneration == owner.generation else { completion("network_error"); return }
        guard userId != nil, hasAuth else {
            completion("no_session")
            return
        }
        if isApiKeyAuth {
            completion("api_key")
            return
        }
        if authState != .reauthRequired,
           let exp = accessTokenExpiry(),
           exp.timeIntervalSinceNow > Self.freshnessHorizon {
            completion("ok")
            return
        }

        let recoveredBefore = OpenWearablesHealthSdkKeychain.getLastRecoveredAt()
        attemptTokenRefresh { [weak self] result in
            guard let self = self else { completion("network_error"); return }
            guard OpenWearablesHealthSdkKeychain.isCurrent(owner) else { completion("network_error"); return }
            switch result {
            case .success:
                let recoveredAfter = OpenWearablesHealthSdkKeychain.getLastRecoveredAt()
                let viaRenewal = recoveredAfter != nil && recoveredAfter != recoveredBefore
                completion(viaRenewal ? "recovered" : "refreshed")
                self.retryOutboxIfPossible()
            case .authFailure:
                completion("reauth_required")
            case .networkError:
                completion("network_error")
            }
        }
    }

    /// Read-only lease proof, using the existing host endpoint and its auth rate controls.
    internal func validateDeviceLease(owner: OpenWearablesHealthSdkKeychain.ConnectionOwner,
                                      completion: @escaping (Bool) -> Void) {
        OpenWearablesHealthSdkKeychain.connectionLock.lock()
        defer { OpenWearablesHealthSdkKeychain.connectionLock.unlock() }
        guard OpenWearablesHealthSdkKeychain.isCurrent(owner) else { completion(false); return }
        leaseValidationLock.lock()
        if leaseValidationGeneration == owner.generation {
            leaseValidationCallbacks.append(completion); leaseValidationLock.unlock(); return
        }
        guard Date() >= leaseValidationBackoffUntil else { leaseValidationLock.unlock(); completion(false); return }
        leaseValidationGeneration = owner.generation; leaseValidationCallbacks = [completion]
        leaseValidationLock.unlock()
        guard let urlString = OpenWearablesHealthSdkKeychain.getRenewalUrl(), let url = URL(string: urlString),
              let token = OpenWearablesHealthSdkKeychain.getRenewalToken(),
              let generation = OpenWearablesHealthSdkKeychain.deviceConnectionGeneration() else {
            finishLeaseValidation(owner: owner, active: false, backoff: 60); return
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"; request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["renewal_token": token, "validate_only": true])
        foregroundSession.dataTask(with: request) { [weak self] data, response, error in
            OpenWearablesHealthSdkKeychain.connectionLock.lock()
            defer { OpenWearablesHealthSdkKeychain.connectionLock.unlock() }
            guard let self = self, OpenWearablesHealthSdkKeychain.isCurrent(owner) else { return }
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            if status == 401 || status == 403 || status == 410 {
                OpenWearablesHealthSdkKeychain.setDeviceLeaseRejected(true)
                self.markReauthRequired(); self.invalidateConnection(); return
            }
            guard error == nil, (200...299).contains(status), let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                let retry = (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Retry-After").flatMap(Double.init)
                self.finishLeaseValidation(owner: owner, active: false, backoff: status == 429 ? min(3600, max(60, retry ?? 900)) : 60)
                return
            }
            let active = json["lease_active"] as? Bool == true && json["connection_generation"] as? String == generation &&
                json["device_id"] as? String == self.deviceId()
            self.finishLeaseValidation(owner: owner, active: active, backoff: active ? 0 : 60)
        }.resume()
    }
    private func finishLeaseValidation(owner: OpenWearablesHealthSdkKeychain.ConnectionOwner, active: Bool, backoff: TimeInterval) {
        leaseValidationLock.lock()
        guard leaseValidationGeneration == owner.generation else { leaseValidationLock.unlock(); return }
        let callbacks = leaseValidationCallbacks
        leaseValidationCallbacks = []; leaseValidationGeneration = nil
        leaseValidationBackoffUntil = Date().addingTimeInterval(backoff)
        leaseValidationLock.unlock()
        for callback in callbacks { callback(active) }
    }

    // MARK: - Internal: the ladder

    /// Entry point for every refresh rejection. Called from `attemptTokenRefresh` while it still
    /// holds the single-flight claim, so nothing else can refresh concurrently.
    internal func resolveRefreshRejection(presentedRefreshToken: String?, owner: OpenWearablesHealthSdkKeychain.ConnectionOwner, completion: @escaping (TokenRefreshResult) -> Void) {
        guard OpenWearablesHealthSdkKeychain.isCurrent(owner) else { completion(.networkError); return }
        // 1. Did another writer (a queued path, a previous run's late response) already install a
        //    newer refresh token? Then the rejection was for a stale value and the session is fine.
        if let current = self.refreshToken, current != presentedRefreshToken {
            logMessage("Refresh rejected for a superseded token - a newer pair is already installed")
            markAuthOk(via: "double-check")
            completion(.success)
            return
        }

        // 2. Native renewal.
        transitionAuthState(.recovering)
        attemptRenewal(owner: owner) { [weak self] outcome in
            guard let self = self else { completion(.networkError); return }
            OpenWearablesHealthSdkKeychain.connectionLock.lock()
            defer { OpenWearablesHealthSdkKeychain.connectionLock.unlock() }
            guard OpenWearablesHealthSdkKeychain.isCurrent(owner) else { completion(.networkError); return }
            switch outcome {
            case .renewed:
                completion(.success)
            case .rejected:
                self.markReauthRequired()
                completion(.authFailure)
            case .transient:
                // Keep `recovering`: the next sync trigger will try again after the backoff.
                completion(.networkError)
            case .unavailable:
                self.markReauthRequired()
                completion(.authFailure)
            }
        }
    }

    /// Exchange the renewal credential for a fresh pair. Single-flight, spaced, and bounded.
    internal func attemptRenewal(owner: OpenWearablesHealthSdkKeychain.ConnectionOwner, completion: @escaping (RenewalOutcome) -> Void) {
        OpenWearablesHealthSdkKeychain.connectionLock.lock()
        defer { OpenWearablesHealthSdkKeychain.connectionLock.unlock() }
        guard OpenWearablesHealthSdkKeychain.isCurrent(owner) else { completion(.transient); return }
        guard let urlString = OpenWearablesHealthSdkKeychain.getRenewalUrl(),
              let token = OpenWearablesHealthSdkKeychain.getRenewalToken(),
              let url = URL(string: urlString) else {
            logMessage("Renewal unavailable: no renewal credential installed")
            completion(.unavailable)
            return
        }

        if OpenWearablesHealthSdkKeychain.getRenewalFailures() >= Self.renewalMaxConsecutiveRejections {
            logMessage("Renewal exhausted: credential rejected \(OpenWearablesHealthSdkKeychain.getRenewalFailures())x")
            completion(.rejected)
            return
        }

        if let last = OpenWearablesHealthSdkKeychain.getLastRenewalAttemptAt(),
           Date().timeIntervalSince(last) < Self.renewalMinGap {
            logMessage("Renewal skipped: attempted \(Int(Date().timeIntervalSince(last)))s ago")
            completion(.transient)
            return
        }

        renewalLock.lock()
        if isRenewing && renewalGeneration == owner.generation {
            renewalCallbacks.append(completion)
            renewalLock.unlock()
            return
        }
        isRenewing = true
        renewalGeneration = owner.generation
        renewalCallbacks.append(completion)
        renewalLock.unlock()

        OpenWearablesHealthSdkKeychain.setLastRenewalAttemptAt(Date())

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = 30
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        let body: [String: String] = [
            "renewal_token": token,
            "platform": "ios",
            "sdk_version": OpenWearablesHealthSDK.sdkVersion
        ]
        guard let bodyData = try? JSONSerialization.data(withJSONObject: body) else {
            finishRenewal(owner: owner, outcome: .transient)
            return
        }
        req.httpBody = bodyData

        logMessage("Renewing SDK credentials via host...")
        let task = foregroundSession.dataTask(with: req) { [weak self] data, response, error in
            guard let self = self else { return }
            OpenWearablesHealthSdkKeychain.connectionLock.lock()
            defer { OpenWearablesHealthSdkKeychain.connectionLock.unlock() }
            guard OpenWearablesHealthSdkKeychain.isCurrent(owner) else { return }

            if let error = error {
                self.logMessage("Renewal failed: \(error.localizedDescription)")
                self.finishRenewal(owner: owner, outcome: .transient)
                return
            }
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0

            if status == 401 || status == 403 || status == 410 {
                let failures = OpenWearablesHealthSdkKeychain.getRenewalFailures() + 1
                OpenWearablesHealthSdkKeychain.setRenewalFailures(failures)
                self.logMessage("Renewal rejected: HTTP \(status) (\(failures)x)")
                self.finishRenewal(owner: owner, outcome: .rejected)
                return
            }

            guard (200...299).contains(status), let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let access = json["access_token"] as? String,
                  let refresh = json["refresh_token"] as? String else {
                self.logMessage("Renewal failed: HTTP \(status)")
                self.finishRenewal(owner: owner, outcome: .transient)
                return
            }

            let persisted = OpenWearablesHealthSdkKeychain.updateTokens(accessToken: access, refreshToken: refresh)
            if !persisted {
                self.logMessage("Renewal succeeded but the pair could not be persisted")
                self.finishRenewal(owner: owner, outcome: .transient)
                return
            }
            OpenWearablesHealthSdkKeychain.setRenewalFailures(0)
            self.logMessage("Renewal: HTTP \(status) - fresh pair installed")
            self.markAuthOk(via: "renewal")
            self.finishRenewal(owner: owner, outcome: .renewed)
        }
        task.resume()
    }

    private func finishRenewal(owner: OpenWearablesHealthSdkKeychain.ConnectionOwner, outcome: RenewalOutcome) {
        renewalLock.lock()
        guard renewalGeneration == owner.generation else { renewalLock.unlock(); return }
        let callbacks = renewalCallbacks
        renewalCallbacks = []
        isRenewing = false
        renewalLock.unlock()
        for cb in callbacks { cb(outcome) }
    }

    // MARK: - Internal: the ledger

    internal func transitionAuthState(_ next: OWAuthState) {
        let previous = authState
        guard previous != next else { return }
        OpenWearablesHealthSdkKeychain.saveAuthState(next.rawValue)
        logMessage("Auth state: \(previous.rawValue) → \(next.rawValue)")
        let callback = onAuthStateChanged
        DispatchQueue.main.async { callback?(next.rawValue) }
    }

    /// A good pair is installed. `via` names the path so the host can tell a routine refresh from a
    /// rescue: "refresh" · "double-check" · "renewal" · "external" (host `updateTokens`) · "sign-in".
    internal func markAuthOk(via: String) {
        let wasBroken = authState != .ok
        if via == "renewal" || via == "external" || via == "double-check" {
            OpenWearablesHealthSdkKeychain.setLastRecoveredAt(Date())
        }
        transitionAuthState(.ok)
        if wasBroken || via == "renewal" {
            let callback = onAuthRecovered
            DispatchQueue.main.async { callback?(via) }
        }
    }

    internal func markReauthRequired() {
        OpenWearablesHealthSdkKeychain.setLastAuthErrorAt(Date())
        transitionAuthState(.reauthRequired)
    }

    /// Wipe the ledger for a fresh sign-in.
    internal func resetAuthLedger() {
        OpenWearablesHealthSdkKeychain.clearAuthState()
    }

    // MARK: - Internal: best-effort revoke on sign-out (open_wearables_ios_sdk#39)

    /// RFC 7009 revoke of the refresh token we are about to forget, so a copy left anywhere cannot
    /// rotate against this user later. Fire-and-forget: sign-out never waits on the network.
    internal func revokeRefreshTokenBestEffort() {
        guard let refreshToken = self.refreshToken, let base = self.apiBaseUrl,
              let url = URL(string: "\(base)/token/revoke") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = 10
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["refresh_token": refreshToken])
        foregroundSession.dataTask(with: req) { _, response, _ in
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            NSLog("[OpenWearablesHealthSDK] Refresh token revoke: HTTP \(status)")
        }.resume()
    }

    // MARK: - Internal: JWT expiry

    /// `exp` of the stored access token, decoded locally. nil when absent or unparseable.
    internal func accessTokenExpiry() -> Date? {
        guard let token = self.accessToken else { return nil }
        let raw = token.hasPrefix("Bearer ") ? String(token.dropFirst(7)) : token
        let parts = raw.split(separator: ".")
        guard parts.count >= 2 else { return nil }
        var payload = String(parts[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while payload.count % 4 != 0 { payload.append("=") }
        guard let data = Data(base64Encoded: payload),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        if let exp = json["exp"] as? Double { return Date(timeIntervalSince1970: exp) }
        if let exp = json["exp"] as? Int { return Date(timeIntervalSince1970: TimeInterval(exp)) }
        return nil
    }
}
