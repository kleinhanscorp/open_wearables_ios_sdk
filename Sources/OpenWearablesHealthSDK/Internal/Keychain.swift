import Foundation
import Security

/// Secure storage for credentials using iOS Keychain
internal class OpenWearablesHealthSdkKeychain {

    private static let service = "com.openwearables.healthsdk.tokens"
    private static let defaults = UserDefaults(suiteName: "com.openwearables.healthsdk.config") ?? .standard

    internal static let connectionLock = NSRecursiveLock()
    internal struct ConnectionOwner: Equatable {
        let userId: String?
        let generation: String
    }
    static func connectionGeneration() -> String {
        connectionLock.lock(); defer { connectionLock.unlock() }
        if let value = defaults.string(forKey: "connectionGeneration") { return value }
        return invalidateConnection()
    }
    @discardableResult static func invalidateConnection() -> String {
        connectionLock.lock(); defer { connectionLock.unlock() }
        let value = UUID().uuidString
        defaults.set(value, forKey: "connectionGeneration")
        defaults.synchronize()
        return value
    }
    static func deviceId() -> String {
        connectionLock.lock(); defer { connectionLock.unlock() }
        if let value = defaults.string(forKey: "deviceId") { return value }
        let value = UUID().uuidString
        defaults.set(value, forKey: "deviceId"); defaults.synchronize()
        return value
    }
    static func deviceLeaseRejected() -> Bool { defaults.bool(forKey: "deviceLeaseRejected") }
    static func setDeviceLeaseRejected(_ value: Bool) { defaults.set(value, forKey: "deviceLeaseRejected"); defaults.synchronize() }
    static func deviceConnectionGeneration() -> String? { defaults.string(forKey: "deviceConnectionGeneration") }
    static func setDeviceConnectionGeneration(_ value: String) { defaults.set(value, forKey: "deviceConnectionGeneration"); defaults.synchronize() }
    static func connectionOwner() -> ConnectionOwner {
        connectionLock.lock(); defer { connectionLock.unlock() }
        return ConnectionOwner(userId: getUserId(), generation: connectionGeneration())
    }
    static func isCurrent(_ owner: ConnectionOwner) -> Bool {
        return connectionOwner() == owner
    }
    @discardableResult static func withConnection<T>(_ owner: ConnectionOwner, _ action: () -> T) -> T? {
        connectionLock.lock(); defer { connectionLock.unlock() }
        return isCurrent(owner) ? action() : nil
    }

    // MARK: - Keys
    private static let accessTokenKey = "accessToken"
    private static let refreshTokenKey = "refreshToken"
    private static let userIdKey = "userId"
    private static let apiKeyKey = "apiKey"
    private static let baseUrlKey = "baseUrl"
    private static let hostKey = "host"
    private static let customSyncUrlKey = "customSyncUrl"
    private static let syncActiveKey = "syncActive"
    private static let trackedTypesKey = "trackedTypes"
    private static let appInstalledKey = "appInstalled"
    private static let syncDaysBackKey = "syncDaysBack"

    // Gutsy fork — the renewal credential (Keychain) and the auth state ledger (config defaults).
    // See `Internal/AuthRecovery.swift` for the state machine these keys back.
    private static let renewalUrlKey = "renewalUrl"
    private static let renewalTokenKey = "renewalToken"
    private static let authStateKey = "authState"
    private static let lastAuthErrorAtKey = "authLastErrorAt"
    private static let lastRecoveredAtKey = "authLastRecoveredAt"
    private static let renewalFailuresKey = "authRenewalFailures"
    private static let lastRenewalAttemptAtKey = "authLastRenewalAttemptAt"

    // MARK: - Fresh Install Detection

    /// Call this on app launch to clear Keychain if app was reinstalled.
    /// UserDefaults is cleared on uninstall, but Keychain persists.
    /// If UserDefaults flag is missing but Keychain has data, the app was reinstalled.
    static func clearKeychainIfReinstalled() {
        let wasInstalled = defaults.bool(forKey: appInstalledKey)

        if !wasInstalled {
            if hasSession() {
                NSLog("[OpenWearablesHealthSDK] App reinstalled - clearing stale Keychain data")
                clearAll()
            }

            defaults.set(true, forKey: appInstalledKey)
            defaults.synchronize()
        }
    }

    // MARK: - Save Credentials

    static func saveCredentials(userId: String, accessToken: String? = nil, refreshToken: String? = nil) {
        save(key: userIdKey, value: userId)
        // Refresh token FIRST — see `updateTokens` for why the order is load-bearing.
        if let refreshToken = refreshToken {
            save(key: refreshTokenKey, value: refreshToken)
        }
        if let accessToken = accessToken {
            save(key: accessTokenKey, value: accessToken)
        }
    }

    // MARK: - Load Credentials

    static func getAccessToken() -> String? {
        return load(key: accessTokenKey)
    }

    static func getRefreshToken() -> String? {
        return load(key: refreshTokenKey)
    }

    static func getUserId() -> String? {
        return load(key: userIdKey)
    }

    // MARK: - Update Tokens (after refresh)

    /// Persist a rotated pair. The server has ALREADY revoked the refresh token we presented by the
    /// time this runs (strict rotation, zero grace), so the write order decides what a crash leaves
    /// behind:
    ///   · refresh first, then access — a crash in between leaves {expired access, NEW refresh}:
    ///     the next upload 401s, refreshes with the new token, and recovers.
    ///   · access first, then refresh — a crash in between leaves {fresh access, REVOKED refresh}:
    ///     an hour later every refresh is rejected forever. That was the field failure.
    /// Every write is verified by reading it back; a mismatch is logged loudly and retried once.
    @discardableResult
    static func updateTokens(accessToken: String, refreshToken: String?) -> Bool {
        var ok = true
        if let refreshToken = refreshToken {
            ok = saveVerified(key: refreshTokenKey, value: refreshToken) && ok
        }
        ok = saveVerified(key: accessTokenKey, value: accessToken) && ok
        return ok
    }

    static func hasSession() -> Bool {
        guard getUserId() != nil else { return false }
        return getAccessToken() != nil || getApiKey() != nil
    }

    // MARK: - Renewal credential (Gutsy fork)

    /// A long-lived, single-purpose credential that can mint a fresh SDK token pair for this user
    /// at `url` when the refresh token has been revoked. Never rotated by the SDK.
    static func saveRenewalCredential(url: String, token: String) {
        save(key: renewalUrlKey, value: url)
        save(key: renewalTokenKey, value: token)
    }

    static func getRenewalUrl() -> String? {
        return load(key: renewalUrlKey)
    }

    static func getRenewalToken() -> String? {
        return load(key: renewalTokenKey)
    }

    static func hasRenewalCredential() -> Bool {
        return getRenewalUrl() != nil && getRenewalToken() != nil
    }

    static func clearRenewalCredential() {
        delete(key: renewalUrlKey)
        delete(key: renewalTokenKey)
    }

    // MARK: - Auth state ledger (Gutsy fork; UserDefaults — not secret, must survive relaunch)

    static func getAuthState() -> String {
        return defaults.string(forKey: authStateKey) ?? "ok"
    }

    static func saveAuthState(_ state: String) {
        defaults.set(state, forKey: authStateKey)
        defaults.synchronize()
    }

    static func getLastAuthErrorAt() -> Date? {
        return defaults.object(forKey: lastAuthErrorAtKey) as? Date
    }

    static func setLastAuthErrorAt(_ date: Date?) {
        if let date = date { defaults.set(date, forKey: lastAuthErrorAtKey) } else { defaults.removeObject(forKey: lastAuthErrorAtKey) }
        defaults.synchronize()
    }

    static func getLastRecoveredAt() -> Date? {
        return defaults.object(forKey: lastRecoveredAtKey) as? Date
    }

    static func setLastRecoveredAt(_ date: Date?) {
        if let date = date { defaults.set(date, forKey: lastRecoveredAtKey) } else { defaults.removeObject(forKey: lastRecoveredAtKey) }
        defaults.synchronize()
    }

    static func getRenewalFailures() -> Int {
        return defaults.integer(forKey: renewalFailuresKey)
    }

    static func setRenewalFailures(_ count: Int) {
        defaults.set(count, forKey: renewalFailuresKey)
        defaults.synchronize()
    }

    static func getLastRenewalAttemptAt() -> Date? {
        return defaults.object(forKey: lastRenewalAttemptAtKey) as? Date
    }

    static func setLastRenewalAttemptAt(_ date: Date?) {
        if let date = date { defaults.set(date, forKey: lastRenewalAttemptAtKey) } else { defaults.removeObject(forKey: lastRenewalAttemptAtKey) }
        defaults.synchronize()
    }

    static func clearAuthState() {
        defaults.removeObject(forKey: authStateKey)
        defaults.removeObject(forKey: lastAuthErrorAtKey)
        defaults.removeObject(forKey: lastRecoveredAtKey)
        defaults.removeObject(forKey: renewalFailuresKey)
        defaults.removeObject(forKey: lastRenewalAttemptAtKey)
        defaults.synchronize()
    }

    // MARK: - Host (stored in UserDefaults, not sensitive)

    static func saveHost(_ host: String?) {
        if let host = host {
            defaults.set(host, forKey: hostKey)
        } else {
            defaults.removeObject(forKey: hostKey)
        }
        defaults.synchronize()
    }

    static func getHost() -> String? {
        return defaults.string(forKey: hostKey)
    }

    // Legacy - kept for migration/cleanup
    static func saveCustomSyncUrl(_ url: String?) {
        if let url = url {
            defaults.set(url, forKey: customSyncUrlKey)
        } else {
            defaults.removeObject(forKey: customSyncUrlKey)
        }
        defaults.synchronize()
    }

    static func getCustomSyncUrl() -> String? {
        return defaults.string(forKey: customSyncUrlKey)
    }

    // MARK: - Sync Active State

    static func setSyncActive(_ active: Bool) {
        defaults.set(active, forKey: syncActiveKey)
        defaults.synchronize()
    }

    static func isSyncActive() -> Bool {
        return defaults.bool(forKey: syncActiveKey)
    }

    // MARK: - Tracked Types

    static func saveTrackedTypes(_ types: [String]) {
        defaults.set(types, forKey: trackedTypesKey)
        defaults.synchronize()
    }

    static func getTrackedTypes() -> [String]? {
        return defaults.stringArray(forKey: trackedTypesKey)
    }

    // MARK: - Sync Days Back

    static func saveSyncDaysBack(_ days: Int) {
        defaults.set(days, forKey: syncDaysBackKey)
        defaults.synchronize()
    }

    /// Returns the stored sync days back, or 0 if not set (meaning full sync / no limit).
    static func getSyncDaysBack() -> Int {
        return defaults.integer(forKey: syncDaysBackKey)
    }

    // MARK: - API Key (alternative auth mode)

    static func saveApiKey(_ apiKey: String) {
        save(key: apiKeyKey, value: apiKey)
    }

    static func getApiKey() -> String? {
        return load(key: apiKeyKey)
    }

    // MARK: - Clear

    static func clearAll() {
        defaults.removeObject(forKey: "deviceConnectionGeneration")
        defaults.removeObject(forKey: "deviceLeaseRejected")
        delete(key: accessTokenKey)
        delete(key: refreshTokenKey)
        delete(key: userIdKey)
        delete(key: apiKeyKey)
        clearRenewalCredential()
        clearAuthState()
        defaults.removeObject(forKey: hostKey)
        defaults.removeObject(forKey: customSyncUrlKey)
        defaults.removeObject(forKey: syncActiveKey)
        defaults.removeObject(forKey: trackedTypesKey)
        defaults.removeObject(forKey: syncDaysBackKey)
        defaults.synchronize()
    }

    // MARK: - Private Keychain Operations

    /// Upsert in place. The previous implementation deleted the item and re-added it, which left a
    /// window in which the key did not exist at all — a suspend or kill inside that window lost the
    /// credential outright. `SecItemUpdate` mutates the existing item atomically; `SecItemAdd` runs
    /// only when there is nothing to update.
    private static func save(key: String, value: String) {
        guard let data = value.data(using: .utf8) else { return }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var addQuery = query
            for (k, v) in attributes { addQuery[k] = v }
            status = SecItemAdd(addQuery as CFDictionary, nil)
        }

        if status != errSecSuccess {
            NSLog("[OpenWearablesHealthSDK] Keychain save failed for \(key): \(status)")
        }
    }

    /// Save, read back, compare. One retry. Returns whether the value is now durably what we wrote.
    private static func saveVerified(key: String, value: String) -> Bool {
        save(key: key, value: value)
        if load(key: key) == value { return true }
        NSLog("[OpenWearablesHealthSDK] Keychain verify failed for \(key) - retrying once")
        save(key: key, value: value)
        let ok = load(key: key) == value
        if !ok {
            NSLog("[OpenWearablesHealthSDK] Keychain verify failed for \(key) after retry")
        }
        return ok
    }

    private static func load(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let string = String(data: data, encoding: .utf8) else {
            return nil
        }

        return string
    }

    private static func delete(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]

        SecItemDelete(query as CFDictionary)
    }
}
