import Foundation
import HealthKit

extension OpenWearablesHealthSDK {

    // MARK: - Outbox model
    internal struct OutboxItem: Codable {
        let typeIdentifier: String
        let userKey: String
        let payloadPath: String
        let anchorPath: String?
        let wasFullExport: Bool?
        var connectionGeneration: String? = nil
        var retryCount: Int? = nil
        var nextRetryAt: Date? = nil
        var rejectedStatus: Int? = nil
        // Gutsy fork (OW-P3): when the copy was written. Age is measured from here, not from the
        // file's mtime, which every retry rewrite reset (so an item retried forever never aged out).
        var createdAt: Date? = nil
        /// When the copy was last handed to the background session (it may still be in flight).
        var lastAttemptAt: Date? = nil
    }

    internal func outboxDir() -> URL {
        let base = try? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        return (base ?? FileManager.default.temporaryDirectory).appendingPathComponent("health_outbox", isDirectory: true)
    }

    internal func ensureOutboxDir() {
        try? FileManager.default.createDirectory(at: outboxDir(), withIntermediateDirectories: true)
    }

    internal func newPath(_ name: String, ext: String) -> URL {
        ensureOutboxDir()
        return outboxDir().appendingPathComponent("\(name).\(ext)")
    }

    // MARK: - Combined upload
    internal func enqueueCombinedUpload(
        payload: [String: Any],
        anchors: [String: HKQueryAnchor],
        endpoint: URL,
        credential: String,
        wasFullExport: Bool = false,
        completion: @escaping (Bool) -> Void
    ) {
        let owner = OpenWearablesHealthSdkKeychain.connectionOwner()
        OpenWearablesHealthSdkKeychain.connectionLock.lock()
        defer { OpenWearablesHealthSdkKeychain.connectionLock.unlock() }
        guard let data = try? JSONSerialization.data(withJSONObject: payload) else {
            self.logMessage("Failed to serialize payload")
            completion(false)
            return
        }
        
        let id = UUID().uuidString
        let payloadURL = newPath("combined_payload_\(id)", ext: "json")
        
        do {
            try data.write(to: payloadURL, options: Data.WritingOptions.atomic)
        } catch {
            self.logMessage("Failed to write payload: \(error.localizedDescription)")
            completion(false)
            return
        }

        var anchorsURL: URL? = nil
        if !anchors.isEmpty {
            var anchorsData: [String: Data] = [:]
            for (typeId, anchor) in anchors {
                if let data = try? NSKeyedArchiver.archivedData(withRootObject: anchor, requiringSecureCoding: true) {
                    anchorsData[typeId] = data
                }
            }
            
            if let serializedData = try? NSKeyedArchiver.archivedData(withRootObject: anchorsData, requiringSecureCoding: true) {
                let u = newPath("combined_anchors_\(id)", ext: "bin")
                try? serializedData.write(to: u, options: Data.WritingOptions.atomic)
                anchorsURL = u
            }
        }

        let item = OutboxItem(
            typeIdentifier: "combined",
            userKey: userKey(),
            payloadPath: payloadURL.path,
            anchorPath: anchorsURL?.path,
            wasFullExport: wasFullExport,
            connectionGeneration: owner.generation,
            createdAt: Date()
        )
        let itemURL = newPath("combined_item_\(id)", ext: "json")
        if let md = try? JSONEncoder().encode(item) {
            try? md.write(to: itemURL, options: Data.WritingOptions.atomic)
        }
        enforceOutboxCaps(inFlightPayloadPaths: nil, protecting: [payloadURL.path])

        guard let payloadData = try? Data(contentsOf: payloadURL) else {
            self.logMessage("Failed to read payload")
            completion(false)
            return
        }
        
        var req = URLRequest(url: endpoint)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        applyAuth(to: &req, credential: credential)
        req.httpBody = payloadData
        req.setValue("\(payloadData.count)", forHTTPHeaderField: "Content-Length")
        
        self.logPayloadSummary(payloadData, label: "Sending")

        let task = foregroundSession.dataTask(with: req) { [weak self] data, response, error in
            guard let self = self else { return }
            OpenWearablesHealthSdkKeychain.connectionLock.lock()
            defer { OpenWearablesHealthSdkKeychain.connectionLock.unlock() }
            guard OpenWearablesHealthSdkKeychain.isCurrent(owner) else { completion(false); return }
            
            if let error = error {
                let nsError = error as NSError
                if nsError.code != NSURLErrorCancelled {
                    self.logMessage("Upload error: \(error.localizedDescription)")
                    self.markNetworkError()
                }
                self.noteSyncAttempt { $0.errorCode = nsError.code == NSURLErrorCancelled ? "upload_cancelled" : "upload_network" }
                completion(false)
                return
            }
            
            if let httpResponse = response as? HTTPURLResponse {
                if (200...299).contains(httpResponse.statusCode) {
                    self.logMessage("HTTP \(httpResponse.statusCode)")
                    
                    self.handleSuccessfulUpload(itemPath: itemURL.path, anchorPath: anchorsURL?.path, wasFullExport: wasFullExport)
                    
                    try? FileManager.default.removeItem(atPath: payloadURL.path)
                    completion(true)
                } else if httpResponse.statusCode == 401 {
                    self.handle401ForUpload(
                        payloadData: payloadData,
                        endpoint: endpoint,
                        itemPath: itemURL.path,
                        payloadPath: payloadURL.path,
                        anchorsPath: anchorsURL?.path,
                        wasFullExport: wasFullExport,
                        completion: completion
                    )
                } else {
                    var errorMsg = "HTTP \(httpResponse.statusCode)"
                    if let data = data, let errorBody = String(data: data, encoding: .utf8) {
                        let truncated = errorBody.count > 200 ? String(errorBody.prefix(200)) + "..." : errorBody
                        errorMsg += " - \(truncated)"
                    }
                    self.logMessage(errorMsg)
                    
                    // A rejected chunk is never accepted progress. Retain retryable 429;
                    // permanent 4xx is explicitly refused without advancing its query anchor.
                    self.recordUploadRejection(itemPath: itemURL.path, status: httpResponse.statusCode)
                    let status = httpResponse.statusCode
                    self.noteSyncAttempt {
                        $0.httpStatus = status
                        $0.errorCode = status == 429 ? "upload_rate_limited" : (500...599).contains(status) ? "upload_transient" : "upload_rejected"
                    }
                    if httpResponse.statusCode == 429 {
                        self.logMessage("Upload rate limited - retaining chunk for bounded outbox retry")
                    } else if (400...499).contains(httpResponse.statusCode) {
                        self.logMessage("Upload rejected - refusing progress (HTTP \(httpResponse.statusCode))")
                    }
                    completion(false)
                }
            } else {
                self.logMessage("No HTTP response")
                self.markNetworkError()
                completion(false)
            }
        }
        
        task.resume()
    }
    
    /// Handles 401 response for combined uploads.
    private func handle401ForUpload(
        payloadData: Data,
        endpoint: URL,
        itemPath: String,
        payloadPath: String,
        anchorsPath: String?,
        wasFullExport: Bool,
        completion: @escaping (Bool) -> Void
    ) {
        let owner = OpenWearablesHealthSdkKeychain.connectionOwner()
        if isApiKeyAuth {
            self.logMessage("Got 401 with apiKey auth")
            self.emitAuthError(statusCode: 401)
            recordUploadRejection(itemPath: itemPath, status: 401)
            completion(false)
            return
        }
        
        self.logMessage("Got 401, refreshing token...")
        
        self.attemptTokenRefresh { [weak self] result in
            guard let self = self else { return }
            OpenWearablesHealthSdkKeychain.connectionLock.lock()
            defer { OpenWearablesHealthSdkKeychain.connectionLock.unlock() }
            guard OpenWearablesHealthSdkKeychain.isCurrent(owner) else { completion(false); return }
            
            switch result {
            case .success:
                guard let newCredential = self.authCredential else {
                    self.logMessage("Token refreshed but no credential available")
                    completion(false)
                    return
                }
                self.logMessage("Token refreshed, retrying...")
                
                var retryReq = URLRequest(url: endpoint)
                retryReq.httpMethod = "POST"
                retryReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
                self.applyAuth(to: &retryReq, credential: newCredential)
                retryReq.httpBody = payloadData
                retryReq.setValue("\(payloadData.count)", forHTTPHeaderField: "Content-Length")
                
                let retryTask = self.foregroundSession.dataTask(with: retryReq) { [weak self] retryData, retryResponse, retryError in
                    guard let self = self else { return }
            OpenWearablesHealthSdkKeychain.connectionLock.lock()
            defer { OpenWearablesHealthSdkKeychain.connectionLock.unlock() }
            guard OpenWearablesHealthSdkKeychain.isCurrent(owner) else { completion(false); return }
                    
                    if let retryError = retryError {
                        self.logMessage("Retry failed: \(retryError.localizedDescription)")
                        completion(false)
                        return
                    }
                    
                    if let retryHttp = retryResponse as? HTTPURLResponse, (200...299).contains(retryHttp.statusCode) {
                        self.logMessage("Retry: HTTP \(retryHttp.statusCode)")
                        self.handleSuccessfulUpload(itemPath: itemPath, anchorPath: anchorsPath, wasFullExport: wasFullExport)
                        try? FileManager.default.removeItem(atPath: payloadPath)
                        completion(true)
                    } else {
                        let retryStatus = (retryResponse as? HTTPURLResponse)?.statusCode ?? 0
                        self.recordUploadRejection(itemPath: itemPath, status: retryStatus)
                        self.logMessage("Retry failed: HTTP \(retryStatus)")
                        if (401...403).contains(retryStatus) {
                            self.emitAuthError(statusCode: retryStatus)
                        }
                        completion(false)
                    }
                }
                guard OpenWearablesHealthSdkKeychain.isCurrent(owner) else { completion(false); return }
                retryTask.resume()
                
            case .authFailure:
                self.logMessage("Token refresh rejected - auth is invalid")
                self.emitAuthError(statusCode: 401)
                self.noteSyncAttempt { $0.httpStatus = 401; $0.errorCode = "upload_auth" }
                completion(false)

            case .networkError:
                self.logMessage("Token refresh failed (network) - will retry later")
                self.markNetworkError()
                self.noteSyncAttempt { $0.errorCode = "upload_network" }
                completion(false)
            }
        }
    }
    
    // MARK: - Handle successful upload
    internal func handleSuccessfulUpload(itemPath: String, anchorPath: String?, wasFullExport: Bool) {
        guard let itemData = try? Data(contentsOf: URL(fileURLWithPath: itemPath)),
              let item = try? JSONDecoder().decode(OutboxItem.self, from: itemData) else {
            logMessage("Failed to read item for anchor saving")
            return
        }
        
        guard item.userKey == userKey(),
              item.connectionGeneration == connectionGeneration() else { return }
        if let anchorPath = anchorPath, !anchorPath.isEmpty {
            if item.typeIdentifier == "combined" {
                if let anchorData = try? Data(contentsOf: URL(fileURLWithPath: anchorPath)),
                   let anchorsDict = try? NSKeyedUnarchiver.unarchivedObject(ofClasses: [NSDictionary.self, NSString.self, NSData.self], from: anchorData) as? [String: Data] {
                    for (typeId, anchorData) in anchorsDict {
                        saveAnchorData(anchorData, typeIdentifier: typeId, userKey: item.userKey)
                    }
                    logMessage("Saved anchors for \(anchorsDict.count) types")
                }
            } else {
                if let anchorData = try? Data(contentsOf: URL(fileURLWithPath: anchorPath)) {
                    saveAnchorData(anchorData, typeIdentifier: item.typeIdentifier, userKey: item.userKey)
                }
            }
            
            try? FileManager.default.removeItem(atPath: anchorPath)
        }
        
        // One accepted chunk cannot establish completion of the entire historical export.
        // Only finalizeSyncState marks the native traversal complete; server commit is separate.

        try? FileManager.default.removeItem(atPath: itemPath)
        markOutboxDelivering()
    }

    internal func recordUploadRejection(itemPath: String, status: Int) {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: itemPath)),
              var item = try? JSONDecoder().decode(OutboxItem.self, from: data),
              item.userKey == userKey(), item.connectionGeneration == connectionGeneration() else { return }
        if status == 429 { item.nextRetryAt = Date().addingTimeInterval(60) }
        else if (400...499).contains(status) && status != 401 { item.rejectedStatus = status }
        if let metadata = try? JSONEncoder().encode(item) {
            try? metadata.write(to: URL(fileURLWithPath: itemPath), options: .atomic)
        }
        logMessage("Upload not accepted: HTTP \(status); cursor retained")
    }

    // MARK: - Clear outbox
    internal func clearOutbox() {
        let dir = outboxDir()
        if let files = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) {
            for file in files {
                try? FileManager.default.removeItem(at: file)
            }
        }
        // The health record goes with the copies it describes, for every member (sign-out has
        // already forgotten whose they were).
        for key in defaults.dictionaryRepresentation().keys where key.hasPrefix(Self.outboxHealthPrefix) {
            defaults.removeObject(forKey: key)
        }
        logMessage("Cleared outbox")
    }

    // MARK: - Outbox bounds and health (Gutsy fork, OW-P3 #9)

    private static let outboxHealthPrefix = "outbox.health."
    private func outboxHealthKey() -> String { Self.outboxHealthPrefix + userKey() }

    internal struct OutboxEntry {
        let itemURL: URL
        let item: OutboxItem
        let bytes: Int64
    }

    internal func outboxEntries() -> [OutboxEntry] {
        guard let files = try? FileManager.default.contentsOfDirectory(at: outboxDir(), includingPropertiesForKeys: nil) else { return [] }
        return files.filter {
            $0.pathExtension == "json" &&
            ($0.lastPathComponent.hasPrefix("item_") || $0.lastPathComponent.hasPrefix("combined_item_"))
        }.compactMap { url -> OutboxEntry? in
            guard let data = try? Data(contentsOf: url), let item = try? JSONDecoder().decode(OutboxItem.self, from: data) else { return nil }
            let size = (try? FileManager.default.attributesOfItem(atPath: item.payloadPath)[.size] as? NSNumber)?.int64Value ?? 0
            return OutboxEntry(itemURL: url, item: item, bytes: size)
        }
    }

    internal func removeOutboxItem(itemURL: URL, item: OutboxItem) {
        try? FileManager.default.removeItem(atPath: item.payloadPath)
        if let anchorPath = item.anchorPath, !anchorPath.isEmpty { try? FileManager.default.removeItem(atPath: anchorPath) }
        try? FileManager.default.removeItem(at: itemURL)
    }

    @discardableResult
    private func persistOutboxItem(_ item: OutboxItem, to url: URL) -> Bool {
        guard let data = try? JSONEncoder().encode(item) else { return false }
        return (try? data.write(to: url, options: .atomic)) != nil
    }

    /// Pre-OW-P3 copies carry no creation time: take the file's once, then keep it in the item.
    private func legacyCreationDate(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.creationDate] as? Date) ?? (attrs?[.modificationDate] as? Date) ?? Date()
    }

    /// Count a dropped copy. Anything but another member's copy marks the outbox exhausted until the next accepted upload.
    private func noteOutboxDrop(_ reason: String, count: Int = 1) {
        var health = defaults.dictionary(forKey: outboxHealthKey()) ?? [:]
        health[reason] = ((health[reason] as? Int) ?? 0) + count
        if reason != "foreign" && health["exhaustedSince"] == nil {
            health["exhaustedSince"] = Date().timeIntervalSince1970
        }
        defaults.set(health, forKey: outboxHealthKey())
    }

    private func markOutboxDelivering() {
        guard var health = defaults.dictionary(forKey: outboxHealthKey()), health["exhaustedSince"] != nil else { return }
        health.removeValue(forKey: "exhaustedSince")
        defaults.set(health, forKey: outboxHealthKey())
    }

    /// Item and byte caps, oldest first. `nil` in-flight set (the enqueue path): a copy handed to the
    /// background session within its resource timeout counts as in flight.
    internal func enforceOutboxCaps(inFlightPayloadPaths: Set<String>?, protecting: Set<String> = [], now: Date = Date()) {
        let entries = outboxEntries()
        guard entries.count > OutboxPolicy.maxItems || entries.reduce(Int64(0), { $0 + $1.bytes }) > OutboxPolicy.maxBytes else { return }
        let candidates = entries.map { entry -> OutboxPolicy.Entry in
            let path = entry.item.payloadPath
            let inFlight = protecting.contains(path) || (inFlightPayloadPaths?.contains(path)
                ?? entry.item.lastAttemptAt.map { now.timeIntervalSince($0) < OutboxPolicy.inFlightWindow } ?? false)
            return OutboxPolicy.Entry(id: entry.itemURL.path, createdAt: entry.item.createdAt ?? .distantPast, bytes: entry.bytes, inFlight: inFlight)
        }
        let evict = Set(OutboxPolicy.evictions(candidates))
        guard !evict.isEmpty else { return }
        for entry in entries where evict.contains(entry.itemURL.path) { removeOutboxItem(itemURL: entry.itemURL, item: entry.item) }
        noteOutboxDrop("evicted", count: evict.count)
        logMessage("Outbox: cap reached - evicted \(evict.count) oldest copy(ies); HealthKit still holds the samples")
    }

    /// Visible state for getSyncStatus: this member's retained copies and what was dropped.
    internal func outboxStatus() -> [String: Any] {
        let mine = outboxEntries().filter { $0.item.userKey == userKey() }
        let health = defaults.dictionary(forKey: outboxHealthKey()) ?? [:]
        let iso = ISO8601DateFormatter()
        var dropped: [String: Int] = [:]
        for reason in ["terminal", "dead", "expired", "evicted", "foreign"] { dropped[reason] = (health[reason] as? Int) ?? 0 }
        return [
            "pending": mine.count,
            "bytes": mine.reduce(Int64(0)) { $0 + $1.bytes },
            "oldestCreatedAt": mine.compactMap { $0.item.createdAt }.min().map { iso.string(from: $0) } as Any? ?? NSNull(),
            "dropped": dropped,
            "exhausted": health["exhaustedSince"] != nil,
            "exhaustedSince": (health["exhaustedSince"] as? Double).map { iso.string(from: Date(timeIntervalSince1970: $0)) } as Any? ?? NSNull()
        ]
    }

    // MARK: - Retry pending items

    /// Retries pending outbox items through the *background* URLSession.
    /// - uploads go through the background session (survive suspension/kill),
    /// - the session is limited to one connection per host, so items go out serially,
    /// - a retry pass is skipped while a regular sync is running,
    /// - only one retry pass can run at a time,
    /// - items already enqueued in the background session are not enqueued again.
    internal func retryOutboxIfPossible() {
        let owner = OpenWearablesHealthSdkKeychain.connectionOwner()
        validateDeviceLease(owner: owner) { [weak self] active in
            OpenWearablesHealthSdkKeychain.connectionLock.lock()
            defer { OpenWearablesHealthSdkKeychain.connectionLock.unlock() }
            guard active, OpenWearablesHealthSdkKeychain.isCurrent(owner) else { return }
            self?.retryValidatedOutboxIfPossible()
        }
    }
    private func retryValidatedOutboxIfPossible() {
        let owner = OpenWearablesHealthSdkKeychain.connectionOwner()
        guard let endpoint = self.syncEndpoint, let credential = self.authCredential else { return }
        
        if isSyncInProgress {
            logMessage("Outbox retry skipped - sync in progress")
            return
        }
        
        outboxRetryLock.lock()
        if isRetryingOutbox {
            outboxRetryLock.unlock()
            return
        }
        isRetryingOutbox = true
        outboxRetryGeneration = owner.generation
        outboxRetryLock.unlock()
        
        session.getAllTasks { [weak self] tasks in
            guard let self = self else { return }
            OpenWearablesHealthSdkKeychain.connectionLock.lock()
            defer { OpenWearablesHealthSdkKeychain.connectionLock.unlock() }
            guard OpenWearablesHealthSdkKeychain.isCurrent(owner) else { return }
            defer {
                self.outboxRetryLock.lock()
                if self.outboxRetryGeneration == owner.generation {
                    self.isRetryingOutbox = false; self.outboxRetryGeneration = nil
                }
                self.outboxRetryLock.unlock()
            }
            
            // Payloads already queued in the background session (possibly from a
            // previous app run) must not be enqueued a second time.
            let inFlightPayloadPaths = Set(tasks.compactMap { task -> String? in
                let parts = task.taskDescription?.split(separator: "|", omittingEmptySubsequences: false)
                guard let parts = parts, parts.count > 1 else { return nil }
                return String(parts[1])
            })
            
            let dir = self.outboxDir()
            guard let files = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else { return }

            let itemFiles = files.filter {
                $0.pathExtension == "json" &&
                ($0.lastPathComponent.hasPrefix("item_") || $0.lastPathComponent.hasPrefix("combined_item_"))
            }

            // Gutsy fork (OW-P3, #9): every retained copy gets a disposition (OutboxPolicy). Refused,
            // out-of-retries, week-old and other members' copies are removed and counted — they used
            // to be skipped before the age check and so stayed on disk forever.
            let now = Date()
            var enqueued = 0
            var justEnqueued = Set<String>()
            for itemURL in itemFiles {
                guard let data = try? Data(contentsOf: itemURL),
                      var item = try? JSONDecoder().decode(OutboxItem.self, from: data) else {
                    try? FileManager.default.removeItem(at: itemURL)
                    continue
                }
                let payloadURL = URL(fileURLWithPath: item.payloadPath)
                guard FileManager.default.fileExists(atPath: payloadURL.path) else {
                    // Orphaned metadata without a payload - clean up
                    self.removeOutboxItem(itemURL: itemURL, item: item)
                    continue
                }
                if item.createdAt == nil {
                    item.createdAt = self.legacyCreationDate(itemURL)
                    self.persistOutboxItem(item, to: itemURL)
                }
                let inFlight = inFlightPayloadPaths.contains(payloadURL.path)
                var disposition = OutboxPolicy.disposition(item, createdAt: item.createdAt ?? now, now: now,
                                                           userKey: self.userKey(), generation: owner.generation, inFlight: inFlight)
                if disposition == .adopt {
                    // Same member, an earlier generation (a host token repair bumps it): the copy is
                    // still this member's, so it is re-homed rather than orphaned.
                    item.connectionGeneration = owner.generation
                    guard self.persistOutboxItem(item, to: itemURL) else { continue }
                    disposition = OutboxPolicy.disposition(item, createdAt: item.createdAt ?? now, now: now,
                                                           userKey: self.userKey(), generation: owner.generation, inFlight: inFlight)
                }
                if disposition.isDrop {
                    self.logMessage("Outbox: dropping a \(disposition.reason) copy")
                    self.removeOutboxItem(itemURL: itemURL, item: item)
                    self.noteOutboxDrop(disposition.reason)
                    continue
                }
                guard disposition == .replay else { continue }

                var req = URLRequest(url: endpoint)
                req.httpMethod = "POST"
                req.setValue("application/json", forHTTPHeaderField: "Content-Type")
                self.applyAuth(to: &req, credential: credential)

                item.retryCount = (item.retryCount ?? 0) + 1
                item.nextRetryAt = now.addingTimeInterval(min(3600, 60 * pow(2, Double(item.retryCount! - 1))))
                item.lastAttemptAt = now
                guard self.persistOutboxItem(item, to: itemURL) else { continue }
                let task = self.session.uploadTask(with: req, fromFile: payloadURL)
                task.taskDescription = [itemURL.path, payloadURL.path, item.anchorPath ?? ""].joined(separator: "|")
                task.resume()
                enqueued += 1
                justEnqueued.insert(payloadURL.path)
            }
            self.enforceOutboxCaps(inFlightPayloadPaths: inFlightPayloadPaths.union(justEnqueued))

            if enqueued > 0 {
                self.logMessage("Outbox: enqueued \(enqueued) pending upload(s) to background session")
            }
        }
    }
}
