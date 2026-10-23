import Foundation

/// Gutsy fork (OW-P3, GUT-217 #16 hook) — what each sync attempt reached and why it stopped: stage,
/// times, counts, an error code. No health values, tokens or endpoints are recorded.
///
/// Internal on purpose: OW-P2-DESIGN fixes the shape the host reads. When it lands, `asDictionary()`
/// is the one place that changes, plus a `getSyncAttempts` line in the wrapper bridge.
internal struct SyncAttemptRecord: Codable {
    let id: String
    let userKey: String
    let trigger: String
    let startedAt: Date
    var endedAt: Date? = nil
    var stage: String = "start"
    var outcome: String? = nil
    var errorCode: String? = nil
    var httpStatus: Int? = nil
    var typeCount: Int = 0
    var rounds: Int = 0
    var sentItems: Int = 0

    func asDictionary() -> [String: Any] {
        let iso = ISO8601DateFormatter()
        return [
            "id": id, "trigger": trigger, "startedAt": iso.string(from: startedAt),
            "endedAt": endedAt.map { iso.string(from: $0) } as Any? ?? NSNull(),
            "stage": stage, "outcome": outcome as Any? ?? NSNull(), "errorCode": errorCode as Any? ?? NSNull(),
            "httpStatus": httpStatus as Any? ?? NSNull(), "typeCount": typeCount, "rounds": rounds, "sentItems": sentItems
        ]
    }
}

extension OpenWearablesHealthSDK {
    private static let syncAttemptsKey = "syncAttempts"
    private static let syncAttemptHistory = 20

    // userKey() takes the connection lock: always read it BEFORE syncAttemptLock, never inside it.

    /// Opens the record for the run that now owns `isSyncing`.
    internal func beginSyncAttempt(trigger: String, typeCount: Int) {
        let record = SyncAttemptRecord(id: UUID().uuidString, userKey: userKey(), trigger: trigger,
                                       startedAt: Date(), stage: "read", typeCount: typeCount)
        syncAttemptLock.lock(); defer { syncAttemptLock.unlock() }
        currentSyncAttempt = record
    }

    internal func noteSyncAttempt(_ mutate: (inout SyncAttemptRecord) -> Void) {
        syncAttemptLock.lock(); defer { syncAttemptLock.unlock() }
        guard var record = currentSyncAttempt else { return }
        mutate(&record)
        currentSyncAttempt = record
    }

    internal func finishSyncAttempt(outcome: String, errorCode: String? = nil) {
        syncAttemptLock.lock()
        guard var record = currentSyncAttempt else { syncAttemptLock.unlock(); return }
        currentSyncAttempt = nil
        syncAttemptLock.unlock()
        record.endedAt = Date()
        record.outcome = record.outcome ?? outcome
        record.errorCode = record.errorCode ?? errorCode
        storeSyncAttempt(record)
    }

    /// A run that never owned `isSyncing` (lease unverified, another run busy): opened and closed at once.
    internal func recordSyncAttempt(trigger: String, stage: String, outcome: String, errorCode: String) {
        storeSyncAttempt(SyncAttemptRecord(id: UUID().uuidString, userKey: userKey(), trigger: trigger, startedAt: Date(),
                                           endedAt: Date(), stage: stage, outcome: outcome, errorCode: errorCode))
    }

    private func storeSyncAttempt(_ record: SyncAttemptRecord) {
        syncAttemptLock.lock(); defer { syncAttemptLock.unlock() }
        let all = Array(([record] + loadSyncAttempts()).prefix(Self.syncAttemptHistory))
        if let data = try? JSONEncoder().encode(all) { defaults.set(data, forKey: Self.syncAttemptsKey) }
    }

    private func loadSyncAttempts() -> [SyncAttemptRecord] {
        guard let data = defaults.data(forKey: Self.syncAttemptsKey),
              let all = try? JSONDecoder().decode([SyncAttemptRecord].self, from: data) else { return [] }
        return all
    }

    /// This member's recent attempts, newest first. Not bridged to JS until OW-P2-DESIGN fixes the shape.
    public func getSyncAttempts() -> [[String: Any]] {
        let key = userKey()
        syncAttemptLock.lock(); defer { syncAttemptLock.unlock() }
        return loadSyncAttempts().filter { $0.userKey == key }.map { $0.asDictionary() }
    }

    internal func clearSyncAttempts() {
        syncAttemptLock.lock(); defer { syncAttemptLock.unlock() }
        defaults.removeObject(forKey: Self.syncAttemptsKey)
    }
}
