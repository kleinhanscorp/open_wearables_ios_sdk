import Foundation

/// Gutsy fork (OW-P3, GUT-217 #9) — what the outbox does with each retained item, as pure rules the
/// XCTests exercise without HealthKit or a URLSession.
///
/// Every outbox payload is a redundant copy: a failed upload never advances its HealthKit anchor or
/// cursor, so the next sync re-reads the same samples. Dropping an item therefore loses no data; it
/// only stops retrying a copy that can no longer help (refused, out of retries, a week old, another
/// member's) and keeps the directory bounded.
internal enum OutboxPolicy {
    /// The item's first upload may still be in flight.
    static let minRetryAge: TimeInterval = 30
    static let maxItemAge: TimeInterval = 7 * 24 * 3600
    static let maxRetries = 6
    static let maxItems = 200
    static let maxBytes: Int64 = 64 * 1024 * 1024
    /// A background upload enqueued this recently may still be in flight (the session's resource timeout).
    static let inFlightWindow: TimeInterval = 3600

    enum Disposition: Equatable {
        case replay
        case wait
        /// Same member, an earlier connection generation (a host token repair bumps it): re-home, then replay.
        case adopt
        /// Another member's copy: never replayed under this connection.
        case dropForeign
        case dropTerminal(Int)
        case dropDead
        case dropExpired

        var isDrop: Bool {
            switch self {
            case .dropForeign, .dropTerminal, .dropDead, .dropExpired: return true
            default: return false
            }
        }

        /// Counter name for the outbox health record.
        var reason: String {
            switch self {
            case .dropForeign: return "foreign"
            case .dropTerminal: return "terminal"
            case .dropDead: return "dead"
            case .dropExpired: return "expired"
            default: return "kept"
            }
        }
    }

    /// Age is measured from [createdAt] — the moment the copy was written — never from the file's
    /// modification time, which every retry rewrite reset. An in-flight item is never touched.
    static func disposition(_ item: OpenWearablesHealthSDK.OutboxItem, createdAt: Date, now: Date,
                            userKey: String, generation: String, inFlight: Bool) -> Disposition {
        if inFlight { return .wait }
        if item.userKey != userKey { return .dropForeign }
        if let status = item.rejectedStatus { return .dropTerminal(status) }
        if (item.retryCount ?? 0) >= maxRetries { return .dropDead }
        if now.timeIntervalSince(createdAt) > maxItemAge { return .dropExpired }
        if item.connectionGeneration != generation { return .adopt }
        if now.timeIntervalSince(createdAt) < minRetryAge { return .wait }
        if let next = item.nextRetryAt, next > now { return .wait }
        return .replay
    }

    struct Entry {
        let id: String
        let createdAt: Date
        let bytes: Int64
        let inFlight: Bool
    }

    /// Oldest first until both caps hold. In-flight (or just-written) items are never evicted.
    static func evictions(_ entries: [Entry], maxItems: Int = maxItems, maxBytes: Int64 = maxBytes) -> [String] {
        var count = entries.count
        var bytes = entries.reduce(Int64(0)) { $0 + $1.bytes }
        var evicted: [String] = []
        for entry in entries.sorted(by: { $0.createdAt < $1.createdAt }) where !entry.inFlight {
            if count <= maxItems && bytes <= maxBytes { break }
            evicted.append(entry.id)
            count -= 1
            bytes -= entry.bytes
        }
        return evicted
    }
}

/// HealthKit wants each observer completion called once, after the work it triggered — call it
/// early and processing may be suspended mid-sync; never call it and HealthKit backs off, then stops
/// background delivery. A burst of observer callbacks shares the one debounced sync, so their
/// completions wait here together; a watchdog fires them if that sync never reports back.
internal final class ObserverCompletionGate {
    private let lock = NSLock()
    private var pending: [() -> Void] = []
    private var watchdog: DispatchWorkItem?
    private let timeout: TimeInterval
    private let queue: DispatchQueue

    init(timeout: TimeInterval = 25, queue: DispatchQueue = DispatchQueue(label: "health_observer_completion")) {
        self.timeout = timeout
        self.queue = queue
    }

    func add(_ completion: @escaping () -> Void) {
        lock.lock()
        pending.append(completion)
        if watchdog == nil {
            let item = DispatchWorkItem { [weak self] in self?.flush() }
            watchdog = item
            queue.asyncAfter(deadline: .now() + timeout, execute: item)
        }
        lock.unlock()
    }

    /// Fires every waiting completion exactly once; returns how many fired.
    @discardableResult
    func flush() -> Int {
        lock.lock()
        let due = pending
        pending = []
        watchdog?.cancel()
        watchdog = nil
        lock.unlock()
        due.forEach { $0() }
        return due.count
    }

    var waiting: Int {
        lock.lock(); defer { lock.unlock() }
        return pending.count
    }
}
