import XCTest
@testable import OpenWearablesHealthSDK

/// OW-P3 (GUT-217 #9): outbox ageing, cleanup, caps and owner scoping, and observer completion timing.
final class OutboxPolicyTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_790_000_000)

    private func item(user: String = "user.a", generation: String = "g2", retries: Int? = nil,
                      next: Date? = nil, rejected: Int? = nil) -> OpenWearablesHealthSDK.OutboxItem {
        var item = OpenWearablesHealthSDK.OutboxItem(typeIdentifier: "combined", userKey: user, payloadPath: "/synthetic/p.json",
                                                     anchorPath: nil, wasFullExport: false, connectionGeneration: generation)
        item.retryCount = retries
        item.nextRetryAt = next
        item.rejectedStatus = rejected
        return item
    }

    private func disposition(_ item: OpenWearablesHealthSDK.OutboxItem, age: TimeInterval, inFlight: Bool = false) -> OutboxPolicy.Disposition {
        OutboxPolicy.disposition(item, createdAt: now.addingTimeInterval(-age), now: now,
                                 userKey: "user.a", generation: "g2", inFlight: inFlight)
    }

    func testEligibleCopyReplays() {
        XCTAssertEqual(disposition(item(), age: 120), .replay)
    }

    func testFreshCopyWaitsForItsFirstUpload() {
        XCTAssertEqual(disposition(item(), age: 10), .wait)
    }

    func testRetryWindowIsHonoured() {
        XCTAssertEqual(disposition(item(retries: 2, next: now.addingTimeInterval(60)), age: 600), .wait)
        XCTAssertEqual(disposition(item(retries: 2, next: now.addingTimeInterval(-1)), age: 600), .replay)
    }

    func testAgeComesFromCreationNotFromTheRetryRewrite() throws {
        // Retried an hour ago (fresh mtime) but written eight days ago: it expires.
        var retried = item(retries: 3, next: now.addingTimeInterval(-60))
        retried.createdAt = now.addingTimeInterval(-8 * 24 * 3600)
        retried.lastAttemptAt = now.addingTimeInterval(-3600)
        let roundTrip = try JSONDecoder().decode(OpenWearablesHealthSDK.OutboxItem.self, from: JSONEncoder().encode(retried))
        XCTAssertEqual(roundTrip.createdAt, retried.createdAt, "a retry rewrite keeps the creation time")
        XCTAssertEqual(disposition(roundTrip, age: now.timeIntervalSince(roundTrip.createdAt!)), .dropExpired)
    }

    func testPreOwP3ItemsStillDecode() throws {
        let legacy = #"{"typeIdentifier":"combined","userKey":"user.a","payloadPath":"/synthetic/p.json","retryCount":1}"#
        let item = try JSONDecoder().decode(OpenWearablesHealthSDK.OutboxItem.self, from: Data(legacy.utf8))
        XCTAssertNil(item.createdAt)
        XCTAssertNil(item.lastAttemptAt)
    }

    func testRefusedAndExhaustedCopiesAreDropped() {
        XCTAssertEqual(disposition(item(rejected: 422), age: 600), .dropTerminal(422))
        XCTAssertEqual(disposition(item(retries: OutboxPolicy.maxRetries), age: 600), .dropDead)
        XCTAssertTrue(OutboxPolicy.Disposition.dropDead.isDrop)
        XCTAssertFalse(OutboxPolicy.Disposition.wait.isDrop)
    }

    func testAnotherMembersCopyIsNeverReplayed() {
        XCTAssertEqual(disposition(item(user: "user.b"), age: 600), .dropForeign)
    }

    func testSameMemberEarlierGenerationIsReHomed() {
        XCTAssertEqual(disposition(item(generation: "g1"), age: 600), .adopt)
    }

    func testInFlightCopyIsNeverTouched() {
        XCTAssertEqual(disposition(item(retries: OutboxPolicy.maxRetries), age: 600, inFlight: true), .wait)
        XCTAssertEqual(disposition(item(user: "user.b"), age: 600, inFlight: true), .wait)
    }

    func testCapsEvictOldestFirstAndSkipInFlight() {
        let entries = (0..<5).map { i in
            OutboxPolicy.Entry(id: "i\(i)", createdAt: now.addingTimeInterval(Double(i)), bytes: 10, inFlight: i == 0)
        }
        XCTAssertEqual(OutboxPolicy.evictions(entries, maxItems: 3, maxBytes: 1_000), ["i1", "i2"])
        XCTAssertEqual(OutboxPolicy.evictions(entries, maxItems: 10, maxBytes: 25), ["i1", "i2", "i3"])
        XCTAssertEqual(OutboxPolicy.evictions(entries, maxItems: 10, maxBytes: 1_000), [])
    }

    func testObserverCompletionsFireOnceAfterTheSync() {
        let gate = ObserverCompletionGate(timeout: 60)
        var fired = 0
        gate.add { fired += 1 }
        gate.add { fired += 1 }
        XCTAssertEqual(fired, 0, "nothing fires before the sync reports back")
        XCTAssertEqual(gate.waiting, 2)
        XCTAssertEqual(gate.flush(), 2)
        XCTAssertEqual(fired, 2)
        XCTAssertEqual(gate.flush(), 0, "each completion fires exactly once")
        XCTAssertEqual(fired, 2)
    }

    func testObserverWatchdogAnswersHealthKitIfTheSyncNeverReports() {
        let gate = ObserverCompletionGate(timeout: 0.2)
        let answered = expectation(description: "watchdog fired the completion")
        gate.add { answered.fulfill() }
        wait(for: [answered], timeout: 5)
        XCTAssertEqual(gate.waiting, 0)
    }
}
