import XCTest

@testable import DragonWatch

final class ProcessTreeTests: XCTestCase {
    private func process(_ pid: pid_t, parent: pid_t?, name: String = "p") -> MonitoredProcess {
        MonitoredProcess(
            record: ProcessRecord(
                pid: pid, path: "/bin/\(name)", name: name, cpuPercent: 0, residentBytes: 0,
                parentPID: parent, startedAt: nil),
            trust: TrustAssessment(tier: .applePlatform, modifiers: [], teamID: nil, signingID: nil)
        )
    }

    func testNestsChildrenUnderParentsAndOrdersByName() {
        let tree = ProcessTree.build([
            process(1, parent: 0, name: "launchd"),
            process(30, parent: 1, name: "zsh"),
            process(20, parent: 1, name: "Terminal"),
            process(40, parent: 30, name: "node"),
        ])
        XCTAssertEqual(tree.map(\.name), ["launchd"])
        XCTAssertEqual(tree[0].children?.map(\.name), ["Terminal", "zsh"], "name order, not pid")
        XCTAssertEqual(tree[0].children?[1].children?.map(\.name), ["node"])
        XCTAssertNil(tree[0].children?[0].children, "leaves carry nil, not []")
        XCTAssertEqual(tree[0].subtreeCount, 4)
    }

    /// Scoped to the input: a member whose parent is not in the set is a
    /// root, which is what makes one builder serve a group and the machine.
    func testParentOutsideTheSetMakesARoot() {
        let tree = ProcessTree.build([
            process(30, parent: 1, name: "zsh"),
            process(40, parent: 30, name: "node"),
            process(50, parent: 999, name: "helper"),
        ])
        XCTAssertEqual(tree.map(\.name), ["helper", "zsh"])
        XCTAssertEqual(tree[1].children?.map(\.name), ["node"])
    }

    /// Every process appears exactly once, even under a parent cycle — a
    /// reused pid between samples can make a → b → a.
    func testCycleAndSelfParentStillListEveryProcessOnce() {
        let input = [
            process(10, parent: 11, name: "a"),
            process(11, parent: 10, name: "b"),
            process(12, parent: 12, name: "self"),
            process(13, parent: nil, name: "unknown"),
        ]
        let tree = ProcessTree.build(input)
        XCTAssertEqual(tree.reduce(0) { $0 + $1.subtreeCount }, input.count)
        var seen: [pid_t] = []
        func walk(_ nodes: [ProcessTreeNode]) {
            for node in nodes {
                seen.append(node.id)
                walk(node.children ?? [])
            }
        }
        walk(tree)
        XCTAssertEqual(Set(seen).count, input.count)
    }

    func testEmptyInputIsEmptyTree() {
        XCTAssertTrue(ProcessTree.build([]).isEmpty)
    }

    func testStartedLabelUsesTimeTodayAndDateOtherwise() {
        let now = Date()
        XCTAssertFalse(ProcessTreeView.startedLabel(now, now: now).isEmpty)
        let lastWeek = now.addingTimeInterval(-7 * 86400)
        XCTAssertNotEqual(
            ProcessTreeView.startedLabel(lastWeek, now: now),
            lastWeek.formatted(date: .omitted, time: .shortened),
            "an old process must show its date, not a bare clock time")
    }
}
