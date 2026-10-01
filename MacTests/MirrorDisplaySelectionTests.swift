import XCTest

final class MirrorDisplaySelectionTests: XCTestCase {
    private let main = MirrorDisplayInfo(id: "AAAA", name: "Built-in", w: 3024, h: 1964, main: true)
    private let side = MirrorDisplayInfo(id: "BBBB", name: "Studio Display", w: 5120, h: 2880, main: false)
    private let third = MirrorDisplayInfo(id: "CCCC", name: "Écran 3", w: 1920, h: 1080, main: false)

    func testPreferredDisplayWinsWhenPresent() {
        let chosen = MirrorDisplaySelection.resolve(preferredID: "BBBB", available: [main, side, third])
        XCTAssertEqual(chosen, side)
    }

    func testMissingPreferredFallsBackToMain() {
        let chosen = MirrorDisplaySelection.resolve(preferredID: "ZZZZ", available: [side, main, third])
        XCTAssertEqual(chosen, main)
    }

    func testNoPreferenceUsesMain() {
        XCTAssertEqual(MirrorDisplaySelection.resolve(preferredID: nil, available: [side, main]), main)
    }

    func testNoMainFallsBackToFirst() {
        XCTAssertEqual(MirrorDisplaySelection.resolve(preferredID: nil, available: [side, third]), side)
        XCTAssertEqual(MirrorDisplaySelection.resolve(preferredID: "ZZZZ", available: [third, side]), third)
    }

    func testEmptyListResolvesToNil() {
        XCTAssertNil(MirrorDisplaySelection.resolve(preferredID: nil, available: []))
        XCTAssertNil(MirrorDisplaySelection.resolve(preferredID: "AAAA", available: []))
    }
}
