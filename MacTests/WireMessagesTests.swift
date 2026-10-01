import XCTest

final class WireMessagesTests: XCTestCase {
    func testMirrorDisplayInfoRoundTrip() throws {
        let list = [
            MirrorDisplayInfo(id: "37D8832A-2D66-02CA-B9F7-8F30A301B230",
                              name: "Built-in Retina Display", w: 3024, h: 1964, main: true),
            MirrorDisplayInfo(id: "11111111-2222-3333-4444-555555555555",
                              name: "Écran 2", w: 2560, h: 1440, main: false),
        ]
        let data = try JSONEncoder().encode(list)
        XCTAssertEqual(try JSONDecoder().decode([MirrorDisplayInfo].self, from: data), list)
    }

    func testUnknownFieldIsIgnored() throws {
        let json = #"{"id":"A","name":"X","w":10,"h":20,"main":false,"refresh":120,"future":{"a":1}}"#
        let info = try JSONDecoder().decode(MirrorDisplayInfo.self, from: Data(json.utf8))
        XCTAssertEqual(info, MirrorDisplayInfo(id: "A", name: "X", w: 10, h: 20, main: false))
    }

    func testMessageTypeConstants() {
        XCTAssertEqual(WireMessage.displays, "displays")
        XCTAssertEqual(WireMessage.setDisplay, "setDisplay")
        XCTAssertEqual(WireMessage.streamConfig, "streamConfig")
    }

    func testProtocolVersionUnchanged() {
        // The display picker and dictation are additive: no `pv` bump.
        XCTAssertEqual(WireProtocol.version, 3)
    }
}
