import XCTest

final class TextChunkingTests: XCTestCase {
    func testEmptyStringHasNoChunks() {
        XCTAssertEqual(TextChunking.chunks(""), [])
    }

    func testShortStringIsOneChunk() {
        XCTAssertEqual(TextChunking.chunks("bonjour"), ["bonjour"])
        XCTAssertEqual(TextChunking.chunks(String(repeating: "a", count: 16)).count, 1)
    }

    func testLongASCIIStaysWithinLimitAndJoinsBack() {
        let input = String((0..<100).map { _ in Character("a") })
        let chunks = TextChunking.chunks(input)
        XCTAssertTrue(chunks.allSatisfy { $0.utf16.count <= 16 })
        XCTAssertEqual(chunks.joined(), input)
        XCTAssertEqual(chunks.count, 7)
    }

    func testDecomposedAccentsAreNeverSplit() {
        // "é" as e + U+0301: two UTF-16 units, one grapheme.
        let decomposed = "e\u{301}"
        let input = String(repeating: decomposed, count: 20)
        let chunks = TextChunking.chunks(input)
        XCTAssertEqual(chunks.joined(), input)
        XCTAssertTrue(chunks.allSatisfy { $0.utf16.count <= 16 })
        for chunk in chunks {
            XCTAssertFalse(chunk.unicodeScalars.first == "\u{301}", "a combining mark opened a chunk")
        }
    }

    func testZWJEmojiStaysWhole() {
        let family = "👨‍👩‍👧‍👦"   // 11 UTF-16 units, one grapheme
        XCTAssertEqual(family.count, 1)
        let input = "ab" + family + family + "cd"
        let chunks = TextChunking.chunks(input)
        XCTAssertEqual(chunks.joined(), input)
        XCTAssertTrue(chunks.allSatisfy { $0.utf16.count <= 16 })
        XCTAssertEqual(chunks, ["ab" + family, family + "cd"])
    }

    func testOversizedGraphemeGetsItsOwnChunk() {
        let big = "e" + String(repeating: "\u{301}", count: 20)   // one grapheme, 21 units
        XCTAssertEqual(big.count, 1)
        let chunks = TextChunking.chunks("x" + big + "y")
        XCTAssertEqual(chunks, ["x", big, "y"])
    }

    func testFrenchSentence() {
        let input = "Bonjour, ça va très bien ? J'écris à l'été prochain, déjà."
        let chunks = TextChunking.chunks(input)
        XCTAssertEqual(chunks.joined(), input)
        XCTAssertTrue(chunks.allSatisfy { !$0.isEmpty && $0.utf16.count <= 16 })
    }
}
