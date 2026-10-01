// Compiled into both the Mac and iOS targets. Foundation-only.

import Foundation

/// Splits dictated text into pieces that fit the sender's unicode-key event
/// limit (a CGEvent carries at most ~20 UTF-16 units; we stay at 16).
enum TextChunking {
    /// Chunks of at most `maxUTF16` UTF-16 code units, cut only on grapheme
    /// cluster boundaries. A single grapheme longer than the limit gets a
    /// chunk of its own (never split). Joining the result gives back `s`.
    static func chunks(_ s: String, maxUTF16: Int = 16) -> [String] {
        let limit = max(1, maxUTF16)
        var result: [String] = []
        var current = ""
        var currentUnits = 0
        for character in s {
            let units = character.utf16.count
            if currentUnits > 0, currentUnits + units > limit {
                result.append(current)
                current = ""
                currentUnits = 0
            }
            current.append(character)
            currentUnits += units
        }
        if !current.isEmpty { result.append(current) }
        return result
    }
}
