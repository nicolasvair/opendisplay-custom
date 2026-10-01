// Pure selection logic for the Mirror-mode screen picker, kept free of
// AppKit/ScreenCaptureKit so it can be unit tested (see MacTests).

import Foundation

enum MirrorDisplaySelection {
    /// The screen to mirror: the preferred one when it is still connected,
    /// otherwise the main screen, otherwise the first one, otherwise nil.
    static func resolve(preferredID: String?,
                        available: [MirrorDisplayInfo]) -> MirrorDisplayInfo? {
        if let preferredID, let match = available.first(where: { $0.id == preferredID }) {
            return match
        }
        if let main = available.first(where: { $0.main }) { return main }
        return available.first
    }
}
