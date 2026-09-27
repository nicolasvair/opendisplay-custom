import SwiftUI
import AppKit
import Carbon

/// A keyboard drawn by the sender itself, above the Mirror control bar.
/// macOS's Accessibility Keyboard cannot be summoned programmatically, so this
/// is the reliable way to type from the receiver: the panel never activates,
/// so keystrokes land in whatever app was frontmost, and a finger on a key is
/// an ordinary click.
@MainActor
enum OnScreenKeyboard {
    private static var panel: NSPanel?
    private static var displayID: CGDirectDisplayID?

    static var isVisible: Bool { panel != nil }

    static func toggle() {
        if isVisible { hide() } else if let id = displayID { show(on: id) }
    }

    /// Remember which display the bar lives on, so the button knows where to
    /// open the keyboard.
    static func attach(to displayID: CGDirectDisplayID) {
        self.displayID = displayID
    }

    static func detach() {
        hide()
        displayID = nil
    }

    static func show(on displayID: CGDirectDisplayID) {
        hide()
        guard let screen = NSScreen.screens.first(where: {
            ($0.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? CGDirectDisplayID) == displayID
        }) else { return }
        let width = min(screen.frame.width - 16, 900)
        let height: CGFloat = 5 * 50 + 16
        let frame = NSRect(x: screen.frame.midX - width / 2,
                           y: screen.frame.minY + MirrorControlBar.height,
                           width: width, height: height)
        let p = NSPanel(contentRect: frame,
                        styleMask: [.borderless, .nonactivatingPanel],
                        backing: .buffered, defer: false)
        p.level = .statusBar
        p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
        p.isFloatingPanel = true
        p.hidesOnDeactivate = false
        p.becomesKeyOnlyIfNeeded = true
        p.backgroundColor = .clear
        p.isOpaque = false
        p.hasShadow = true
        p.contentView = KeyboardHostingView(rootView: KeyboardView(model: KeyboardModel()))
        p.setFrame(frame, display: true)
        p.orderFrontRegardless()
        panel = p

        // Global CG rect (y-down): keys stay direct clicks in trackpad mode.
        let bounds = CGDisplayBounds(displayID)
        let fromBottom = frame.minY - screen.frame.minY
        PointerModeState.shared.keyboardRect = CGRect(
            x: bounds.minX + (frame.minX - screen.frame.minX),
            y: bounds.maxY - fromBottom - frame.height,
            width: frame.width, height: frame.height)
    }

    static func hide() {
        panel?.orderOut(nil)
        panel = nil
        PointerModeState.shared.keyboardRect = nil
    }
}

private final class KeyboardHostingView<Content: View>: NSHostingView<Content> {
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
}

// MARK: - Keys

private enum Key: Hashable {
    case char(String)
    case special(label: String, code: CGKeyCode)
    case shift, command, option, control, page
    case space

    static let returnKey = Key.special(label: "⏎", code: 36)
    static let delete = Key.special(label: "⌫", code: 51)
    static let tab = Key.special(label: "⇥", code: 48)
    static let escape = Key.special(label: "esc", code: 53)
    static let left = Key.special(label: "←", code: 123)
    static let right = Key.special(label: "→", code: 124)
    static let down = Key.special(label: "↓", code: 125)
    static let up = Key.special(label: "↑", code: 126)
}

private func chars(_ s: String) -> [Key] { s.map { .char(String($0)) } }

/// AZERTY order, as printed on a French Mac keyboard. What a key TYPES does
/// not depend on the Mac's layout: see `KeyPoster`.
private let letterRows: [[Key]] = [
    [.escape] + chars("1234567890") + [.delete],
    [.tab] + chars("azertyuiop"),
    chars("qsdfghjklm") + [.returnKey],
    [.shift] + chars("wxcvbn,.") + [.up],
    [.page, .control, .option, .command, .space, .left, .down, .right],
]

private let symbolRows: [[Key]] = [
    [.escape] + chars("&é\"'(è!çà)") + [.delete],
    [.tab] + chars("@#€$%^*-_=+"),
    chars("ùêâ<>[]{}/\\") + [.returnKey],
    [.shift] + chars("?;:|~`°£") + [.up],
    [.page, .control, .option, .command, .space, .left, .down, .right],
]

@MainActor
private final class KeyboardModel: ObservableObject {
    @Published var shift = false
    @Published var command = false
    @Published var option = false
    @Published var control = false
    @Published var symbols = false

    var rows: [[Key]] { symbols ? symbolRows : letterRows }

    func label(_ key: Key) -> String {
        switch key {
        case .char(let c): return shift ? c.uppercased() : c
        case .special(let label, _): return label
        case .shift: return "⇧"
        case .command: return "⌘"
        case .option: return "⌥"
        case .control: return "⌃"
        case .page: return symbols ? "abc" : "#+="
        case .space: return ""
        }
    }

    func isOn(_ key: Key) -> Bool {
        switch key {
        case .shift: return shift
        case .command: return command
        case .option: return option
        case .control: return control
        default: return false
        }
    }

    func press(_ key: Key) {
        switch key {
        case .shift: shift.toggle(); return
        case .command: command.toggle(); return
        case .option: option.toggle(); return
        case .control: control.toggle(); return
        case .page: symbols.toggle(); return
        default: break
        }
        var flags: CGEventFlags = []
        if command { flags.insert(.maskCommand) }
        if option { flags.insert(.maskAlternate) }
        if control { flags.insert(.maskControl) }
        switch key {
        case .char(let c):
            KeyPoster.shared.type(shift ? c.uppercased() : c, flags: flags)
        case .space:
            KeyPoster.shared.press(code: 49, flags: flags)
        case .special(_, let code):
            if shift { flags.insert(.maskShift) }
            KeyPoster.shared.press(code: code, flags: flags)
        default:
            break
        }
        // Modifiers are one-shot, as on the iPad's own keyboard.
        shift = false
        command = false
        option = false
        control = false
    }

    func width(_ key: Key) -> CGFloat {
        switch key {
        case .space: return 5
        case .returnKey, .delete, .shift, .page: return 1.5
        default: return 1
        }
    }
}

private struct KeyboardView: View {
    @ObservedObject var model: KeyboardModel

    var body: some View {
        GeometryReader { geo in
            let unit = (geo.size.width - 16) / 13
            VStack(spacing: 6) {
                ForEach(Array(model.rows.enumerated()), id: \.offset) { _, row in
                    HStack(spacing: 6) {
                        ForEach(Array(row.enumerated()), id: \.offset) { _, key in
                            Button { model.press(key) } label: {
                                Text(model.label(key))
                                    .font(.system(size: 18, weight: .medium))
                                    .frame(width: max(unit * model.width(key) - 6, 20), height: 44)
                                    .background(RoundedRectangle(cornerRadius: 6)
                                        .fill(model.isOn(key) ? Color.accentColor : Color.white.opacity(0.18)))
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(.white)
                        }
                    }
                }
            }
            .padding(8)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(RoundedRectangle(cornerRadius: 10).fill(Color.black.opacity(0.92)))
        .environment(\.colorScheme, .dark)
    }
}

// MARK: - Posting keystrokes

/// Types a character through the key that produces it on the Mac's CURRENT
/// layout when there is one — so ⌘ + a letter is a real shortcut and apps
/// that read key codes see the right key — and as a raw Unicode string
/// otherwise (accents off the layout, symbols behind ⌥).
@MainActor
private final class KeyPoster {
    static let shared = KeyPoster()

    private let source = CGEventSource(stateID: .hidSystemState)
    private var map: [String: (code: CGKeyCode, shift: Bool)] = [:]
    private var mappedLayout: String?

    func type(_ text: String, flags: CGEventFlags) {
        refreshMapIfNeeded()
        if let hit = map[text] {
            var f = flags
            if hit.shift { f.insert(.maskShift) }
            press(code: hit.code, flags: f)
            return
        }
        let units = Array(text.utf16)
        for down in [true, false] {
            guard let e = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: down) else { continue }
            e.flags = flags
            e.keyboardSetUnicodeString(stringLength: units.count, unicodeString: units)
            e.post(tap: .cghidEventTap)
        }
    }

    func press(code: CGKeyCode, flags: CGEventFlags) {
        for down in [true, false] {
            guard let e = CGEvent(keyboardEventSource: source, virtualKey: code, keyDown: down) else { continue }
            e.flags = flags
            e.post(tap: .cghidEventTap)
        }
    }

    /// Reverse the layout once per layout: key code (+ shift) → character.
    /// Dead keys are left out on purpose — pressing one would start a compose
    /// sequence in the target app instead of typing the character.
    private func refreshMapIfNeeded() {
        guard let source = TISCopyCurrentKeyboardLayoutInputSource()?.takeRetainedValue() else { return }
        let id = (TISGetInputSourceProperty(source, kTISPropertyInputSourceID))
            .map { Unmanaged<CFString>.fromOpaque($0).takeUnretainedValue() as String }
        guard id != mappedLayout else { return }
        mappedLayout = id
        map = [:]
        guard let raw = TISGetInputSourceProperty(source, kTISPropertyUnicodeKeyLayoutData) else { return }
        let data = Unmanaged<CFData>.fromOpaque(raw).takeUnretainedValue() as Data
        data.withUnsafeBytes { buffer in
            guard let layout = buffer.bindMemory(to: UCKeyboardLayout.self).baseAddress else { return }
            for code in 0..<128 {
                for shift in [false, true] {
                    var dead: UInt32 = 0
                    var length = 0
                    var chars = [UniChar](repeating: 0, count: 4)
                    let modifiers: UInt32 = shift ? UInt32(shiftKey >> 8) & 0xFF : 0
                    let status = UCKeyTranslate(layout, UInt16(code), UInt16(kUCKeyActionDown),
                                                modifiers, UInt32(LMGetKbdType()), 0,
                                                &dead, chars.count, &length, &chars)
                    guard status == noErr, dead == 0, length > 0 else { continue }
                    let s = String(utf16CodeUnits: chars, count: length)
                    // Keypad keys duplicate digits and operators; the main
                    // block's comes first in code order for most, and either
                    // types the same character.
                    if map[s] == nil { map[s] = (CGKeyCode(code), shift) }
                }
            }
        }
        Log.info("on-screen keyboard: mapped \(map.count) characters for layout \(id ?? "?")")
    }
}
