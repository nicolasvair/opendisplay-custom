import SwiftUI
import UIKit

// MARK: - Local controls (custom build)
//
// The control bar, the keyboard and trackpad mode live on the receiver:
// the bar sits in space reserved below the picture (the announced desktop is
// that much shorter), the keyboard is the iPadOS system one (pinch it to
// float it), and trackpad gestures are recognized here with full touch
// information, then sent to the Mac as relative moves, buttons and scrolls.

enum LocalPointerMode: String {
    case touch      // the screen is a touchscreen: the cursor jumps under the finger
    case trackpad   // the screen is a big trackpad: relative moves, tap to click
}

final class LocalControls: ObservableObject {
    static let shared = LocalControls()
    static let barHeight: CGFloat = 44

    @Published var mode = LocalPointerMode(rawValue: UserDefaults.standard.string(forKey: "pointerMode") ?? "")
        ?? .touch {
        didSet {
            if persistsMode { UserDefaults.standard.set(mode.rawValue, forKey: "pointerMode") }
            // The Mac brings a cursor left on another screen back onto the
            // mirrored one, where this trackpad can see it.
            if mode != oldValue { receiver?.sendPointerMode(mode.rawValue) }
        }
    }
    /// False while a layout forces the mode (the iPhone mirror screen): the
    /// forced value must not reach UserDefaults, so that killing the app
    /// there does not change the mode of the next launch.
    private var persistsMode = true

    /// Set the mode without remembering it (the Mac is still told).
    func setTransientMode(_ new: LocalPointerMode) {
        persistsMode = false
        mode = new
        persistsMode = true
    }

    /// Touch mode: the next tap becomes a right click, then it disarms.
    @Published var rightClickArmed = false
    @Published var keyboardVisible = false
    /// While a docked keyboard is up, slide the picture up so it does not
    /// hide what is being worked on (trackpad mode follows the cursor).
    /// Always on: there is no toggle any more.
    @Published var followKeyboard = true
    /// How far (points) the picture is currently slid up; the video view
    /// computes it, the screen applies it as an offset.
    @Published var keyboardShift: CGFloat = 0
    /// iPhone: the bar rides above a docked keyboard (it would otherwise sit
    /// under it, out of reach, and the phone keyboard has no dismiss key).
    static var barRaisedAboveKeyboard: Bool { UIDevice.current.userInterfaceIdiom == .phone }
    /// How much of the picture's bottom a docked keyboard of this height
    /// hides: the keyboard minus the bar's own strip (the bar lies under the
    /// keyboard on iPad), or the whole keyboard when the bar is raised.
    static func pictureCovered(byKeyboard docked: CGFloat) -> CGFloat {
        barRaisedAboveKeyboard ? docked : max(0, docked - barHeight)
    }
    /// Space under the overlaid keys row: just above a docked keyboard (and
    /// above the bar when that rides on it).
    static func keysRowBottomPadding(docked: CGFloat) -> CGFloat {
        if barRaisedAboveKeyboard, docked > 0 { return docked + 6 }
        return max(0, docked - barHeight) + 6
    }
    /// Whether the latest shift change should animate.
    var animateShift = false
    /// Height the Mac keys row takes above the bar or the keyboard: two key
    /// lines (the inverted T), the gap, padding and the margin below.
    /// One line (arrows side by side) on a landscape iPhone, where height is
    /// scarce; the inverted T otherwise.
    static var keysRowHeight: CGFloat {
        phoneLandscape ? MacKeysRow.keyHeight + 3 * MacKeysRow.gap
            : 2 * MacKeysRow.keyHeight + 4 * MacKeysRow.gap
    }
    /// An iPhone held sideways.
    static var phoneLandscape: Bool {
        UIDevice.current.userInterfaceIdiom == .phone
            && UIScreen.main.bounds.width > UIScreen.main.bounds.height
    }
    /// Sticky one-shot modifiers from the Mac keys row (1 ⌘, 2 ⌥, 4 ⌃, 8 ⇧).
    @Published var mods = 0
    /// Modifiers locked by a swipe up on their key: they ride on every key
    /// until tapped again. Same bits as `mods`; a bit is never in both.
    @Published var lockedMods = 0
    /// Height of a docked keyboard (0 when hidden or floating), so the keys
    /// row can sit above it.
    @Published var dockedKeyboardHeight: CGFloat = 0
    weak var receiver: StreamReceiver?

    private init() {
        NotificationCenter.default.addObserver(
            forName: UIResponder.keyboardWillChangeFrameNotification, object: nil, queue: .main
        ) { [weak self] note in
            guard let frame = note.userInfo?[UIResponder.keyboardFrameEndUserInfoKey] as? CGRect else { return }
            let screen = UIScreen.main.bounds
            // Docked = full width and flush with the bottom; the floating
            // keyboard reports a small or empty frame instead.
            let docked = frame.width >= screen.width - 1 && abs(frame.maxY - screen.maxY) < 1
            self?.dockedKeyboardHeight = docked ? max(0, screen.maxY - frame.minY) : 0
        }
        NotificationCenter.default.addObserver(
            forName: UIResponder.keyboardWillHideNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.dockedKeyboardHeight = 0 }
    }

    /// The modifiers for the next key: the one-shot ones (spent here) plus
    /// the locked ones (kept). The Mac presses and releases them around each
    /// key, so a locked modifier is never left held between keys or clicks.
    func takeMods() -> Int {
        let current = mods
        if current != 0 { mods = 0 }
        return current | lockedMods
    }

    /// Tap on a modifier key: unlocks a locked one, else toggles one-shot.
    func tapModifier(_ bit: Int) {
        if lockedMods & bit != 0 { lockedMods &= ~bit } else { mods ^= bit }
    }

    /// Swipe up on a modifier key: locks it (like the iPad's number lock).
    func lockModifier(_ bit: Int) {
        mods &= ~bit
        lockedMods |= bit
    }
    /// Trackpad speed multiplier (0.4…2.5).
    @Published var trackpadSpeed: Double = {
        let v = UserDefaults.standard.double(forKey: "trackpadSpeed")
        return v > 0 ? v : 1
    }() {
        didSet { UserDefaults.standard.set(trackpadSpeed, forKey: "trackpadSpeed") }
    }
}

// MARK: - Bar

struct LocalControlBar: View {
    @ObservedObject var receiver: StreamReceiver
    @ObservedObject var controls = LocalControls.shared
    @ObservedObject var dictation = DictationController.shared

    /// Forces the compact (phone) arrangement; it is also chosen on any iPhone.
    var compact = false
    /// Souris/Tactile switch and right-click button (compact bar). Hidden on
    /// the iPhone mirror screen, where the pointer is always a mouse.
    var showsPointerMode = true
    /// A column of icon buttons for the side of a landscape screen (the
    /// iPhone mirror layout), where height is scarce: keyboard, dictation,
    /// Extend/Mirror menu, Mac screen menu, trackpad speed.
    var vertical = false

    /// Every iPad is under 1100 pt wide in portrait and over it in landscape.
    @State private var portrait = false
    /// Window safe-area insets: the compact bar keeps its buttons out from
    /// under the Dynamic Island and the rounded corners in landscape.
    @State private var insets = UIEdgeInsets.zero
    /// Popup of the trackpad speed slider (iPhone bars).
    @State private var speedShown = false
    /// Frame of the speed button in the bar's own coordinate space: the
    /// popover is anchored to the bar (a view that survives a rotation) at
    /// this rect, not to the button, which is rebuilt when the mirror layout
    /// swaps the vertical and compact bars.
    @State private var speedFrames: [Bool: CGRect] = [:]
    @Environment(\.horizontalSizeClass) private var sizeClass

    private var isCompact: Bool {
        // iPhone Plus/Max report a regular width in landscape: the idiom is
        // the surer test there.
        compact || sizeClass == .compact || UIDevice.current.userInterfaceIdiom == .phone
    }

    var body: some View {
        Group {
            if vertical {
                verticalBar
            } else {
                Group {
                    if isCompact { compactBar } else { regularBar }
                }
                .frame(maxWidth: .infinity)
                .frame(height: LocalControls.barHeight)
            }
        }
        .coordinateSpace(name: Self.barSpace)
        .onPreferenceChange(SpeedButtonFrameKey.self) { speedFrames.merge($0) { _, new in new } }
        .onChange(of: vertical) { _ in speedShown = false }   // mirror rotation: the button changes bar
        .onChange(of: controls.mode) { if $0 != .trackpad { speedShown = false } }
        .background(SafeAreaInsetsReader { insets = $0 })
        .background(Color.black)
        .environment(\.colorScheme, .dark)
        // Presented from the bar itself, outside the vertical/compact switch:
        // a popover anchored to a button that leaves the hierarchy during a
        // rotation is orphaned (white screen, content only, no dismissal).
        .speedPopover(isPresented: $speedShown, anchor: speedFrames[vertical] ?? .zero, speed: $controls.trackpadSpeed)
    }

    private static let barSpace = "LocalControlBar"

    // MARK: Vertical (landscape iPhone mirror): a column of icons

    private var verticalBar: some View {
        VStack(spacing: 6) {
            barButton(systemImage: "keyboard", active: controls.keyboardVisible, width: 44) {
                controls.keyboardVisible.toggle()
            }
            barButton(systemImage: dictation.isListening ? "mic.fill" : "mic",
                      active: dictation.isListening, width: 44) {
                dictation.toggle()
            }
            if let current = receiver.senderMode {
                Menu {
                    Picker("", selection: Binding(get: { current },
                                                  set: { receiver.requestMode($0) })) {
                        Text("Étendre").tag("extend")
                        Text("Recopie").tag("mirror")
                    }
                } label: {
                    Image(systemName: current == "mirror" ? "rectangle.on.rectangle" : "rectangle.split.2x1")
                        .font(.system(size: 20))
                        .frame(width: 44, height: 34)
                        .background(RoundedRectangle(cornerRadius: 8).fill(Color.white.opacity(0.18)))
                        .contentShape(Rectangle())
                }
                .foregroundColor(.white)
                if current == "mirror", receiver.macDisplays.count > 1 {
                    displayMenu(iconOnly: true)
                }
            }
            speedButton(vertical: true)
            Spacer(minLength: 0)
        }
        .frame(width: 44)
    }

    // MARK: Compact (iPhone): icon buttons; speed in a popover

    private var compactBar: some View {
        HStack(spacing: 4) {
            barButton(systemImage: "keyboard", active: controls.keyboardVisible, width: 44) {
                controls.keyboardVisible.toggle()
            }
            barButton(systemImage: dictation.isListening ? "mic.fill" : "mic",
                      active: dictation.isListening, width: 44) {
                dictation.toggle()
            }
            Spacer(minLength: 0)
            if let current = receiver.senderMode {
                Picker("", selection: Binding(get: { current },
                                              set: { receiver.requestMode($0) })) {
                    Text("Étendre").tag("extend")
                    Text("Recopie").tag("mirror")
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(maxWidth: 130)
                // The labels must stay readable: the icon-only pointer
                // switch below gives way first when the line is tight.
                .layoutPriority(1)
                if current == "mirror", receiver.macDisplays.count > 1 {
                    displayMenu(iconOnly: true)
                }
            }
            Spacer(minLength: 0)
            if showsPointerMode {
                if controls.mode == .touch {
                    barButton(systemImage: "cursorarrow.click.2", active: controls.rightClickArmed, width: 44) {
                        controls.rightClickArmed.toggle()
                    }
                } else {
                    speedButton(vertical: false)   // same spot as the right click, as on the iPad
                }
                Picker("", selection: $controls.mode) {
                    Image(systemName: "rectangle.and.hand.point.up.left").tag(LocalPointerMode.trackpad)
                    Image(systemName: "hand.point.up").tag(LocalPointerMode.touch)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(maxWidth: 100)
            } else {
                speedButton(vertical: false)   // mirror portrait: always a trackpad, button on the right
            }
        }
        .padding(.leading, max(8, insets.left))
        .padding(.trailing, max(8, insets.right))
    }

    // MARK: Regular (iPad)

    private var regularBar: some View {
        HStack(spacing: 12) {
            // Left: keyboard and dictation.
            HStack(spacing: 12) {
                barButton(systemImage: "keyboard", active: controls.keyboardVisible) {
                    controls.keyboardVisible.toggle()
                }
                barButton(systemImage: dictation.isListening ? "mic.fill" : "mic",
                          active: dictation.isListening) {
                    dictation.toggle()
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            // Centre: Extend / Mirror, and which Mac screen to mirror (only
            // when there is a choice).
            HStack(spacing: 12) {
                // Only shown to a sender that announces its mode (this fork).
                if let current = receiver.senderMode {
                    Picker("", selection: Binding(get: { current },
                                                  set: { receiver.requestMode($0) })) {
                        Text("Étendre").tag("extend")
                        Text("Recopie").tag("mirror")
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(width: 180)
                    if current == "mirror", receiver.macDisplays.count > 1 {
                        displayMenu
                    }
                }
            }

            // Right: pointer-mode extras (speed or right click), then the
            // Mouse / Touch switch.
            HStack(spacing: 12) {
                if controls.mode == .touch {
                    barButton(title: "Clic droit", active: controls.rightClickArmed) {
                        controls.rightClickArmed.toggle()
                    }
                } else if !portrait {   // no room for the speed slider in portrait
                    Image(systemName: "tortoise").foregroundColor(.gray)
                    Slider(value: $controls.trackpadSpeed, in: 0.4...2.5)
                        .frame(width: 140)
                    Image(systemName: "hare").foregroundColor(.gray)
                }
                Picker("", selection: $controls.mode) {
                    Label("Souris", systemImage: "rectangle.and.hand.point.up.left").tag(LocalPointerMode.trackpad)
                    Label("Tactile", systemImage: "hand.point.up").tag(LocalPointerMode.touch)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 220)
            }
            .frame(maxWidth: .infinity, alignment: .trailing)
        }
        .padding(.horizontal, 16)
        .frame(maxWidth: .infinity)
        .background(GeometryReader { geo in
            Color.clear
                .onAppear { portrait = geo.size.width < 1100 }
                .onChange(of: geo.size.width) { portrait = $0 < 1100 }
        })
    }

    private var displayMenu: some View { displayMenu(iconOnly: false) }

    private func speedButton(vertical inVerticalBar: Bool) -> some View {
        barButton(systemImage: "speedometer", active: speedShown, width: 44) {
            speedShown.toggle()
        }
        .background(GeometryReader { proxy in
            Color.clear.preference(key: SpeedButtonFrameKey.self,
                                   value: [inVerticalBar: proxy.frame(in: .named(Self.barSpace))])
        })
        .accessibilityLabel("Vitesse du curseur")
    }

    private func displayMenu(iconOnly: Bool) -> some View {
        let selected = receiver.macDisplays.first { $0.id == receiver.selectedMacDisplay }
            ?? receiver.macDisplays.first { $0.main }
            ?? receiver.macDisplays.first
        return Menu {
            ForEach(receiver.macDisplays, id: \.id) { display in
                let title = "\(display.name) — \(display.w)×\(display.h)"
                    + (display.main ? " (principal)" : "")
                Button {
                    receiver.selectedMacDisplay = display.id   // optimistic; the Mac confirms
                    receiver.requestDisplay(display.id)
                } label: {
                    if display.id == selected?.id {
                        Label(title, systemImage: "checkmark")
                    } else {
                        Text(title)
                    }
                }
            }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "display.2").font(.system(size: 18))
                if !iconOnly {
                    Text(selected?.name ?? "Écran")
                        .font(.system(size: 16, weight: .medium))
                        .lineLimit(1)
                }
            }
            .padding(.horizontal, iconOnly ? 0 : 12)
            .frame(maxWidth: iconOnly ? 44 : 220, minHeight: 34)
            .background(RoundedRectangle(cornerRadius: 8).fill(Color.white.opacity(0.18)))
            .contentShape(Rectangle())
        }
        .foregroundColor(.white)
    }

    private func barButton(systemImage: String? = nil, title: String? = nil, active: Bool,
                           width: CGFloat = 110, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Group {
                if let systemImage { Image(systemName: systemImage).font(.system(size: 20)) }
                if let title { Text(title).font(.system(size: 16, weight: .medium)) }
            }
            .frame(width: width, height: 34)
            .background(RoundedRectangle(cornerRadius: 8)
                .fill(active ? Color.accentColor : Color.white.opacity(0.18)))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundColor(.white)
    }
}

/// Content of the trackpad speed popup. Same range and icons as the iPad slider.
private struct TrackpadSpeedPanel: View {
    @Binding var speed: Double

    var body: some View {
        VStack(spacing: 10) {
            HStack {
                Text("Vitesse du curseur").font(.system(size: 15, weight: .semibold))
                Spacer()
                Text(String(format: "×%.1f", speed)).monospacedDigit().foregroundColor(.gray)
            }
            HStack(spacing: 10) {
                Image(systemName: "tortoise").foregroundColor(.gray)
                Slider(value: $speed, in: 0.4...2.5)
                Image(systemName: "hare").foregroundColor(.gray)
            }
        }
        .padding(16)
        .frame(width: 280)
    }
}

/// Where the speed button sits inside the bar, for the popover's arrow.
/// Keyed by the bar that holds the button (vertical or compact): while the
/// mirror layout swaps bars, the outgoing one still reports a stale frame
/// for a moment, and the popover must follow the current one.
private struct SpeedButtonFrameKey: PreferenceKey {
    static var defaultValue: [Bool: CGRect] = [:]
    static func reduce(value: inout [Bool: CGRect], nextValue: () -> [Bool: CGRect]) {
        value.merge(nextValue()) { _, new in new }
    }
}

private extension View {
    /// A real popover on iOS 16.4+, its arrow pointing at `anchor` (the
    /// compact adaptation keeps it a bubble on iPhone); a sheet on older
    /// systems.
    @ViewBuilder
    func speedPopover(isPresented: Binding<Bool>, anchor: CGRect, speed: Binding<Double>) -> some View {
        if #available(iOS 16.4, *) {
            popover(isPresented: isPresented, attachmentAnchor: .rect(.rect(anchor))) {
                TrackpadSpeedPanel(speed: speed)
                    .presentationCompactAdaptation(.popover)
            }
        } else if #available(iOS 16, *) {
            sheet(isPresented: isPresented) {
                TrackpadSpeedPanel(speed: speed)
                    .frame(maxWidth: .infinity)
                    .presentationDetents([.height(120)])
            }
        } else {
            sheet(isPresented: isPresented) {   // iOS 15: full-height sheet, swipe to dismiss
                TrackpadSpeedPanel(speed: speed)
            }
        }
    }
}

// MARK: - Keyboard

/// Invisible first responder that brings up the iPadOS keyboard and forwards
/// what is typed to the Mac. The Mac keys iOS lacks live in `MacKeysRow`,
/// drawn by the app above the bar rather than riding on the keyboard.
final class MacKeyInputView: UIView, UIKeyInput {
    weak var receiver: StreamReceiver?
    var onDismiss: (() -> Void)?

    override var canBecomeFirstResponder: Bool { true }
    // No undo/redo/paste shortcuts bar, no 3-finger editing gestures.
    override var editingInteractionConfiguration: UIEditingInteractionConfiguration { .none }

    // The Mac does its own text handling: no autocorrect, caps or smart punctuation.
    var autocorrectionType: UITextAutocorrectionType = .no
    var autocapitalizationType: UITextAutocapitalizationType = .none
    var spellCheckingType: UITextSpellCheckingType = .no
    var smartQuotesType: UITextSmartQuotesType = .no
    var smartDashesType: UITextSmartDashesType = .no
    var smartInsertDeleteType: UITextSmartInsertDeleteType = .no
    var keyboardType: UIKeyboardType = .default

    var hasText: Bool { true }   // keeps the delete key live

    override func becomeFirstResponder() -> Bool {
        inputAssistantItem.leadingBarButtonGroups = []
        inputAssistantItem.trailingBarButtonGroups = []
        return super.becomeFirstResponder()
    }

    override func resignFirstResponder() -> Bool {
        let resigned = super.resignFirstResponder()
        if resigned { onDismiss?() }
        return resigned
    }

    func insertText(_ text: String) {
        let mods = LocalControls.shared.takeMods()
        switch text {
        case "\n": receiver?.sendKey(code: 36, mods: mods)    // Return
        case "\t": receiver?.sendKey(code: 48, mods: mods)    // Tab
        default: receiver?.sendText(text, mods: mods)
        }
    }

    func deleteBackward() {
        receiver?.sendKey(code: 51, mods: LocalControls.shared.takeMods())   // Delete
    }
}

/// The Mac keys row: dictation, Esc, Tab, ⇧ ⌃ ⌥ ⌘ (one-shot), arrows. Overlaid on the
/// bottom of the picture just above the bar, or above a docked keyboard; a
/// floating keyboard never covers it. The `.phone` layout is the iPhone mirror
/// screen's: in the layout flow (the screen reserves the keyboard's room
/// itself) and sized to fit a 390 pt wide screen, inverted T included.
struct MacKeysRow: View {
    enum Layout { case overlay, phone, phoneWide }

    var layout: Layout = .overlay
    @ObservedObject var controls = LocalControls.shared
    @ObservedObject var dictation = DictationController.shared
    @Environment(\.horizontalSizeClass) private var sizeClass

    static let keyHeight: CGFloat = 43
    static let gap: CGFloat = 6
    private var phone: Bool { layout != .overlay }
    /// Landscape phone: one line, arrows side by side (no inverted T).
    private var wide: Bool { layout == .phoneWide || (layout == .overlay && LocalControls.phoneLandscape) }
    /// Window safe-area insets: a full-width landscape overlay keeps its keys
    /// out from under the notch / Dynamic Island.
    @State private var insets = UIEdgeInsets.zero
    private var keyHeight: CGFloat { phone ? 38 : Self.keyHeight }
    private var gap: CGFloat { phone ? 4 : Self.gap }
    private var keyWidth: CGFloat { sizeClass == .regular ? 72 : 50 }
    private var hPadding: CGFloat {
        if phone { return 8 }
        return wide ? max(10, insets.left, insets.right) : 10
    }
    /// Keys share the line width instead of having a natural one: the phone
    /// layout, and the overlay on a narrow screen (iPhone in portrait; the
    /// natural row is ~600 pt wide). iPad and iPhone landscape are untouched.
    private var flexible: Bool {
        phone || (UIDevice.current.userInterfaceIdiom == .phone
                  && (UIScreen.main.bounds.width < 620 || LocalControls.phoneLandscape))
    }

    var body: some View {
        if controls.keyboardVisible {
            Group {
                if flexible {
                    // Ten key widths share the line with three dividers (1 pt).
                    GeometryReader { geo in
                        let keys: CGFloat = wide ? 11 : 10
                        let gaps: CGFloat = wide ? 13 : 12
                        let unit = max(20, (geo.size.width - 2 * hPadding - gaps * gap - 3) / keys)
                        row(unit: unit)
                            .frame(width: geo.size.width, height: geo.size.height, alignment: .bottom)
                    }
                    .frame(height: wide ? keyHeight + 2 * gap : 2 * keyHeight + 3 * gap)
                } else {
                    row(unit: nil)
                }
            }
            .padding(.bottom, phone ? 0 : LocalControls.keysRowBottomPadding(docked: controls.dockedKeyboardHeight))
            .background(SafeAreaInsetsReader { insets = $0 })
        }
    }

    /// `unit`: the exact width of one key (phone layout); nil lets keys take
    /// their natural width.
    @ViewBuilder
    private func row(unit: CGFloat?) -> some View {
        HStack(alignment: .bottom, spacing: gap) {
            key(systemImage: dictation.isListening ? "mic.fill" : "mic",
                active: dictation.isListening, unit: unit) { dictation.toggle() }
            divider
            sendKey("esc", 53, unit: unit)
            sendKey("tab", 48, unit: unit)
            modKey("⇧", 8, unit: unit)
            divider
            modKey("⌃", 4, unit: unit)
            modKey("⌥", 2, unit: unit)
            modKey("⌘", 1, unit: unit)
            divider
            if wide {
                HStack(spacing: gap) {
                    sendKey("←", 123, unit: unit)
                    sendKey("↑", 126, unit: unit)
                    sendKey("↓", 125, unit: unit)
                    sendKey("→", 124, unit: unit)
                }
            } else {
            // Inverted T, as on the Mac keyboard: ↑ over ← ↓ →.
            VStack(spacing: gap) {
                if let unit {
                    HStack(spacing: gap) {
                        Color.clear.frame(width: unit, height: 0)
                        sendKey("↑", 126, unit: unit)
                            .anchorPreference(key: UpKeyBounds.self, value: .bounds) { $0 }
                        Color.clear.frame(width: unit, height: 0)
                    }
                } else {
                    sendKey("↑", 126, unit: nil)
                        .anchorPreference(key: UpKeyBounds.self, value: .bounds) { $0 }
                }
                HStack(spacing: gap) {
                    sendKey("←", 123, unit: unit)
                    sendKey("↓", 125, unit: unit)
                    sendKey("→", 124, unit: unit)
                }
            }
            }
        }
        .padding(.horizontal, hPadding)
        .padding(.vertical, gap)
        // The panel hugs the keys: one bar for the bottom line plus a tab
        // behind ↑, flattened before the opacity so the overlap is even.
        // (The phone layout sits on black already.)
        .backgroundPreferenceValue(UpKeyBounds.self) { anchor in
            if !phone {
                GeometryReader { g in
                    ZStack(alignment: .topLeading) {
                        RoundedRectangle(cornerRadius: 12)
                            .frame(height: keyHeight + 2 * gap)
                            .frame(maxHeight: .infinity, alignment: .bottom)
                        if let up = anchor.map({ g[$0] }) {
                            RoundedRectangle(cornerRadius: 12)
                                .frame(width: up.width + 2 * gap, height: up.height + 4 * gap)
                                .offset(x: up.minX - gap, y: up.minY - gap)
                        }
                    }
                    .foregroundColor(.black)
                    .compositingGroup()
                    .opacity(0.85)
                }
            }
        }
        .environment(\.colorScheme, .dark)
    }

    private var divider: some View {
        Divider().frame(width: flexible ? 1 : nil, height: 24).overlay(Color.white.opacity(0.3))
            .frame(height: keyHeight)
    }

    /// Tap for one key, swipe up to lock (a bar under the symbol shows it).
    private func modKey(_ title: String, _ bit: Int, unit: CGFloat?) -> some View {
        let locked = controls.lockedMods & bit != 0
        return key(title, active: locked || controls.mods & bit != 0, locked: locked, unit: unit) {
            controls.tapModifier(bit)
        }
        .highPriorityGesture(DragGesture(minimumDistance: 12).onEnded { drag in
            guard drag.translation.height < -20,
                  abs(drag.translation.height) > abs(drag.translation.width) else { return }
            controls.lockModifier(bit)
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
        })
    }

    private func sendKey(_ title: String, _ code: Int, unit: CGFloat?) -> some View {
        key(title, active: false, unit: unit) {
            controls.receiver?.sendKey(code: code, mods: controls.takeMods())
        }
    }

    private func key(_ title: String = "", systemImage: String? = nil, active: Bool,
                     locked: Bool = false, unit: CGFloat?, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Group {
                if let systemImage { Image(systemName: systemImage) } else { Text(title) }
            }
                .font(.system(size: flexible ? 15 : 18, weight: .medium))
                .foregroundColor(.white)
                .frame(minWidth: unit == nil ? keyWidth : nil, minHeight: keyHeight)
                .frame(width: unit)
                .overlay(Capsule().fill(Color.white).frame(width: 14, height: 3)
                    .padding(.bottom, 5).opacity(locked ? 1 : 0), alignment: .bottom)
                .background(RoundedRectangle(cornerRadius: 8)
                    .fill(active ? Color.accentColor : Color.white.opacity(0.18)))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

private struct UpKeyBounds: PreferenceKey {
    static var defaultValue: Anchor<CGRect>? = nil
    static func reduce(value: inout Anchor<CGRect>?, nextValue: () -> Anchor<CGRect>?) {
        value = value ?? nextValue()
    }
}

// MARK: - Trackpad

/// Trackpad mode, recognized on the receiver: one finger moves the pointer
/// with macOS-like acceleration, a tap clicks (taps in a row count up), a
/// two-finger tap right-clicks, two fingers scroll with momentum, three
/// fingers drag with the button held.
final class TrackpadEngine {
    weak var receiver: StreamReceiver?
    /// View points per video pixel (scroll deltas travel in video pixels).
    var pointsPerVideoPixel: () -> CGFloat = { 1 }

    private enum Gesture { case none, pointing, scrolling, dragging, settling }

    private var last: [ObjectIdentifier: (point: CGPoint, time: TimeInterval)] = [:]
    private var gesture = Gesture.none
    private var gestureStart: TimeInterval = 0
    private var maxFingers = 0
    private var travel: CGFloat = 0
    private var lastTapEnd: TimeInterval = 0
    private var tapCount = 0
    private var scrollSamples: [(time: TimeInterval, delta: CGPoint)] = []
    // Pinch detection inside a two-finger gesture: finger spread vs centroid travel.
    private var pinching = false
    private var pinchSpread: CGFloat = 0     // current finger distance, points
    private var pinchSpreadChange: CGFloat = 0
    private var pinchPanTravel: CGFloat = 0
    private let pinchStartSpread: CGFloat = 16   // points of spread change to latch
    private var momentum: CADisplayLink?
    private var momentumVelocity = CGPoint.zero   // video pixels per second
    private var lastMomentumTime: CFTimeInterval = 0

    private let tapMaxDuration: TimeInterval = 0.25
    private let tapMaxTravel: CGFloat = 10
    private let multiClickInterval: TimeInterval = 0.4

    /// Pointer gain for a finger speed in points per second: slow moves stay
    /// precise, fast flicks cross the screen — the shape of macOS's curve.
    private func gain(forSpeed v: CGFloat) -> CGFloat {
        CGFloat(LocalControls.shared.trackpadSpeed) * (0.5 + 2.8 * v / (v + 1000))
    }

    func began(_ touches: Set<UITouch>, all: Set<UITouch>) {
        stopMomentum()
        // Window coordinates: the video view itself slides with the keyboard
        // shift, and a still finger must not read as a move when it does.
        for t in touches { last[ObjectIdentifier(t)] = (t.location(in: nil), t.timestamp) }
        let count = last.count
        if gesture == .none {
            gesture = .pointing
            gestureStart = touches.first?.timestamp ?? CACurrentMediaTime()
            travel = 0
            maxFingers = 0
        }
        maxFingers = max(maxFingers, count)
        switch count {
        case 2 where gesture == .pointing:
            gesture = .scrolling
            scrollSamples.removeAll()
            pinching = false
            pinchSpreadChange = 0
            pinchPanTravel = 0
            pinchSpread = fingerSpread()
        case 3... where gesture == .pointing || gesture == .scrolling:
            gesture = .dragging
            receiver?.sendButton(right: false, down: true)
        default: break
        }
    }

    func moved(_ touches: Set<UITouch>, event: UIEvent?) {
        // Per-finger displacement since the last callback, from the newest
        // coalesced sample (UIKit batches several per frame).
        var deltas: [CGPoint] = []
        var dt: TimeInterval = 0
        for t in touches {
            let id = ObjectIdentifier(t)
            guard let prev = last[id] else { continue }
            let newest = event?.coalescedTouches(for: t)?.last ?? t
            let p = newest.location(in: nil)
            deltas.append(CGPoint(x: p.x - prev.point.x, y: p.y - prev.point.y))
            dt = max(dt, newest.timestamp - prev.time)
            last[id] = (p, newest.timestamp)
        }
        guard !deltas.isEmpty else { return }
        // Fingers that did not move this callback count as zero: average over
        // all fingers down, so the centroid moves at the right rate.
        let n = CGFloat(max(last.count, deltas.count))
        let d = CGPoint(x: deltas.map(\.x).reduce(0, +) / n, y: deltas.map(\.y).reduce(0, +) / n)
        let distance = hypot(d.x, d.y)
        travel += distance

        switch gesture {
        case .pointing where last.count == 1, .dragging:
            let speed = dt > 0 ? distance / CGFloat(dt) : 0
            let g = gain(forSpeed: speed)
            receiver?.sendPointer(dx: Double(d.x * g), dy: Double(d.y * g))
        case .scrolling:
            // Pinch vs scroll: latch into pinch once the spread changes by
            // more than the centroid has travelled; it then replaces scroll.
            let spread = fingerSpread()
            if last.count == 2, pinchSpread > 0, spread > 0 {
                let change = spread - pinchSpread
                pinchSpread = spread
                if pinching {
                    receiver?.sendMagnify(delta: Double(change / (spread - change)))
                    return
                }
                pinchSpreadChange += change
                pinchPanTravel += distance
                if abs(pinchSpreadChange) > pinchStartSpread, abs(pinchSpreadChange) > pinchPanTravel {
                    pinching = true
                    scrollSamples.removeAll()
                    return
                }
            }
            let s = pointsPerVideoPixel()
            let px = CGPoint(x: d.x / s, y: d.y / s)
            receiver?.sendScroll(dx: Double(px.x), dy: Double(px.y))
            let now = CACurrentMediaTime()
            scrollSamples.append((now, px))
            scrollSamples.removeAll { now - $0.time > 0.08 }
        default:
            break
        }
    }

    /// Distance between the two fingers down (0 unless exactly two).
    private func fingerSpread() -> CGFloat {
        let points = last.values.map(\.point)
        guard points.count == 2 else { return 0 }
        return hypot(points[0].x - points[1].x, points[0].y - points[1].y)
    }

    func ended(_ touches: Set<UITouch>, cancelled: Bool) {
        for t in touches { last.removeValue(forKey: ObjectIdentifier(t)) }
        let wasPinching = pinching
        if pinching {
            pinching = false
            receiver?.sendMagnify(delta: 0)
        }
        guard last.isEmpty else {
            // Some fingers still down: a scroll or drag keeps its meaning,
            // but the leftover finger must not start steering the pointer.
            if gesture == .pointing || gesture == .scrolling { gesture = .settling }
            return
        }
        let now = touches.first?.timestamp ?? CACurrentMediaTime()
        let isTap = !cancelled && now - gestureStart <= tapMaxDuration && travel <= tapMaxTravel

        switch gesture {
        case .dragging:
            receiver?.sendButton(right: false, down: false)
        case .pointing where isTap && maxFingers == 1:
            let wallNow = CACurrentMediaTime()
            tapCount = wallNow - lastTapEnd <= multiClickInterval ? min(tapCount + 1, 3) : 1
            lastTapEnd = wallNow
            receiver?.sendButton(right: false, down: true, clicks: tapCount)
            receiver?.sendButton(right: false, down: false, clicks: tapCount)
        case .scrolling, .settling:
            if isTap && maxFingers == 2 && !wasPinching {
                receiver?.sendButton(right: true, down: true)
                receiver?.sendButton(right: true, down: false)
            } else if gesture == .scrolling, !cancelled, !wasPinching {
                startMomentum()
            }
        default:
            break
        }
        gesture = .none
    }

    func reset() {
        if pinching { receiver?.sendMagnify(delta: 0) }
        pinching = false
        if gesture == .dragging { receiver?.sendButton(right: false, down: false) }
        last.removeAll()
        gesture = .none
        stopMomentum()
    }

    // MARK: Momentum

    private func startMomentum() {
        guard let first = scrollSamples.first, let lastSample = scrollSamples.last else { return }
        let span = max(lastSample.time - first.time, 1.0 / 120)
        let sum = scrollSamples.reduce(CGPoint.zero) { CGPoint(x: $0.x + $1.delta.x, y: $0.y + $1.delta.y) }
        let v = CGPoint(x: sum.x / CGFloat(span), y: sum.y / CGFloat(span))
        scrollSamples.removeAll()
        guard hypot(v.x, v.y) > 300 else { return }   // a slow lift just stops
        momentumVelocity = v
        lastMomentumTime = CACurrentMediaTime()
        let link = CADisplayLink(target: self, selector: #selector(momentumTick))
        link.add(to: .main, forMode: .common)
        momentum = link
    }

    @objc private func momentumTick(_ link: CADisplayLink) {
        let now = link.timestamp
        let dt = CGFloat(max(0, now - lastMomentumTime))
        lastMomentumTime = now
        // Exponential decay, ~0.35 s time constant — close to macOS's glide.
        let decay = exp(-dt / 0.35)
        momentumVelocity = CGPoint(x: momentumVelocity.x * decay, y: momentumVelocity.y * decay)
        guard hypot(momentumVelocity.x, momentumVelocity.y) > 40 else { stopMomentum(); return }
        receiver?.sendScroll(dx: Double(momentumVelocity.x * dt), dy: Double(momentumVelocity.y * dt))
    }

    private func stopMomentum() {
        momentum?.invalidate()
        momentum = nil
    }
}

// MARK: - Safe area reader

/// Reports the window's safe-area insets (also when they change, on
/// rotation). The receiver screen ignores the safe area to use the whole
/// panel, so views that must stay clear of the Dynamic Island, the rounded
/// corners or the home indicator read them from here.
struct SafeAreaInsetsReader: UIViewRepresentable {
    let onChange: (UIEdgeInsets) -> Void

    func makeUIView(context: Context) -> InsetsView {
        let view = InsetsView()
        view.isUserInteractionEnabled = false
        view.onChange = onChange
        return view
    }

    func updateUIView(_ uiView: InsetsView, context: Context) {
        uiView.onChange = onChange
    }

    final class InsetsView: UIView {
        var onChange: ((UIEdgeInsets) -> Void)?
        private var last: UIEdgeInsets?

        override func didMoveToWindow() { super.didMoveToWindow(); report() }
        override func safeAreaInsetsDidChange() { super.safeAreaInsetsDidChange(); report() }
        override func layoutSubviews() { super.layoutSubviews(); report() }

        private func report() {
            guard let insets = window?.safeAreaInsets, insets != last else { return }
            last = insets
            // Never mutate SwiftUI state in the middle of a layout pass.
            DispatchQueue.main.async { [weak self] in self?.onChange?(insets) }
        }
    }
}
