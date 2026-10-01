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
        didSet { UserDefaults.standard.set(mode.rawValue, forKey: "pointerMode") }
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
    /// Whether the latest shift change should animate.
    var animateShift = false
    /// Height the Mac keys row takes above the bar or the keyboard.
    static let keysRowHeight: CGFloat = 54
    /// Sticky one-shot modifiers from the Mac keys row (1 ⌘, 2 ⌥, 4 ⌃, 8 ⇧).
    @Published var mods = 0
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

    func takeMods() -> Int {
        let current = mods
        if current != 0 { mods = 0 }
        return current
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

    var body: some View {
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
                } else {
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
        .frame(height: LocalControls.barHeight)
        .background(Color.black)
        .environment(\.colorScheme, .dark)
    }

    private var displayMenu: some View {
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
                Text(selected?.name ?? "Écran")
                    .font(.system(size: 16, weight: .medium))
                    .lineLimit(1)
            }
            .padding(.horizontal, 12)
            .frame(maxWidth: 220, minHeight: 34)
            .background(RoundedRectangle(cornerRadius: 8).fill(Color.white.opacity(0.18)))
            .contentShape(Rectangle())
        }
        .foregroundColor(.white)
    }

    private func barButton(systemImage: String? = nil, title: String? = nil, active: Bool,
                           action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Group {
                if let systemImage { Image(systemName: systemImage).font(.system(size: 20)) }
                if let title { Text(title).font(.system(size: 16, weight: .medium)) }
            }
            .frame(width: 110, height: 34)
            .background(RoundedRectangle(cornerRadius: 8)
                .fill(active ? Color.accentColor : Color.white.opacity(0.18)))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundColor(.white)
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

/// The Mac keys row: ⌘ ⌥ ⌃ ⇧ (one-shot), Esc, Tab, arrows, ⌦. Overlaid on the
/// bottom of the picture just above the bar, or above a docked keyboard; a
/// floating keyboard never covers it.
struct MacKeysRow: View {
    @ObservedObject var controls = LocalControls.shared

    var body: some View {
        if controls.keyboardVisible {
            HStack(spacing: 6) {
                ForEach([("⌘", 1), ("⌥", 2), ("⌃", 4), ("⇧", 8)], id: \.1) { title, bit in
                    key(title, active: controls.mods & bit != 0) { controls.mods ^= bit }
                }
                Divider().frame(height: 24).overlay(Color.white.opacity(0.3))
                ForEach([("esc", 53), ("tab", 48), ("←", 123), ("↓", 125),
                         ("↑", 126), ("→", 124), ("⌦", 117)], id: \.1) { title, code in
                    key(title, active: false) {
                        controls.receiver?.sendKey(code: code, mods: controls.takeMods())
                    }
                }
                Divider().frame(height: 24).overlay(Color.white.opacity(0.3))
                key("⌨︎↓", active: false) { controls.keyboardVisible = false }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.black.opacity(0.85)))
            .padding(.bottom, max(0, controls.dockedKeyboardHeight - LocalControls.barHeight) + 6)
            .environment(\.colorScheme, .dark)
        }
    }

    private func key(_ title: String, active: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 18, weight: .medium))
                .foregroundColor(.white)
                .frame(minWidth: 48, minHeight: 36)
                .background(RoundedRectangle(cornerRadius: 7)
                    .fill(active ? Color.accentColor : Color.white.opacity(0.18)))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
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
