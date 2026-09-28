import SwiftUI
import AppKit

/// How receiver touches drive the Mac pointer.
enum PointerMode: String {
    /// The receiver is a touchscreen: the cursor jumps under the finger.
    case touch
    /// The receiver is a giant trackpad: the finger moves the cursor
    /// relatively, a tap clicks where the cursor already is.
    case trackpad
}

/// Shared between the main actor (the bar's UI) and the sender queue that
/// feeds `InputInjector`, hence the lock.
final class PointerModeState {
    static let shared = PointerModeState()

    private let lock = NSLock()
    private var _mode = PointerMode(rawValue: UserDefaults.standard.string(forKey: "pointerMode") ?? "") ?? .touch
    private var _barRect: CGRect?

    var mode: PointerMode {
        get { lock.withLock { _mode } }
        set {
            lock.withLock { _mode = newValue }
            UserDefaults.standard.set(newValue.rawValue, forKey: "pointerMode")
        }
    }

    /// The control bar's frame in global CG coordinates (y-down), so a touch
    /// on the bar stays a direct click even in trackpad mode — otherwise the
    /// switch back to touch mode could not be reached with a finger.
    var barRect: CGRect? {
        get { lock.withLock { _barRect } }
        set { lock.withLock { _barRect = newValue } }
    }

    /// Same, for the on-screen keyboard: one taps a key, one does not steer
    /// a cursor onto it.
    var keyboardRect: CGRect? {
        get { lock.withLock { _keyboardRect } }
        set { lock.withLock { _keyboardRect = newValue } }
    }
    private var _keyboardRect: CGRect?

    /// Armed by the bar's "Clic droit" button: the next press becomes a right
    /// click, then it disarms itself. One-shot, like the keyboard's modifiers.
    var rightClickArmed: Bool {
        get { lock.withLock { _rightClickArmed } }
        set {
            lock.withLock { _rightClickArmed = newValue }
            notifyRightClick(newValue)
        }
    }
    private var _rightClickArmed = false

    /// Lets the bar's button follow a disarm that happens on the sender queue.
    var onRightClickArmedChanged: (@MainActor (Bool) -> Void)?

    /// Consumes the arming for a press at `point`. A press on the bar or the
    /// keyboard never consumes it: tapping the button again must disarm it
    /// with an ordinary click, and a key must stay a key.
    func takeRightClick(at point: CGPoint) -> Bool {
        let taken: Bool = lock.withLock {
            guard _rightClickArmed else { return false }
            let onControls = (_barRect?.contains(point) ?? false)
                || (_keyboardRect?.contains(point) ?? false)
            guard !onControls else { return false }
            _rightClickArmed = false
            return true
        }
        if taken { notifyRightClick(false) }
        return taken
    }

    private func notifyRightClick(_ armed: Bool) {
        Task { @MainActor [weak self] in self?.onRightClickArmedChanged?(armed) }
    }

    /// A touch here is always a direct click, whatever the pointer mode.
    func isDirect(_ point: CGPoint) -> Bool {
        lock.withLock {
            (_barRect?.contains(point) ?? false) || (_keyboardRect?.contains(point) ?? false)
        }
    }
}

/// A black strip along the bottom of the streamed display (the mirrored Mac
/// screen, or the iPad's virtual display in Extend). It is a real window on
/// the Mac, so it streams to the receiver like any other pixel and a finger
/// on it is an ordinary click — no receiver change needed.
@MainActor
enum MirrorControlBar {
    static let height: CGFloat = 44

    private static var panel: NSPanel?
    private static var displayID: CGDirectDisplayID?
    private static var screenObserver: NSObjectProtocol?
    private static let model = MirrorBarModel()

    static func show(on displayID: CGDirectDisplayID) {
        hide()
        guard UserDefaults.standard.object(forKey: "mirrorControlBar") as? Bool ?? true else { return }
        self.displayID = displayID
        place(attempt: 0)
        // Re-placed when screens change: a display rearranged, resized or
        // (in Extend) the virtual display coming online a moment late.
        screenObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didChangeScreenParametersNotification,
            object: nil, queue: .main) { _ in
            Task { @MainActor in place(attempt: 0) }
        }
    }

    /// A freshly created virtual display can reach NSScreen a little after
    /// its capture starts — retry briefly before giving up.
    private static func place(attempt: Int) {
        guard let displayID else { return }
        guard let screen = NSScreen.screens.first(where: {
            ($0.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? CGDirectDisplayID) == displayID
        }) else {
            if attempt < 10 {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                    Task { @MainActor in place(attempt: attempt + 1) }
                }
            } else {
                Log.info("control bar: no screen for display \(displayID)")
            }
            return
        }
        let frame = NSRect(x: screen.frame.minX, y: screen.frame.minY,
                           width: screen.frame.width, height: height)
        if let panel {
            panel.setFrame(frame, display: true)
        } else {
            let p = NSPanel(contentRect: frame,
                            styleMask: [.borderless, .nonactivatingPanel],
                            backing: .buffered, defer: false)
            p.level = .statusBar   // above the Dock
            p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
            p.isFloatingPanel = true
            p.hidesOnDeactivate = false
            p.becomesKeyOnlyIfNeeded = true
            p.backgroundColor = .black
            p.hasShadow = false
            p.contentView = FirstMouseHostingView(rootView: MirrorBarView(model: model))
            p.setFrame(frame, display: true)
            p.orderFrontRegardless()
            panel = p
            OnScreenKeyboard.attach(to: displayID)
            Log.info("control bar shown on display \(displayID)")
        }

        let bounds = CGDisplayBounds(displayID)
        PointerModeState.shared.barRect = CGRect(x: bounds.minX, y: bounds.maxY - height,
                                                 width: bounds.width, height: height)
    }

    /// Hides the bar only if it is on `displayID` — a session ending must not
    /// take down the bar another device's session is showing.
    static func hide(ifOn displayID: CGDirectDisplayID) {
        guard displayID != 0, self.displayID == displayID else { return }
        hide()
    }

    static func hide() {
        if let screenObserver { NotificationCenter.default.removeObserver(screenObserver) }
        screenObserver = nil
        displayID = nil
        OnScreenKeyboard.detach()
        panel?.orderOut(nil)
        panel = nil
        PointerModeState.shared.barRect = nil
    }
}

/// The bar never becomes key, so its first click must count — otherwise every
/// tap on it would be spent making the window key.
private final class FirstMouseHostingView<Content: View>: NSHostingView<Content> {
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
}

@MainActor
private final class MirrorBarModel: ObservableObject {
    @Published var mode = PointerModeState.shared.mode {
        didSet { PointerModeState.shared.mode = mode }
    }
    @Published var rightClickArmed = false

    init() {
        PointerModeState.shared.onRightClickArmedChanged = { [weak self] armed in
            self?.rightClickArmed = armed
        }
    }

    func toggleRightClick() {
        PointerModeState.shared.rightClickArmed.toggle()
    }
}

private struct MirrorBarView: View {
    @ObservedObject var model: MirrorBarModel

    var body: some View {
        HStack(spacing: 16) {
            Button {
                OnScreenKeyboard.toggle()
            } label: {
                // The grey is INSIDE the label and the whole rectangle is the
                // hit shape: a plain button only answers where it draws, and
                // with the grey laid behind it, a finger on the grey missed.
                Image(systemName: "keyboard")
                    .font(.system(size: 22))
                    .frame(width: 120, height: 36)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color.white.opacity(0.18)))
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(.white)

            Button {
                model.toggleRightClick()
            } label: {
                Text("Clic droit")
                    .font(.system(size: 16, weight: .medium))
                    .frame(width: 120, height: 36)
                    .background(RoundedRectangle(cornerRadius: 8)
                        .fill(model.rightClickArmed ? Color.accentColor : Color.white.opacity(0.18)))
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(.white)

            Spacer()

            Picker("", selection: $model.mode) {
                Label("Tactile", systemImage: "hand.point.up").tag(PointerMode.touch)
                Label("Souris", systemImage: "rectangle.and.hand.point.up.left").tag(PointerMode.trackpad)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 240)
        }
        .padding(.horizontal, 16)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.black)
        .environment(\.colorScheme, .dark)
    }
}
