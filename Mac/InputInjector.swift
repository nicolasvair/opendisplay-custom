import CoreGraphics
import AppKit
import Darwin

/// System double-click thresholds. Interval is public API; distance is read from
/// AppKit's `NSDoubleClickDistance()` (same value the Window Server uses).
private enum SystemClickMetrics {
    static var interval: TimeInterval { NSEvent.doubleClickInterval }

    static var distance: CGFloat {
        doubleClickDistanceFn?() ?? 4
    }

    private typealias DoubleClickDistanceFn = @convention(c) () -> CGFloat
    private static let doubleClickDistanceFn: DoubleClickDistanceFn? = {
        guard let handle = dlopen("/System/Library/Frameworks/AppKit.framework/AppKit", RTLD_LAZY),
              let sym = dlsym(handle, "NSDoubleClickDistance") else { return nil }
        return unsafeBitCast(sym, to: DoubleClickDistanceFn.self)
    }()
}

/// Turns normalized touch coordinates from the phone into mouse events on a
/// target display. Touch semantics: finger down = left button down, finger
/// move = drag, finger up = button up — i.e. the phone acts as a touchscreen.
final class InputInjector {

    private let displayID: CGDirectDisplayID
    private var isDown = false
    private var pressIsRight = false   // the current touchscreen press is a right click
    private var penDown = false
    // A real event source (vs nil) plus non-zero clickState on down/up: menu
    // tracking treats sourceless/zero-click synthetic clicks as malformed — menus
    // open but their tracking session breaks, leaving zombie menu windows
    // composited on the display (visible in the stream, unclickable).
    private let source = CGEventSource(stateID: .hidSystemState)
    // Synthetic OpenDisplay tablet — conspicuous in logs; not Wacom (0x056A) or
    // typical small driver IDs (1, 2, …).
    private let tabletVendorID: Int64 = 0x0D15       // "ODIS"
    private let tabletProductID: Int64 = 0x0101
    private let deviceID: Int64 = 424242
    private let pointerID: Int64 = 0x0D02              // pen tip
    private let vendorPointerType: Int64 = 0x0802    // Grip Pen (what apps expect)
    private let capabilityMask: Int64 = 0x05C7       // pressure + tilt + rotation + buttons
    private var inRange = false

    // Pencil-only synthetic click counting — tablet events don't get click
    // state from the Window Server, so we mirror macOS double-click prefs here.
    private struct PenClickSession {
        let downLocation: CGPoint
        let clickState: Int
    }

    private struct PenCompletedClick {
        let upTime: CFAbsoluteTime
        let downLocation: CGPoint
        let clickState: Int
    }

    private var penClickSession: PenClickSession?
    private var penLastClick: PenCompletedClick?

    /// Mirror mode: the cursor is free to leave the mirrored display, but it
    /// is brought back onto it when a session starts and when the receiver
    /// switches to trackpad mode — off it, it vanishes from the receiver's
    /// picture and the trackpad looks frozen.
    private let mirrored: Bool
    private var lastMode = PointerModeState.shared.mode

    init(displayID: CGDirectDisplayID, mirrored: Bool = false) {
        self.displayID = displayID
        self.mirrored = mirrored
        if mirrored { bringCursorOntoDisplay() }
    }

    /// A cursor left on another screen (e.g. after the mirrored screen was
    /// switched) is moved to the middle of the mirrored one.
    private func bringCursorOntoDisplay() {
        let bounds = CGDisplayBounds(displayID)
        guard !bounds.isEmpty, !bounds.contains(currentCursor()) else { return }
        CGWarpMouseCursorPosition(CGPoint(x: bounds.midX, y: bounds.midY))
        CGAssociateMouseAndMouseCursorPosition(1)
    }

    static func ensureAccessibilityPermission() -> Bool {
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue(): true] as CFDictionary
        let trusted = AXIsProcessTrustedWithOptions(options)
        if !trusted {
            Log.info("Accessibility permission missing — prompt requested")
        }
        return trusted
    }

    /// x/y are normalized [0,1] in video space (origin top-left).
    func handleTouch(phase: String, x: Double, y: Double, allowTrackpad: Bool = true) {
        let mode = PointerModeState.shared.mode
        if mirrored, mode == .trackpad, lastMode != .trackpad { bringCursorOntoDisplay() }
        lastMode = mode
        let bounds = CGDisplayBounds(displayID)   // global CG coords, y-down
        let point = CGPoint(
            x: bounds.origin.x + x * bounds.width,
            y: bounds.origin.y + y * bounds.height
        )
        if allowTrackpad, handleTrackpad(phase: phase, point: point, bounds: bounds) { return }

        let type: CGEventType
        // Click count on the release. A cancel means "a second finger joined,
        // this was a scroll, not a tap" — but there is no CGEvent for undoing a
        // press, and a plain up over the press point is indistinguishable from a
        // click, so every two-finger scroll opened whatever was under finger one.
        // Releasing with clickCount 0 keeps the button state honest while telling
        // AppKit and WebKit not to synthesize a click. Only the cancel path gets
        // 0: a zero-click *down* is what breaks menu tracking (see above).
        var clickState = 1
        switch phase {
        case "began":
            pressIsRight = PointerModeState.shared.takeRightClick(at: point)
            type = pressIsRight ? .rightMouseDown : .leftMouseDown
            isDown = true
        case "moved":
            type = isDown ? (pressIsRight ? .rightMouseDragged : .leftMouseDragged) : .mouseMoved
        case "ended":
            guard isDown else { return }   // spurious up without a down
            type = pressIsRight ? .rightMouseUp : .leftMouseUp
            isDown = false
        case "cancelled":
            guard isDown else { return }
            type = pressIsRight ? .rightMouseUp : .leftMouseUp
            isDown = false
            clickState = 0
        default:
            return
        }

        guard let event = CGEvent(mouseEventSource: source, mouseType: type,
                                  mouseCursorPosition: point,
                                  mouseButton: pressIsRight ? .right : .left) else { return }
        event.setIntegerValueField(.mouseEventClickState, value: Int64(clickState))
        event.post(tap: .cghidEventTap)
    }

    // MARK: - Trackpad mode

    /// The receiver cannot say when a finger lands: it withholds `began` until
    /// the press commits (hold or slop) and then sends it at the LANDING point,
    /// after hover `moved`s that already went further. So a stroke is read off
    /// the message stream itself — a gap or a jump starts a new one — and
    /// `began` only marks the finger as down, its coordinates are not used.
    private struct PadStroke {
        var lastEvent: CFAbsoluteTime = 0
        var lastPoint = CGPoint.zero
        var start: CFAbsoluteTime = 0
        var travel: CGFloat = 0
        var cursor = CGPoint.zero
        var direct = true          // stroke handled as a touchscreen
        var dragArmed = false      // stroke began right after a tap
        var dragging = false
        var fingerDown = false     // between `began` and `ended`/`cancelled`
        var lastTapEnd: CFAbsoluteTime = 0
        var lastTapPoint = CGPoint.zero
        var tapCount = 0
    }
    private var pad = PadStroke()

    /// Messages further apart than this belong to different strokes. UIKit
    /// sends nothing while a finger rests, so a resumed movement also counts
    /// as new — it only loses its first sample.
    private let strokeGap: CFTimeInterval = 0.08
    /// A single-sample move this large is a new finger, not motion (e.g. the
    /// two-finger scroll's one positioning `moved`).
    private let strokeJump: CGFloat = 150
    /// A finger held still this long, then slid, drags. Measured as the
    /// silence after the press commits (~120 ms after landing on the receiver).
    private let longPressDelay: CFTimeInterval = 0.3
    /// Constant on purpose: the receiver also sends predicted samples that are
    /// corrected by the next real one, and only a linear gain lets those
    /// back-and-forth deltas cancel exactly.
    private var trackpadGain: CGFloat {
        let v = UserDefaults.standard.double(forKey: "trackpadSpeed")
        return v > 0 ? CGFloat(v) : 1.6
    }

    /// Returns true when the event was consumed as trackpad input.
    private func handleTrackpad(phase: String, point: CGPoint, bounds: CGRect) -> Bool {
        let state = PointerModeState.shared
        let now = CFAbsoluteTimeGetCurrent()
        let jump = hypot(point.x - pad.lastPoint.x, point.y - pad.lastPoint.y)
        // A committed finger may rest (UIKit sends nothing then) and move
        // again: that is still one stroke — it is what makes a long press
        // readable at all.
        let newStroke = !pad.fingerDown
            && (now - pad.lastEvent > strokeGap || jump > strokeJump)
        let silence = now - pad.lastEvent
        pad.lastEvent = now

        if newStroke, phase == "moved" || phase == "began" {
            if pad.dragging {   // a drag whose end never arrived
                postMouse(.leftMouseUp, at: pad.cursor, clickState: 1)
                pad.dragging = false
            }
            pad.lastPoint = point
            pad.start = now
            pad.travel = 0
            // A touch on the control bar stays a direct click, so the switch
            // back to touch mode is always reachable.
            pad.direct = state.mode != .trackpad || state.isDirect(point)
            pad.cursor = currentCursor()
            pad.dragArmed = now - pad.lastTapEnd <= SystemClickMetrics.interval
            if phase == "began" { pad.fingerDown = true }
            Log.info("pointer stroke: \(phase) mode=\(state.mode.rawValue) direct=\(pad.direct) "
                + "at=\(Int(point.x)),\(Int(point.y)) bar=\(state.barRect.map { "\($0)" } ?? "nil") "
                + "kb=\(state.keyboardRect.map { "\($0)" } ?? "nil")")
            return !pad.direct
        }
        if pad.direct {
            // The finger's state is tracked for EVERY stroke, direct ones
            // included: a `began` left without its `ended` would glue every
            // later touch into one endless direct stroke, and trackpad mode
            // would never engage again.
            switch phase {
            case "began": pad.fingerDown = true
            case "ended", "cancelled":
                pad.fingerDown = false
                pad.lastEvent = 0
            default: break
            }
            return false
        }

        switch phase {
        case "moved":
            let dx = point.x - pad.lastPoint.x
            let dy = point.y - pad.lastPoint.y
            pad.lastPoint = point
            // UIKit sends nothing while a finger rests, so the silence
            // before this sample IS how long the finger held still.
            if !pad.dragging, pad.fingerDown, pad.travel < 8,
               silence >= longPressDelay {
                // Hold still, then slide: drag.
                pad.dragging = true
                postMouse(.leftMouseDown, at: pad.cursor, clickState: 1)
            }
            pad.travel += hypot(dx, dy)
            if pad.dragArmed, !pad.dragging, pad.travel > 6 {
                // Tap, then touch again and slide: drag, as on a Mac trackpad.
                pad.dragging = true
                postMouse(.leftMouseDown, at: pad.cursor, clickState: 1)
            }
            let g = trackpadGain
            pad.cursor = desktopPoint(from: pad.cursor,
                                      to: CGPoint(x: pad.cursor.x + dx * g, y: pad.cursor.y + dy * g),
                                      fallback: bounds)
            postMouse(pad.dragging ? .leftMouseDragged : .mouseMoved, at: pad.cursor, clickState: 0)
        case "began":
            // Finger committed; its coordinates are the landing point, already past.
            pad.fingerDown = true
        case "ended":
            if pad.dragging {
                postMouse(.leftMouseUp, at: pad.cursor, clickState: 1)
                pad.dragging = false
                pad.lastTapEnd = 0
            } else if pad.travel < 8, now - pad.start < 0.35,
                      PointerModeState.shared.takeRightClick(at: pad.cursor) {
                // Armed from the bar: this tap is a right click. It stays out
                // of the multi-click chain and arms no tap-and-drag.
                postMouse(.rightMouseDown, at: pad.cursor, clickState: 1, button: .right)
                postMouse(.rightMouseUp, at: pad.cursor, clickState: 1, button: .right)
                pad.lastTapEnd = 0
            } else if pad.travel < 8, now - pad.start < 0.35 {
                // A tap clicks where the cursor is; taps in a row count up
                // (double click, triple click) like the system does.
                let near = hypot(pad.cursor.x - pad.lastTapPoint.x,
                                 pad.cursor.y - pad.lastTapPoint.y) <= SystemClickMetrics.distance
                let count = (now - pad.lastTapEnd <= SystemClickMetrics.interval && near)
                    ? pad.tapCount + 1 : 1
                postMouse(.leftMouseDown, at: pad.cursor, clickState: count)
                postMouse(.leftMouseUp, at: pad.cursor, clickState: count)
                pad.tapCount = count
                pad.lastTapEnd = now
                pad.lastTapPoint = pad.cursor
            }
            pad.fingerDown = false
            pad.lastEvent = 0   // the next message starts a new stroke
        case "cancelled":
            // A second finger joined: this was a scroll, not a click.
            if pad.dragging {
                postMouse(.leftMouseUp, at: pad.cursor, clickState: 0)
                pad.dragging = false
            }
            pad.fingerDown = false
            pad.lastEvent = 0
        default:
            break
        }
        return true
    }

    // MARK: - Receiver-side trackpad (local controls)

    private var localLeftDown = false
    private var localRightDown = false
    // Where the receiver last put the cursor: a button right after a move
    // must land there, and a freshly posted move can still read back stale.
    private var lastPointer: (point: CGPoint, time: CFAbsoluteTime)?

    private func pointerPosition() -> CGPoint {
        if let last = lastPointer, CFAbsoluteTimeGetCurrent() - last.time < 1 { return last.point }
        return currentCursor()
    }

    /// A relative move computed by the receiver (acceleration included), in
    /// display points. Crosses onto other displays like a real mouse; drags
    /// while a button the receiver pressed is held.
    func handlePointer(dx: Double, dy: Double) {
        let from = pointerPosition()
        let to = desktopPoint(from: from, to: CGPoint(x: from.x + dx, y: from.y + dy),
                              fallback: CGDisplayBounds(displayID))
        lastPointer = (to, CFAbsoluteTimeGetCurrent())
        let type: CGEventType = localLeftDown ? .leftMouseDragged
            : localRightDown ? .rightMouseDragged : .mouseMoved
        guard let event = CGEvent(mouseEventSource: source, mouseType: type,
                                  mouseCursorPosition: to,
                                  mouseButton: localRightDown ? .right : .left) else { return }
        // Apps that read raw deltas (games, some canvases) get them too.
        event.setIntegerValueField(.mouseEventDeltaX, value: Int64(dx.rounded()))
        event.setIntegerValueField(.mouseEventDeltaY, value: Int64(dy.rounded()))
        event.post(tap: .cghidEventTap)
    }

    /// A button press or release at the cursor, or at normalized (nx, ny) on
    /// the streamed display when given (touch mode's armed right click).
    func handleButton(right: Bool, down: Bool, clicks: Int, nx: Double? = nil, ny: Double? = nil) {
        if let nx, let ny {
            lastPointer = (screenPoint(nx: nx, ny: ny), CFAbsoluteTimeGetCurrent())
        }
        let type: CGEventType
        switch (right, down) {
        case (false, true): type = .leftMouseDown; localLeftDown = true
        case (false, false): guard localLeftDown else { return }; type = .leftMouseUp; localLeftDown = false
        case (true, true): type = .rightMouseDown; localRightDown = true
        case (true, false): guard localRightDown else { return }; type = .rightMouseUp; localRightDown = false
        }
        postMouse(type, at: pointerPosition(), clickState: max(1, min(clicks, 3)),
                  button: right ? .right : .left)
    }

    private func postMouse(_ type: CGEventType, at point: CGPoint, clickState: Int,
                           button: CGMouseButton = .left) {
        guard let event = CGEvent(mouseEventSource: source, mouseType: type,
                                  mouseCursorPosition: point, mouseButton: button) else { return }
        if clickState > 0 {
            event.setIntegerValueField(.mouseEventClickState, value: Int64(clickState))
        }
        event.post(tap: .cghidEventTap)
    }

    /// dx/dy in display pixels, natural-scrolling sign from the phone.
    /// Scroll events take points, so convert via the display's pixel scale.
    func handleScroll(dx: Double, dy: Double) {
        let bounds = CGDisplayBounds(displayID)
        let scale = bounds.width > 0 ? Double(CGDisplayPixelsWide(displayID)) / bounds.width : 2
        guard let event = CGEvent(scrollWheelEvent2Source: source, units: .pixel,
                                  wheelCount: 2,
                                  wheel1: Int32((dy / scale).rounded()),
                                  wheel2: Int32((dx / scale).rounded()),
                                  wheel3: 0) else { return }
        event.post(tap: .cghidEventTap)
    }

    /// Pinch-to-zoom: real magnify gesture events (what a trackpad pinch
    /// produces; works in any app that supports pinch-zoom). They use private
    /// CGEvent fields and are unverified on hardware; if the event cannot be
    /// built the pinch is ignored.
    private static let magnifyEventType = CGEventType(rawValue: 29)   // NSEventTypeMagnify
    private var magnifyActive = false
    private var lastMagnifyTime: CFAbsoluteTime = 0

    /// delta: fractional magnification step (0.1 = +10%), 0 = gesture ended.
    func handleMagnify(delta: Double) {
        let now = CFAbsoluteTimeGetCurrent()
        if delta == 0 {
            if magnifyActive { postMagnifyGesture(phase: 4, delta: 0) }
            magnifyActive = false
            return
        }
        guard delta.isFinite else { return }
        // A lost "ended" must not leave the gesture open forever.
        if magnifyActive, now - lastMagnifyTime > 0.5 {
            postMagnifyGesture(phase: 4, delta: 0)
            magnifyActive = false
        }
        let phase: Int64 = magnifyActive ? 2 : 1   // NSEventPhase changed / began
        if postMagnifyGesture(phase: phase, delta: delta) {
            magnifyActive = true
            lastMagnifyTime = now
        }
    }

    /// Private gesture event: type 29, subtype field 110 (8 = zoom), phase
    /// field 132, magnification field 113. Returns false if it could not be built.
    @discardableResult
    private func postMagnifyGesture(phase: Int64, delta: Double) -> Bool {
        guard let type = Self.magnifyEventType,
              let event = CGEvent(source: source),
              let subtypeField = CGEventField(rawValue: 110),
              let phaseField = CGEventField(rawValue: 132),
              let magnifyField = CGEventField(rawValue: 113) else { return false }
        event.type = type
        event.setIntegerValueField(subtypeField, value: 8)
        event.setIntegerValueField(phaseField, value: phase)
        event.setDoubleValueField(magnifyField, value: delta)
        // Gestures go to the window under the cursor, like scroll.
        event.location = CGEvent(source: nil)?.location ?? .zero
        event.post(tap: .cghidEventTap)
        return true
    }

    func handleProximity(entering: Bool, x: Double, y: Double) {
        setProximity(entering: entering, at: screenPoint(nx: x, ny: y))
    }

    func handlePencil(phase: String, x: Double, y: Double,
                      pressure: Double, azimuth: Double, altitude: Double,
                      rotation: Double) {
        // TODO: Wire Apple Pencil Pro barrel roll (UIKit rollAngle) once hardware
        // is available for testing. rotation on the wire is always 0 for now.
        _ = rotation
        let p = screenPoint(nx: x, ny: y)
        if phase == "down", !inRange {
            setProximity(entering: true, at: p)
        }
        let (tiltX, tiltY) = deriveTilt(azimuth: azimuth, altitude: altitude)

        switch phase {
        case "down":
            postTabletPoint(phase: .down, x: x, y: y, pressure: pressure,
                            tiltX: tiltX, tiltY: tiltY, rotation: 0)
            penDown = true
        case "move":
            if penDown {
                postTabletPoint(phase: .drag, x: x, y: y, pressure: pressure,
                                tiltX: tiltX, tiltY: tiltY, rotation: 0)
            } else {
                postTabletPoint(phase: .hover, x: x, y: y, pressure: 0,
                                tiltX: tiltX, tiltY: tiltY, rotation: 0)
            }
        case "up":
            if penDown {
                postTabletPoint(phase: .up, x: x, y: y, pressure: 0,
                                tiltX: tiltX, tiltY: tiltY, rotation: 0)
                penDown = false
            }
        case "hover":
            if penDown {
                postTabletPoint(phase: .up, x: x, y: y, pressure: 0,
                                tiltX: tiltX, tiltY: tiltY, rotation: 0)
                penDown = false
            }
            postTabletPoint(phase: .hover, x: x, y: y, pressure: 0,
                            tiltX: tiltX, tiltY: tiltY, rotation: 0)
        default:
            return
        }
    }

    private func setProximity(entering: Bool, at p: CGPoint) {
        guard entering != inRange else { return }
        inRange = entering
        postProximityEvent(entering: entering, at: p)
    }

    private func postProximityEvent(entering: Bool, at p: CGPoint) {
        guard let ev = CGEvent(source: source) else { return }
        ev.type = .tabletProximity
        ev.location = p
        ev.setIntegerValueField(.tabletProximityEventVendorID, value: tabletVendorID)
        ev.setIntegerValueField(.tabletProximityEventTabletID, value: tabletProductID)
        ev.setIntegerValueField(.tabletProximityEventPointerID, value: pointerID)
        ev.setIntegerValueField(.tabletProximityEventDeviceID, value: deviceID)
        ev.setIntegerValueField(.tabletProximityEventSystemTabletID, value: 0)
        ev.setIntegerValueField(.tabletProximityEventPointerType, value: entering ? 1 : 0)
        ev.setIntegerValueField(.tabletProximityEventVendorPointerType, value: vendorPointerType)
        ev.setIntegerValueField(.tabletProximityEventCapabilityMask, value: capabilityMask)
        ev.setIntegerValueField(.tabletProximityEventEnterProximity, value: entering ? 1 : 0)
        ev.flags = .maskNonCoalesced
        ev.post(tap: .cghidEventTap)
    }

    private enum PointPhase { case down, drag, up, hover }

    private func postTabletPoint(phase: PointPhase, x: Double?, y: Double?,
                                 pressure: Double, tiltX: Double, tiltY: Double,
                                 rotation: Double) {
        let p: CGPoint
        if let nx = x, let ny = y { p = screenPoint(nx: nx, ny: ny) }
        else { p = currentCursor() }

        let type: CGEventType
        switch phase {
        case .down:  type = .leftMouseDown
        case .drag:  type = .leftMouseDragged
        case .up:    type = .leftMouseUp
        case .hover: type = .mouseMoved
        }

        guard let ev = CGEvent(mouseEventSource: source, mouseType: type,
                               mouseCursorPosition: p, mouseButton: .left) else { return }
        ev.setIntegerValueField(.mouseEventDeltaX, value: 0)
        ev.setIntegerValueField(.mouseEventDeltaY, value: 0)
        ev.setIntegerValueField(.mouseEventSubtype, value: Int64(CGEventMouseSubtype.tabletPoint.rawValue))
        ev.setIntegerValueField(.tabletEventDeviceID, value: deviceID)
        ev.setDoubleValueField(.mouseEventPressure, value: pressure)
        ev.setIntegerValueField(.tabletEventPointPressure, value: Int64((pressure * 65535.0).rounded()))
        ev.setDoubleValueField(.tabletEventTiltX, value: tiltX)
        ev.setDoubleValueField(.tabletEventTiltY, value: tiltY)
        ev.setDoubleValueField(.tabletEventRotation, value: rotation)
        switch phase {
        case .down:
            ev.setIntegerValueField(.mouseEventClickState, value: Int64(beginPenClickSession(at: p)))
        case .up:
            ev.setIntegerValueField(.mouseEventClickState, value: Int64(finishPenClickSession(at: p)))
        case .drag, .hover:
            break
        }
        ev.flags = .maskNonCoalesced
        ev.post(tap: .cghidEventTap)
    }

    private func penClickStateForMouseDown(at point: CGPoint) -> Int {
        let now = CFAbsoluteTimeGetCurrent()
        guard let last = penLastClick,
              now - last.upTime <= SystemClickMetrics.interval else {
            return 1
        }
        let dx = point.x - last.downLocation.x
        let dy = point.y - last.downLocation.y
        guard hypot(dx, dy) <= SystemClickMetrics.distance else { return 1 }
        return last.clickState + 1
    }

    private func beginPenClickSession(at point: CGPoint) -> Int {
        let state = penClickStateForMouseDown(at: point)
        penClickSession = PenClickSession(downLocation: point, clickState: state)
        return state
    }

    /// Returns click state for the matching pen mouse-up. Extends the multi-click
    /// chain only when down→up displacement is within the system threshold.
    private func finishPenClickSession(at upLocation: CGPoint) -> Int {
        guard let session = penClickSession else { return 1 }
        penClickSession = nil

        let dx = upLocation.x - session.downLocation.x
        let dy = upLocation.y - session.downLocation.y
        if hypot(dx, dy) <= SystemClickMetrics.distance {
            penLastClick = PenCompletedClick(
                upTime: CFAbsoluteTimeGetCurrent(),
                downLocation: session.downLocation,
                clickState: session.clickState
            )
        } else {
            penLastClick = nil
        }
        return session.clickState
    }

    /// UIKit altitude is radians from the surface (pi/2 = upright); CGEvent tilt
    /// is a unit vector in -1...1, so normalize rather than pass radians through
    /// (unnormalized, a flat pen reads 1.57 and apps that scale tilt by 90 report
    /// impossible angles).
    private func deriveTilt(azimuth: Double, altitude: Double) -> (Double, Double) {
        let mag = min(max(0, Double.pi / 2 - altitude) / (Double.pi / 2), 1)
        return (sin(azimuth) * mag, cos(azimuth) * mag)
    }

    private func screenPoint(nx: Double, ny: Double) -> CGPoint {
        let bounds = CGDisplayBounds(displayID)
        return CGPoint(x: bounds.minX + nx * bounds.width,
                       y: bounds.minY + ny * bounds.height)
    }

    private func currentCursor() -> CGPoint {
        CGEvent(source: source)?.location ?? .zero
    }

    /// Moves the trackpad cursor across the whole desktop, like a real mouse:
    /// it may leave the streamed display for any other active one and only
    /// stops at the desktop's outer edges.
    private func desktopPoint(from old: CGPoint, to target: CGPoint, fallback: CGRect) -> CGPoint {
        var count: UInt32 = 0
        CGGetActiveDisplayList(0, nil, &count)
        var ids = [CGDirectDisplayID](repeating: 0, count: Int(count))
        CGGetActiveDisplayList(count, &ids, &count)
        let screens = ids.prefix(Int(count)).map { CGDisplayBounds($0) }
        if screens.contains(where: { $0.contains(target) }) { return target }
        // Off every screen: slide along the edge on the screen the cursor is on.
        let home = screens.first(where: { $0.contains(old) }) ?? fallback
        return CGPoint(x: min(max(target.x, home.minX), home.maxX - 1),
                       y: min(max(target.y, home.minY), home.maxY - 1))
    }
}
