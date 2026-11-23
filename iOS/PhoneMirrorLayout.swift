import SwiftUI
import UIKit

// MARK: - iPhone mirror layout (custom build)
//
// An iPhone is too small to show a mirrored Mac screen at a usable size, and
// pointing on it from the picture itself is fiddly. So while mirroring, the
// iPhone becomes a remote control: everything between the controls and the
// keys row / keyboard is ONE trackpad, with the Mac screen drawn small inside
// it. The picture takes no touch: every finger, on the picture or beside it,
// drives the pointer. Extend mode, and the iPad, keep the picture layout.
//
//   portrait:  bar on top; trackpad; keys row (inverted T); keyboard
//   landscape: icon column on the left; trackpad and a one-line keys row on
//              the right; keyboard along the bottom (height is scarce)
//
// Every piece is placed by hand from the screen size in ONE view tree, so a
// rotation only moves them: the video view (which owns the keyboard's first
// responder) is never rebuilt, and the keyboard stays up.

struct PhoneMirrorLayout: View {
    @ObservedObject var receiver: StreamReceiver
    let useMetal: Bool
    @ObservedObject private var controls = LocalControls.shared
    /// Window safe-area insets (the screen itself ignores the safe area).
    @State private var insets = UIEdgeInsets.zero
    /// The pointer mode to put back when leaving the layout.
    @State private var savedMode: LocalPointerMode?

    private let barHeight = LocalControls.barHeight
    private let columnWidth: CGFloat = 44
    /// Keys row heights: two lines (inverted T) in portrait, one in landscape.
    private let keysRowPortrait: CGFloat = 2 * 38 + 3 * 4
    private let keysRowLandscape: CGFloat = 38 + 2 * 4

    private var videoAspect: CGFloat {
        let size = receiver.videoSize
        return size.width > 0 && size.height > 0 ? size.width / size.height : 16.0 / 10.0
    }

    var body: some View {
        GeometryReader { geo in
            let w = geo.size.width, h = geo.size.height
            let landscape = w > h
            // Room the keyboard takes at the bottom (home indicator included
            // when none: the screen ignores the safe area, and so the keyboard's).
            let bottom = controls.dockedKeyboardHeight > 0 ? controls.dockedKeyboardHeight : insets.bottom
            let keysH: CGFloat = !controls.keyboardVisible ? 0
                : (landscape ? keysRowLandscape : keysRowPortrait)
            // Left/right keep clear of the notch in landscape.
            let left = max(8, insets.left), right = max(8, insets.right)
            let top = landscape ? 6 : insets.top

            // The rectangles of the three pieces, per orientation. The pieces
            // themselves are the same views in both (only their frames
            // change), so a rotation never rebuilds them.
            let r = rects(w: w, h: h, landscape: landscape, bottom: bottom, keysH: keysH,
                          left: left, right: right, top: top)
            let controlsRect = r.controls, padRect = r.pad, keysRect = r.keys

            ZStack(alignment: .topLeading) {
                TrackpadSurface(receiver: receiver) {
                    picture(margin: landscape ? 6 : 12)
                }
                .frame(width: padRect.width, height: padRect.height)
                .position(x: padRect.midX, y: padRect.midY)
                LocalControlBar(receiver: receiver, compact: true, showsPointerMode: false,
                                vertical: landscape)
                    .frame(width: controlsRect.width, height: controlsRect.height, alignment: .top)
                    .position(x: controlsRect.midX, y: controlsRect.midY)
                MacKeysRow(layout: landscape ? .phoneWide : .phone)
                    .frame(width: keysRect.width, height: keysRect.height)
                    .position(x: keysRect.midX, y: keysRect.midY)
            }
            .frame(width: w, height: h, alignment: .topLeading)
            .animation(.easeOut(duration: 0.25), value: controls.dockedKeyboardHeight)
            .animation(.easeOut(duration: 0.25), value: controls.keyboardVisible)
        }
        .background(Color.black)
        .background(SafeAreaInsetsReader { insets = $0 })
        .onAppear {
            // A phone trackpad only makes sense as a mouse: force it, and put
            // the user's choice back on the way out.
            savedMode = controls.mode
            controls.setTransientMode(.trackpad)   // not persisted: a kill here must not stick
            controls.rightClickArmed = false
            // A keyboard raised in the other layout belongs to a view that is
            // gone; start from a clean state. Nothing here slides the picture.
            controls.keyboardVisible = false
            controls.followKeyboard = false
        }
        .onDisappear {
            controls.followKeyboard = true
            if let saved = savedMode { controls.setTransientMode(saved) }
            savedMode = nil
        }
    }

    private func rects(w: CGFloat, h: CGFloat, landscape: Bool, bottom: CGFloat, keysH: CGFloat,
                       left: CGFloat, right: CGFloat, top: CGFloat)
        -> (controls: CGRect, pad: CGRect, keys: CGRect) {
        if landscape {
            let x = left + columnWidth + 8
            let rightW = max(0, w - x - right)
            return (CGRect(x: left, y: top, width: columnWidth, height: max(0, h - bottom - top)),
                    CGRect(x: x, y: top, width: rightW, height: max(0, h - bottom - keysH - top - 4)),
                    CGRect(x: x, y: h - bottom - keysH, width: rightW, height: keysH))
        }
        let zoneTop = top + barHeight + 8
        return (CGRect(x: 0, y: top, width: w, height: barHeight),
                CGRect(x: 10, y: zoneTop, width: max(0, w - 20),
                       height: max(0, h - bottom - keysH - zoneTop - 8)),
                CGRect(x: 0, y: h - bottom - keysH, width: w, height: keysH))
    }

    /// The Mac screen, small, at the top of the trackpad and untouchable. It
    /// still owns the keyboard's first responder (MacKeyInputView lives inside
    /// VideoView) and shows the cursor echo, so it must stay in the tree.
    private func picture(margin: CGFloat) -> some View {
        VideoLayerView(displayLayer: receiver.displayLayer,
                       receiver: receiver,
                       useMetal: useMetal)
            .id(useMetal)
            .aspectRatio(videoAspect, contentMode: .fit)
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.white.opacity(0.15), lineWidth: 1))
            .allowsHitTesting(false)
            .padding(margin)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }
}

// MARK: - Trackpad surface

/// The trackpad of the iPhone mirror layout: the same gestures as trackpad
/// mode on the picture (move, tap, two-finger scroll and right-click, pinch,
/// three-finger drag), fed by its own `TrackpadEngine`. `content` is drawn on
/// the pad but under the touch layer, so it never receives a touch.
struct TrackpadSurface<Content: View>: View {
    let receiver: StreamReceiver
    @ViewBuilder let content: () -> Content

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(Color(white: 0.13))
            content()
            TrackpadTouchSurface(receiver: receiver)
        }
        .overlay(
            Text("Trackpad")
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(.white.opacity(0.22))
                .padding(10)
                .allowsHitTesting(false),
            alignment: .bottomTrailing)
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}

private struct TrackpadTouchSurface: UIViewRepresentable {
    let receiver: StreamReceiver

    func makeUIView(context: Context) -> TrackpadTouchView {
        let view = TrackpadTouchView()
        view.backgroundColor = .clear
        view.isMultipleTouchEnabled = true
        let controls = LocalControls.shared
        view.engine.receiver = receiver
        controls.receiver = receiver
        // Modifiers armed in the keys row ride on clicks.
        receiver.clickMods = { controls.takeMods() }
        // Scroll deltas travel in video pixels; the thumbnail is not what the
        // fingers act on, so use a fixed, comfortable ratio.
        view.engine.pointsPerVideoPixel = { 0.5 }
        return view
    }

    func updateUIView(_ uiView: TrackpadTouchView, context: Context) {
        uiView.engine.receiver = receiver
    }

    static func dismantleUIView(_ uiView: TrackpadTouchView, coordinator: ()) {
        uiView.engine.reset()
    }
}

private final class TrackpadTouchView: UIView {
    let engine = TrackpadEngine()

    private func fingers(_ touches: Set<UITouch>) -> Set<UITouch> {
        touches.filter { $0.type != .pencil }
    }

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent?) {
        let f = fingers(touches)
        if !f.isEmpty { engine.began(f, all: event?.allTouches ?? f) }
    }

    override func touchesMoved(_ touches: Set<UITouch>, with event: UIEvent?) {
        let f = fingers(touches)
        if !f.isEmpty { engine.moved(f, event: event) }
    }

    override func touchesEnded(_ touches: Set<UITouch>, with event: UIEvent?) {
        let f = fingers(touches)
        if !f.isEmpty { engine.ended(f, cancelled: false) }
    }

    override func touchesCancelled(_ touches: Set<UITouch>, with event: UIEvent?) {
        let f = fingers(touches)
        if !f.isEmpty { engine.ended(f, cancelled: true) }
    }
}
