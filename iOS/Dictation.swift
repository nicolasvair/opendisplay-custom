import AVFoundation
import Speech
import SwiftUI

// MARK: - Dictation (custom build)

/// Voice dictation: the iPad transcribes, the finished text is typed on the Mac.
/// Partial results are only displayed (never sent), so nothing has to be
/// retracted on the Mac; each finished utterance goes out as one `text` message.
final class DictationController: ObservableObject {
    static let shared = DictationController()

    @Published private(set) var isListening = false
    @Published private(set) var partialText = ""
    @Published private(set) var error: String?

    private let engine = AVAudioEngine()
    private var recognizer: SFSpeechRecognizer?
    private var request: SFSpeechAudioBufferRecognitionRequest?
    private var task: SFSpeechRecognitionTask?
    private var generation = 0          // invalidates callbacks of replaced tasks
    private var committedAny = false    // a space separates utterances of one session
    private var stopping = false

    private var receiver: StreamReceiver? { LocalControls.shared.receiver }

    func toggle() { isListening ? stop() : start() }

    func start() {
        guard !isListening else { return }
        error = nil
        SFSpeechRecognizer.requestAuthorization { [weak self] status in
            DispatchQueue.main.async {
                guard let self else { return }
                guard status == .authorized else { return self.fail("Reconnaissance vocale refusée — Réglages") }
                AVAudioSession.sharedInstance().requestRecordPermission { granted in
                    DispatchQueue.main.async {
                        guard granted else { return self.fail("Microphone refusé — Réglages") }
                        self.begin()
                    }
                }
            }
        }
    }

    private func fail(_ message: String) {
        error = message
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
            if self?.error == message { self?.error = nil }
        }
    }

    private func begin() {
        guard !isListening else { return }
        let id = UserDefaults.standard.string(forKey: "dictationLocale") ?? "fr-FR"
        guard let recognizer = SFSpeechRecognizer(locale: Locale(identifier: id)), recognizer.isAvailable else {
            return fail("Dictée indisponible")
        }
        self.recognizer = recognizer
        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.record, mode: .measurement, options: .duckOthers)
            try session.setActive(true, options: .notifyOthersOnDeactivation)
            let input = engine.inputNode
            let format = input.outputFormat(forBus: 0)
            guard format.sampleRate > 0 else { throw NSError(domain: "Dictation", code: 1) }
            input.installTap(onBus: 0, bufferSize: 1024, format: format) { [weak self] buffer, _ in
                self?.request?.append(buffer)
            }
            engine.prepare()
            try engine.start()
        } catch {
            Log.info("dictation: audio start failed: \(error)")
            engine.inputNode.removeTap(onBus: 0)
            return fail("Micro indisponible")
        }
        committedAny = false
        stopping = false
        isListening = true
        startTask()
    }

    private func startTask() {
        guard let recognizer else { return }
        generation += 1
        let mine = generation
        let req = SFSpeechAudioBufferRecognitionRequest()
        req.shouldReportPartialResults = true
        req.requiresOnDeviceRecognition = recognizer.supportsOnDeviceRecognition
        if #available(iOS 16, *) { req.addsPunctuation = true }
        request = req
        partialText = ""
        task = recognizer.recognitionTask(with: req) { [weak self] result, err in
            DispatchQueue.main.async {
                guard let self, mine == self.generation else { return }
                if let result {
                    self.partialText = result.bestTranscription.formattedString
                    if result.isFinal { self.finished() }
                } else if let err {
                    Log.info("dictation: recognition ended: \(err.localizedDescription)")
                    self.finished()
                }
            }
        }
    }

    /// The current task ended (final result, error, or the ~1 min cap): send
    /// what was heard, then keep listening with a fresh task unless stopping.
    private func finished() {
        commit()
        task = nil
        request = nil
        if isListening && !stopping { startTask() } else { teardown() }
    }

    private func commit() {
        let text = partialText.trimmingCharacters(in: .whitespacesAndNewlines)
        partialText = ""
        guard !text.isEmpty, let receiver else { return }
        receiver.sendText((committedAny ? " " : "") + text, mods: 0)
        committedAny = true
    }

    /// Stops listening. With `commit`, the last words are still typed.
    func stop(commit shouldCommit: Bool = true) {
        guard isListening else { return }
        stopping = true
        if !shouldCommit { partialText = "" }
        engine.stop()
        engine.inputNode.removeTap(onBus: 0)
        request?.endAudio()
        let mine = generation
        // The final result normally follows endAudio(); fall back on the last partial.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
            guard let self, self.isListening, mine == self.generation else { return }
            self.task?.cancel()
            self.finished()
        }
    }

    private func teardown() {
        if engine.isRunning { engine.stop(); engine.inputNode.removeTap(onBus: 0) }
        task?.cancel()
        task = nil
        request = nil
        generation += 1
        isListening = false
        partialText = ""
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }
}

/// A capsule with the live transcription (not yet on the Mac) or the reason
/// dictation could not start. Never intercepts touches.
struct DictationOverlay: View {
    @ObservedObject var dictation = DictationController.shared

    var body: some View {
        let message: String? = dictation.error ?? (dictation.isListening
            ? (dictation.partialText.isEmpty ? "Parlez…" : dictation.partialText) : nil)
        Group {
            if let message {
                HStack(spacing: 8) {
                    Image(systemName: dictation.error != nil ? "mic.slash.fill" : "mic.fill")
                    Text(message).lineLimit(2).truncationMode(.head)
                }
                .font(.system(size: 18, weight: .medium))
                .foregroundColor(.white)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .background(Capsule().fill(dictation.error != nil
                                           ? Color.red.opacity(0.85) : Color.black.opacity(0.85)))
                .frame(maxWidth: 560)
                .padding(.top, 24)
            }
        }
        .allowsHitTesting(false)
    }
}
