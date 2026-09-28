import SwiftUI

/// The receiver's pairing screen: opens the pairing listener while shown,
/// displays the code for the Mac, then asks to accept the Mac.
struct PairingResponderView: View {
    @ObservedObject var responder: PairingResponder
    let serviceName: String

    var body: some View {
        VStack(spacing: 18) {
            switch responder.state {
            case .idle, .waiting:
                ProgressView()
                Text("Sur le Mac, ouvre OpenDisplay › Sécurité › Appairer un appareil, puis choisis « \(serviceName) ».")
                    .multilineTextAlignment(.center)
            case .showCode(let code, let mac):
                Text("Tape ce code sur « \(mac) »")
                Text(code.prefix(3) + " " + code.suffix(3))
                    .font(.system(size: 48, weight: .bold, design: .monospaced))
            case .confirm(let mac):
                Text("« \(mac) » a saisi le bon code.")
                Text("Autoriser ce Mac à se connecter en WiFi chiffré ?")
                    .multilineTextAlignment(.center)
                HStack(spacing: 16) {
                    Button("Refuser", role: .cancel) { responder.reject() }
                    Button("Appairer") { responder.accept() }
                        .buttonStyle(.borderedProminent)
                }
            case .paired(let mac):
                Label("« \(mac) » est appairé.", systemImage: "lock.fill")
                    .foregroundColor(.green)
            case .failed(let reason):
                Label(reason, systemImage: "exclamationmark.triangle.fill")
                    .foregroundColor(.orange)
                    .multilineTextAlignment(.center)
                Button("Recommencer") { responder.start(serviceName: serviceName) }
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity)
        .onAppear { responder.start(serviceName: serviceName) }
        .onDisappear { responder.cancel() }
    }
}
