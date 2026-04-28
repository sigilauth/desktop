import SwiftUI
import SigilAuth

struct PairFlowView: View {
    @State private var viewModel: PairFlowViewModel
    @State private var serverURLInput = ""
    @State private var showQRScanner = false
    @State private var qrScanError: String?

    let deviceKey: SecureEnclaveKey

    init(deviceKey: SecureEnclaveKey) {
        self.deviceKey = deviceKey
        _viewModel = State(initialValue: PairFlowViewModel())
    }

    var body: some View {
        VStack(spacing: 24) {
            switch viewModel.state {
            case .idle:
                idleView
            case .fetchingInit:
                loadingView(message: L10n.string("pair-flow-fetching"))
            case .derivingPictogram:
                loadingView(message: L10n.string("pair-flow-deriving"))
            case .displayingPictogram(let pictogram, let expiresAt):
                SessionPictogramView(
                    pictogram: pictogram,
                    expiresAt: expiresAt,
                    onConfirm: {
                        Task {
                            await viewModel.confirmPairing()
                        }
                    },
                    onDeny: {
                        viewModel.denyPairing()
                    }
                )
            case .submittingComplete:
                loadingView(message: L10n.string("pair-flow-submitting"))
            case .persistingTrust:
                loadingView(message: L10n.string("pair-flow-persisting"))
            case .success(let server):
                successView(server: server)
            case .waitingForApproval:
                waitingForApprovalView
            case .error(let message):
                errorView(message: message)
            case .denied:
                deniedView
            case .timeout:
                timeoutView
            }
        }
        .padding(32)
        .frame(width: 480)
    }

    private var idleView: some View {
        VStack(spacing: 24) {
            Text(L10n.string("pair-flow-idle-title"))
                .font(.title2)
                .fontWeight(.semibold)

            Text(L10n.string("pair-flow-idle-subtitle"))
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)

            TextField(L10n.string("pair-flow-url-placeholder"), text: $serverURLInput)
                .textFieldStyle(.roundedBorder)
                .onSubmit {
                    startPairing()
                }

            // QR Scanner button
            Button(action: { showQRScanner = true }) {
                Label("Scan QR Code", systemImage: "qrcode.viewfinder")
            }
            .buttonStyle(.bordered)
            .controlSize(.large)

            HStack(spacing: 12) {
                Button(L10n.string("pair-flow-cancel-button")) {
                    // Dismiss
                }
                .keyboardShortcut(.escape)
                .controlSize(.large)

                Button(L10n.string("pair-flow-start-button")) {
                    startPairing()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(serverURLInput.isEmpty)
            }

            if let error = qrScanError {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
            }
        }
        .sheet(isPresented: $showQRScanner) {
            QRScannerView(
                scannedCode: Binding(
                    get: { serverURLInput.isEmpty ? nil : serverURLInput },
                    set: { serverURLInput = $0 ?? "" }
                ),
                errorMessage: $qrScanError
            )
            .frame(width: 480, height: 360)
        }
    }

    private func loadingView(message: String) -> some View {
        VStack(spacing: 16) {
            ProgressView()
                .controlSize(.large)
            Text(message)
                .font(.body)
                .foregroundColor(.secondary)
        }
    }

    private func successView(server: TrustedServer) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 64))
                .foregroundColor(.green)

            Text(L10n.string("pair-flow-success-title"))
                .font(.title2)
                .fontWeight(.semibold)

            Text(L10n.string("pair-flow-success-subtitle"))
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)

            Button(L10n.string("pair-flow-done-button")) {
                // Dismiss
            }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
    }

    private var waitingForApprovalView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .controlSize(.large)

            Text(L10n.string("pair-flow-waiting-title"))
                .font(.title2)
                .fontWeight(.semibold)

            Text(L10n.string("pair-flow-waiting-subtitle"))
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)

            Button(L10n.string("pair-flow-cancel-button")) {
                viewModel.reset()
            }
            .controlSize(.large)
        }
    }

    private func errorView(message: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 64))
                .foregroundColor(.red)

            Text(L10n.string("pair-flow-error-title"))
                .font(.title2)
                .fontWeight(.semibold)

            Text(message)
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)

            Button(L10n.string("pair-flow-retry-button")) {
                viewModel.reset()
            }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
    }

    private var deniedView: some View {
        VStack(spacing: 16) {
            Image(systemName: "xmark.circle.fill")
                .font(.system(size: 64))
                .foregroundColor(.orange)

            Text(L10n.string("pair-flow-denied-title"))
                .font(.title2)
                .fontWeight(.semibold)

            Text(L10n.string("pair-flow-denied-subtitle"))
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)

            Button(L10n.string("pair-flow-done-button")) {
                // Dismiss
            }
            .keyboardShortcut(.defaultAction)
            .controlSize(.large)
        }
    }

    private var timeoutView: some View {
        VStack(spacing: 16) {
            Image(systemName: "clock.fill")
                .font(.system(size: 64))
                .foregroundColor(.orange)

            Text(L10n.string("pair-flow-timeout-title"))
                .font(.title2)
                .fontWeight(.semibold)

            Text(L10n.string("pair-flow-timeout-subtitle"))
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)

            Button(L10n.string("pair-flow-retry-button")) {
                viewModel.reset()
            }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
    }

    private func startPairing() {
        guard let url = URL(string: serverURLInput) else {
            return
        }

        Task {
            await viewModel.startPairing(serverURL: url, deviceKey: deviceKey)
        }
    }
}

#Preview {
    PairFlowView(deviceKey: try! SecureEnclaveKey.generate())
}
