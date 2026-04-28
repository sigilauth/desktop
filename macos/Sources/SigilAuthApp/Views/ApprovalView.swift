import SwiftUI
import SigilAuth
import LocalAuthentication

struct ApprovalView: View {
    // Example challenge data (would come from AppState in production)
    private let serverName = "Acme Corp Admin"
    private let actionDescription = "Add WebAuthn key"
    private let keyName = "Sarah's YubiKey"
    @State private var isApproving = false
    @State private var timeRemaining = "3 minutes"
    @State private var timeRemainingSeconds = 180
    @State private var timer: Timer?

    private let biometricContext = LAContext()

    var body: some View {
        VStack(spacing: 24) {
            // Server info with pictogram
            VStack(spacing: 12) {
                HStack {
                    Image(systemName: "server.rack")
                        .font(.title2)
                    Text(serverName)
                        .font(.headline)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Server: \(serverName)")

                // Pictogram display
                PictogramView(pictogram: Pictogram.derive(from: generateTestFingerprint()))
            }

            Divider()

            // Action details
            VStack(alignment: .leading, spacing: 12) {
                Label(actionDescription, systemImage: "key.fill")
                    .font(.title3)
                    .accessibilityAddTraits(.isHeader)

                HStack {
                    Text("Key name:")
                        .fontWeight(.medium)
                    Text(keyName)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Key name: \(keyName)")

                HStack {
                    Text("Requested:")
                        .fontWeight(.medium)
                    Text("2 minutes ago")
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Requested: 2 minutes ago")

                HStack {
                    Text("Expires:")
                        .fontWeight(.medium)
                    Text(timeRemaining)
                        .foregroundColor(.orange)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Expires in \(timeRemaining)")
                .accessibilityValue(timeRemaining)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(Color(hex: "141420"))
            .cornerRadius(10)
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .stroke(Color(hex: "252536"), lineWidth: 1)
            )

            Spacer()

            // Action buttons
            HStack(spacing: 12) {
                Button(action: {}) {
                    Text("Deny")
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
                .keyboardShortcut(.escape)
                .accessibilityLabel("Deny this request")
                .accessibilityHint("Press Escape to deny")

                Button(action: handleApprove) {
                    if isApproving {
                        HStack {
                            ProgressView()
                                .controlSize(.small)
                            Text("Approving...")
                        }
                    } else {
                        Text("Approve")
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(isApproving)
                .keyboardShortcut(.return)
                .accessibilityLabel("Approve with \(biometricType)")
                .accessibilityHint("Press Return to approve")
            }
        }
        .padding(24)
        .frame(width: 450, height: 400)
        .accessibilityRotor("Servers") {
            AccessibilityRotorEntry("Server information", id: "server")
        }
        .accessibilityRotor("Actions") {
            AccessibilityRotorEntry("Action details", id: "action")
        }
        .accessibilityRotor("Approvals") {
            AccessibilityRotorEntry("Approve or deny buttons", id: "approvals")
        }
        .onAppear {
            startTimeRemainingTimer()
        }
        .onDisappear {
            timer?.invalidate()
            timer = nil
        }
    }

    private var biometricType: String {
        var error: NSError?
        guard biometricContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return "biometrics"
        }
        return biometricContext.biometryType == .faceID ? "Face ID" : "Touch ID"
    }

    private var biometricIcon: String {
        var error: NSError?
        guard biometricContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return "faceid"
        }
        return biometricContext.biometryType == .faceID ? "faceid" : "touchid"
    }

    private func generateTestFingerprint() -> Data {
        Data([0xa1, 0xb2, 0xc3, 0xd4] + Array(repeating: 0, count: 28))
    }

    private func startTimeRemainingTimer() {
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { _ in
            // Timer is stored and invalidated in onDisappear - no retain cycle with struct
            self.updateTimeRemaining()
        }
    }

    private func updateTimeRemaining() {
        guard timeRemainingSeconds > 0 else { return }
        timeRemainingSeconds -= 60

        if timeRemainingSeconds >= 60 {
            let minutes = timeRemainingSeconds / 60
            timeRemaining = "\(minutes) minute\(minutes == 1 ? "" : "s")"
        } else if timeRemainingSeconds > 0 {
            timeRemaining = "\(timeRemainingSeconds) seconds"
        } else {
            timeRemaining = "expired"
        }

        // Announce time update to VoiceOver
        if let window = NSApp.keyWindow {
            NSAccessibility.post(
                element: window,
                notification: .announcementRequested,
                userInfo: [
                    .announcement: "Time remaining: \(timeRemaining)",
                    .priority: NSAccessibilityPriorityLevel.medium.rawValue
                ]
            )
        }
    }

    private func handleApprove() {
        isApproving = true

        Task {
            // Trigger Touch ID and sign
            do {
                // let key = try SecureEnclaveKey.generate()
                // let signature = try await key.sign(message)
                // Send to server
                try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second (macOS 12 compatible)
                isApproving = false
            } catch {
                isApproving = false
            }
        }
    }
}

#Preview {
    ApprovalView()
}
