import SwiftUI

struct PairingView: View {
    @State private var pairingCode = ""
    @State private var isVerifying = false

    var body: some View {
        VStack(spacing: 24) {
            Text("Enter Pairing Code")
                .font(.system(size: 24, weight: .semibold))

            Text("8-digit code from the service")
                .font(.system(size: 15))
                .foregroundColor(Color(hex: "9ca0b0"))
                .multilineTextAlignment(.center)

            // 8-digit code entry
            HStack(spacing: 8) {
                ForEach(0..<8) { index in
                    if index == 4 {
                        Text("−")
                            .foregroundColor(Color(hex: "636879"))
                            .font(.system(size: 20))
                    }
                    TextField("", text: binding(for: index))
                        .frame(width: 44, height: 56)
                        .multilineTextAlignment(.center)
                        .font(.system(.title2, design: .monospaced))
                        .textFieldStyle(.roundedBorder)
                        .accessibilityLabel("Digit \(index + 1)")
                }
            }

            HStack(spacing: 12) {
                Button("Cancel") {
                    // Dismiss
                }
                .keyboardShortcut(.escape)
                .buttonStyle(.bordered)

                Button("Verify Code") {
                    // Verify pairing code
                }
                .disabled(pairingCode.count < 8)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(24)
    }

    private func binding(for index: Int) -> Binding<String> {
        Binding(
            get: {
                guard pairingCode.count > index else { return "" }
                return String(pairingCode[pairingCode.index(pairingCode.startIndex, offsetBy: index)])
            },
            set: { newValue in
                // Update digit at index
            }
        )
    }
}

#Preview {
    PairingView()
}
