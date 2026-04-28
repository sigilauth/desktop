import SwiftUI
import SigilAuth

struct SessionPictogramView: View {
    let pictogram: SessionPictogram
    let expiresAt: Date
    let onConfirm: () -> Void
    let onDeny: () -> Void

    @State private var timeRemaining: TimeInterval = 10

    var body: some View {
        VStack(spacing: 24) {
            Text(L10n.string("pair-flow-title"))
                .font(.title2)
                .fontWeight(.semibold)

            Text(L10n.string("pair-flow-subtitle"))
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)

            VStack(spacing: 16) {
                HStack(spacing: 20) {
                    ForEach(0..<3, id: \.self) { index in
                        VStack(spacing: 4) {
                            Text(pictogram.emojis[index])
                                .font(.system(size: 48))
                            Text(pictogram.names[index])
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel(L10n.voiceOverPictogram(position: index + 1, emoji: pictogram.emojis[index], word: pictogram.names[index]))
                    }
                }

                HStack(spacing: 20) {
                    ForEach(3..<6, id: \.self) { index in
                        VStack(spacing: 4) {
                            Text(pictogram.emojis[index])
                                .font(.system(size: 48))
                            Text(pictogram.names[index])
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel(L10n.voiceOverPictogram(position: index + 1, emoji: pictogram.emojis[index], word: pictogram.names[index]))
                    }
                }
            }
            .padding()
            .background(Color.secondary.opacity(0.1))
            .cornerRadius(12)

            Text(L10n.countdownSeconds(Int(timeRemaining)))
                .font(.caption)
                .foregroundColor(timeRemaining < 3 ? .red : .secondary)
                .onAppear {
                    startTimer()
                }

            HStack(spacing: 16) {
                Button(L10n.string("pair-flow-deny-button")) {
                    onDeny()
                }
                .keyboardShortcut(.cancelAction)
                .controlSize(.large)
                .accessibilityLabel(L10n.string("pair-flow-deny-a11y"))

                Button(L10n.string("pair-flow-confirm-button")) {
                    onConfirm()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .accessibilityLabel(L10n.string("pair-flow-confirm-a11y"))
            }
        }
        .padding(32)
        .frame(width: 480)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(L10n.string("pair-flow-title"))
        .accessibilityHint(L10n.string("pair-flow-subtitle"))
    }

    private func startTimer() {
        timeRemaining = expiresAt.timeIntervalSinceNow
        Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { timer in
            let remaining = expiresAt.timeIntervalSinceNow
            if remaining <= 0 {
                timer.invalidate()
                timeRemaining = 0
                onDeny()
            } else {
                timeRemaining = remaining
            }
        }
    }
}

#Preview {
    SessionPictogramView(
        pictogram: SessionPictogram(
            emojis: ["🍎", "🚀", "🦊", "⚓", "🌙", "🏠"],
            names: ["apple", "rocket", "fox", "anchor", "moon", "house"]
        ),
        expiresAt: Date().addingTimeInterval(10),
        onConfirm: {},
        onDeny: {}
    )
}
