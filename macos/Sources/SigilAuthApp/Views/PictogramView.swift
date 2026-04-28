import SwiftUI
import SigilAuth

/// Pictogram display for macOS per Aria §3 + protocol-spec §3.6
///
/// Canonical accessible implementation matching Windows reference quality.
/// Per Aria review: Windows PictogramView.xaml is exemplary — this matches that pattern.
///
/// Accessibility features:
/// - Single VoiceOver announcement for all five emoji names
/// - Visual emoji row hidden from VoiceOver (prevents duplicate announcements)
/// - Speakable text visible in all color modes
/// - DisclosureGroup with per-emoji descriptions
/// - List semantics with position information
struct PictogramView: View {
    let pictogram: Pictogram

    // Emoji list matches protocol-spec §3.6 - 64 emoji in 8 categories
    private static let emojiList: [String] = [
        "🍎", "🍌", "🍇", "🍊", "🍋", "🍒", "🍓", "🥝",
        "🥕", "🌽", "🥦", "🍄", "🌶️", "🥑", "🧅", "🥜",
        "🍕", "🍔", "🌮", "🍩", "🍪", "🎂", "🧁", "🍿",
        "🚗", "🚕", "🚌", "🚀", "✈️", "🚁", "⛵", "🚲",
        "🐕", "🐈", "🐟", "🦋", "🐝", "🦊", "🦁", "🐘",
        "🌲", "🌻", "🌵", "🍀", "🌸", "🌈", "⭐", "🌙",
        "🏠", "🏔️", "⛰️", "🌋", "🏝️", "🗿", "⛺", "🏰",
        "🔑", "🔔", "📚", "🎸", "⚓", "👑", "💎", "🔥"
    ]

    var body: some View {
        VStack(spacing: 12) {
            // Visual emoji row — hidden from VoiceOver
            HStack(spacing: 12) {
                ForEach(Array(pictogram.indices.enumerated()), id: \.offset) { index, emojiIndex in
                    Text(emojiForIndex(emojiIndex))
                        .font(.system(size: 48))
                }
            }
            .accessibilityHidden(true)

            // Speakable text — always visible, uses design system muted color
            Text(pictogram.speakable)
                .font(.system(.body, design: .monospaced))
                .foregroundColor(Color(hex: "9ca0b0"))
                .accessibilityHidden(true)

            // Per-emoji descriptions — collapsible per Aria §3.2.1
            DisclosureGroup("Emoji descriptions") {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(pictogram.indices.enumerated()), id: \.offset) { index, emojiIndex in
                        HStack {
                            Text("\(index + 1).")
                                .foregroundColor(.secondary)
                            Text(Pictogram.emojiNames[emojiIndex])
                            Text(emojiForIndex(emojiIndex))
                        }
                        .font(.callout)
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel("Position \(index + 1) of 5: \(Pictogram.emojiNames[emojiIndex])")
                    }
                }
                .padding(.top, 4)
            }
            .accessibilityLabel("Per-emoji descriptions")
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibleLabel)
        .accessibilityAddTraits(.isStaticText)
    }

    private var accessibleLabel: String {
        "Device pictogram: \(pictogram.names.joined(separator: ", "))"
    }

    private func emojiForIndex(_ index: Int) -> String {
        guard index >= 0 && index < Self.emojiList.count else {
            return "❓" // Fallback for invalid index
        }
        return Self.emojiList[index]
    }
}

#Preview {
    let testFingerprint = Data([0xa1, 0xb2, 0xc3, 0xd4] + Array(repeating: 0, count: 28))
    let testPictogram = Pictogram.derive(from: testFingerprint)

    return PictogramView(pictogram: testPictogram)
        .padding()
        .frame(width: 400)
}
