import SwiftUI
import SigilAuth

struct ServerListView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        VStack {
            if appState.servers.isEmpty {
                EmptyStateView()
            } else {
                List(appState.servers) { server in
                    ServerRowView(server: server)
                }
                .toolbar {
                    ToolbarItem(placement: .primaryAction) {
                        Button(action: { appState.showPairing = true }) {
                            Label("Add Server", systemImage: "plus")
                        }
                        .accessibilityLabel("Add new server")
                        .help("Add a new Sigil Auth server")
                    }
                }
            }
        }
        .navigationTitle("Servers")
    }
}

struct ServerRowView: View {
    let server: ServerConfig

    // Emoji map should match PictogramView's emoji list
    private static let emojiMap: [String: String] = [
        "apple": "🍎", "banana": "🍌", "grapes": "🍇", "orange": "🍊",
        "lemon": "🍋", "cherry": "🍒", "strawberry": "🍓", "kiwi": "🥝",
        "carrot": "🥕", "corn": "🌽", "broccoli": "🥦", "mushroom": "🍄",
        "pepper": "🌶️", "avocado": "🥑", "onion": "🧅", "peanut": "🥜",
        "pizza": "🍕", "burger": "🍔", "taco": "🌮", "donut": "🍩",
        "cookie": "🍪", "cake": "🎂", "cupcake": "🧁", "popcorn": "🍿",
        "car": "🚗", "taxi": "🚕", "bus": "🚌", "rocket": "🚀",
        "airplane": "✈️", "helicopter": "🚁", "sailboat": "⛵", "bicycle": "🚲",
        "dog": "🐕", "cat": "🐈", "fish": "🐟", "butterfly": "🦋",
        "bee": "🐝", "fox": "🦊", "lion": "🦁", "elephant": "🐘",
        "tree": "🌲", "sunflower": "🌻", "cactus": "🌵", "clover": "🍀",
        "flower": "🌸", "rainbow": "🌈", "star": "⭐", "moon": "🌙",
        "house": "🏠", "mountain": "🏔️", "peak": "⛰️", "volcano": "🌋",
        "island": "🏝️", "moai": "🗿", "tent": "⛺", "castle": "🏰",
        "key": "🔑", "bell": "🔔", "books": "📚", "guitar": "🎸",
        "anchor": "⚓", "crown": "👑", "gem": "💎", "fire": "🔥"
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(server.name)
                .font(.headline)
                .accessibilityAddTraits(.isHeader)

            HStack(spacing: 4) {
                ForEach(server.pictogram.names, id: \.self) { name in
                    Text(emojiForName(name))
                        .font(.title3)
                }
            }
            .accessibilityHidden(true)

            Text(server.pictogram.speakable)
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(Color(hex: "9ca0b0"))
                .accessibilityLabel("Pictogram: \(server.pictogram.speakable)")
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Server \(server.name), pictogram \(server.pictogram.speakable)")
    }

    private func emojiForName(_ name: String) -> String {
        return Self.emojiMap[name.lowercased()] ?? "⭐"
    }
}

struct EmptyStateView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        VStack(spacing: 20) {
            Text("🔑")
                .font(.system(size: 64))
                .opacity(0.3)
                .accessibilityHidden(true)

            Text("No Servers Paired")
                .font(.system(size: 20, weight: .semibold))
                .accessibilityAddTraits(.isHeader)

            Text("Pair your first server to start approving authentication requests. You can pair via QR code, deep link, or manual 8-digit code.")
                .foregroundColor(Color(hex: "9ca0b0"))
                .multilineTextAlignment(.center)
                .frame(maxWidth: 340)

            Button("Pair Your First Server") {
                appState.showPairing = true
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .accessibilityLabel("Pair your first server")
            .accessibilityHint("Double tap to begin pairing a new server")
        }
        .padding()
        .accessibilityElement(children: .contain)
    }
}

#Preview {
    ServerListView()
        .environmentObject(AppState())
}
