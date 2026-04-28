import SwiftUI

// MARK: - Color Extension

extension Color {
    /// Initialize Color from hex string (supports 3, 6, or 8 digit hex)
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
        case 3: // RGB (12-bit)
            (a, r, g, b) = (255, (int >> 8) * 17, (int >> 4 & 0xF) * 17, (int & 0xF) * 17)
        case 6: // RGB (24-bit)
            (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        case 8: // ARGB (32-bit)
            (a, r, g, b) = (int >> 24, int >> 16 & 0xFF, int >> 8 & 0xFF, int & 0xFF)
        default:
            (a, r, g, b) = (255, 0, 0, 0)
        }
        self.init(
            .sRGB,
            red: Double(r) / 255,
            green: Double(g) / 255,
            blue: Double(b) / 255,
            opacity: Double(a) / 255
        )
    }
}

// MARK: - Design System Colors (from wireframes)

extension Color {
    static let sigilBg = Color(hex: "07070c")
    static let sigilBgRaised = Color(hex: "0e0e16")
    static let sigilSurface = Color(hex: "141420")
    static let sigilBorder = Color(hex: "252536")
    static let sigilText = Color(hex: "f5f5f7")
    static let sigilTextMuted = Color(hex: "9ca0b0")
    static let sigilTextDim = Color(hex: "636879")
    static let sigilPrimary = Color(hex: "4d88ff")
    static let sigilAccent = Color(hex: "3dfce8")
    static let sigilSuccess = Color(hex: "00e676")
    static let sigilDanger = Color(hex: "ff5a5a")
}

// MARK: - Spacing Constants

enum Spacing {
    static let s2: CGFloat = 8
    static let s3: CGFloat = 12
    static let s4: CGFloat = 16
    static let s6: CGFloat = 24
    static let s8: CGFloat = 32
}

// MARK: - Border Radius

enum BorderRadius {
    static let md: CGFloat = 10
    static let lg: CGFloat = 14
}
