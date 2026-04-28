import Foundation

/// Localization helper for pair flow strings
enum L10n {
    /// Get localized string by key
    static func string(_ key: String) -> String {
        NSLocalizedString(key, comment: "")
    }

    /// Countdown timer with plural support - seconds
    static func countdownSeconds(_ seconds: Int) -> String {
        let key = seconds == 1 ? "pair-flow-countdown-seconds-one" : "pair-flow-countdown-seconds-other"
        return String(format: NSLocalizedString(key, comment: ""), seconds)
    }

    /// Countdown timer with plural support - minutes
    static func countdownMinutes(_ minutes: Int) -> String {
        let key = minutes == 1 ? "pair-flow-countdown-minutes-one" : "pair-flow-countdown-minutes-other"
        return String(format: NSLocalizedString(key, comment: ""), minutes)
    }

    /// VoiceOver announcement for pictogram position
    static func voiceOverPictogram(position: Int, emoji: String, word: String) -> String {
        String(format: NSLocalizedString("pair-flow-voiceover-pictogram", comment: ""), position, emoji, word)
    }
}
