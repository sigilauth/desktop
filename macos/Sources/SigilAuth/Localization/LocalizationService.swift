import Foundation
import SwiftUI

/// Fluent-based localization service (macOS)
/// Loads .ftl files from Resources/Localization and provides localized strings
/// Per AC #10: FluentSwift integration with shared i18n catalog
final class LocalizationService {

    static let shared = LocalizationService()

    private var bundles: [String: FluentBundle] = [:]
    private var currentLocale: String = "en"

    private init() {
        loadBundles()
    }

    /// Get localized string for key
    /// Format: "file.key" e.g., "auth.biometric-prompt-approve"
    func string(for key: String, args: [String: FluentValue] = [:]) -> String {
        let parts = key.split(separator: ".")
        guard parts.count == 2 else {
            return key  // Return key if invalid format
        }

        let file = String(parts[0])
        let messageKey = String(parts[1])

        guard let bundle = bundles[file] else {
            return key  // Bundle not found
        }

        guard let message = bundle.getMessage(messageKey) else {
            return key  // Message not found
        }

        var errors: [FluentError] = []
        let formatted = bundle.format(message, args: args, errors: &errors)

        return formatted
    }

    /// Change current locale
    func setLocale(_ locale: String) {
        currentLocale = locale
        loadBundles()
    }

    // MARK: - Bundle Loading

    private func loadBundles() {
        bundles.removeAll()

        let fileNames = ["auth", "challenge", "mpa", "errors", "common", "devices", "pictogram"]

        // Find Resources directory relative to executable
        guard let resourcesURL = Bundle.main.resourceURL else {
            print("Failed to find app resources")
            return
        }

        let localeDir = resourcesURL
            .appendingPathComponent("Localization")
            .appendingPathComponent(currentLocale)

        for fileName in fileNames {
            let fileURL = localeDir.appendingPathComponent("\(fileName).ftl")

            guard let ftlContent = try? String(contentsOf: fileURL, encoding: .utf8) else {
                print("Failed to load \(fileName).ftl for locale \(currentLocale)")
                continue
            }

            let bundle = FluentBundle(locale: currentLocale)
            var errors: [FluentError] = []
            bundle.addResource(ftlContent, errors: &errors)

            if !errors.isEmpty {
                print("Fluent parsing errors in \(fileName).ftl: \(errors)")
            }

            bundles[fileName] = bundle
        }
    }
}

// MARK: - Fluent Types (Simple parser - sufficient for MVP)

/// Fluent bundle - parses and stores .ftl messages
class FluentBundle {
    let locale: String
    private var messages: [String: FluentMessage] = [:]

    init(locale: String) {
        self.locale = locale
    }

    func addResource(_ ftl: String, errors: inout [FluentError]) {
        // Simple FTL parser for key = value format
        // Supports basic variable interpolation with { $var }
        let lines = ftl.components(separatedBy: "\n")
        for line in lines {
            guard !line.isEmpty, !line.hasPrefix("#"), line.contains("=") else {
                continue
            }
            let parts = line.components(separatedBy: "=")
            if parts.count >= 2 {
                let key = parts[0].trimmingCharacters(in: .whitespaces)
                let value = parts[1...].joined(separator: "=").trimmingCharacters(in: .whitespaces)
                messages[key] = FluentMessage(value: value)
            }
        }
    }

    func getMessage(_ key: String) -> FluentMessage? {
        return messages[key]
    }

    func format(_ message: FluentMessage, args: [String: FluentValue], errors: inout [FluentError]) -> String {
        // Simple variable replacement: { $key } → value
        var result = message.value
        for (key, value) in args {
            result = result.replacingOccurrences(of: "{ $\(key) }", with: value.asString())
        }
        return result
    }
}

struct FluentMessage {
    let value: String
}

public enum FluentValue {
    case string(String)
    case number(Double)
    case int(Int)

    func asString() -> String {
        switch self {
        case .string(let s): return s
        case .number(let n): return "\(n)"
        case .int(let i): return "\(i)"
        }
    }
}

struct FluentError: Error {
    let message: String
}

// MARK: - SwiftUI Integration

extension Text {
    /// Create localized Text from Fluent key
    /// Usage: Text(fluent: "auth.onboarding-get-started")
    init(fluent key: String, args: [String: FluentValue] = [:]) {
        self.init(LocalizationService.shared.string(for: key, args: args))
    }
}

extension String {
    /// Get localized string from Fluent key
    /// Usage: "auth.onboarding-get-started".localized()
    func localized(args: [String: FluentValue] = [:]) -> String {
        LocalizationService.shared.string(for: self, args: args)
    }
}
