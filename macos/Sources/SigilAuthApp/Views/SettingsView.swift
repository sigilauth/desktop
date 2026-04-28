import SwiftUI
import SigilAuth

struct SettingsView: View {
    var body: some View {
        TabView {
            GeneralSettingsView()
                .tabItem {
                    Label("General", systemImage: "gearshape")
                }

            SecuritySettingsView()
                .tabItem {
                    Label("Security", systemImage: "lock.shield")
                }

            AboutView()
                .tabItem {
                    Label("About", systemImage: "info.circle")
                }
        }
        .frame(width: 500, height: 400)
    }
}

struct GeneralSettingsView: View {
    @AppStorage("launchAtLogin") private var launchAtLogin = false
    @AppStorage("showMenubarIcon") private var showMenubarIcon = true

    var body: some View {
        Form {
            Toggle("Launch at login", isOn: $launchAtLogin)
                .accessibilityLabel("Launch Sigil Auth at login")

            Toggle("Show menubar icon", isOn: $showMenubarIcon)
                .accessibilityLabel("Show Sigil Auth icon in menubar")
        }
        .padding()
    }
}

struct SecuritySettingsView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Hardware Security")
                .font(.headline)
                .accessibilityAddTraits(.isHeader)

            HStack {
                Image(systemName: SecureEnclaveKey.isSecureEnclaveAvailable ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundColor(SecureEnclaveKey.isSecureEnclaveAvailable ? .green : .orange)
                    .accessibilityHidden(true)

                if SecureEnclaveKey.isSecureEnclaveAvailable {
                    Text("Secure Enclave is available (Apple Silicon)")
                        .accessibilityLabel("Secure Enclave is available on this Apple Silicon Mac")
                } else {
                    Text("Secure Enclave unavailable (Intel Mac)\nUse YubiKey for hardware security")
                        .accessibilityLabel("Secure Enclave is unavailable on this Intel Mac. Use YubiKey for hardware security.")
                }
            }

            Divider()

            Text("All authentication requires Touch ID or YubiKey tap")
                .foregroundColor(.secondary)
                .font(.caption)
                .accessibilityLabel("All authentication operations require Touch ID or YubiKey tap")
        }
        .padding()
    }
}

struct AboutView: View {
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 64))
                .foregroundColor(.blue)
                .accessibilityHidden(true)

            Text("Sigil Auth")
                .font(.title)
                .fontWeight(.semibold)
                .accessibilityAddTraits(.isHeader)

            Text("Version 0.1.0-alpha")
                .foregroundColor(.secondary)
                .accessibilityLabel("Version 0.1.0 alpha")

            Text("Hardware-backed PKI authentication for macOS")
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)

            Divider()

            if let docURL = URL(string: "https://sigilauth.com") {
                Link("Documentation", destination: docURL)
                    .accessibilityLabel("Open Sigil Auth documentation website")
            }

            if let githubURL = URL(string: "https://github.com/sigilauth") {
                Link("GitHub", destination: githubURL)
                    .accessibilityLabel("Open Sigil Auth GitHub repository")
            }

            Text("License: AGPL-3.0")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding()
    }
}

#Preview {
    SettingsView()
}
