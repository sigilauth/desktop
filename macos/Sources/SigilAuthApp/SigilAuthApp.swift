import SwiftUI
import SigilAuth
import CryptoKit

@main
struct SigilAuthMacApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var appState = AppState()

    var body: some Scene {
        // Main server list window
        WindowGroup("Sigil Auth", id: "servers") {
            ServerListView()
                .environmentObject(appState)
                .frame(minWidth: 600, minHeight: 400)
                .onAppear {
                    // Pass appState to app delegate for menubar popover
                    appDelegate.appState = appState
                }
        }
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Add Server...") {
                    appState.showPairing = true
                }
                .keyboardShortcut("n", modifiers: [.command])
            }

            CommandGroup(after: .appInfo) {
                Button("Quick Approve...") {
                    appState.showQuickApprove = true
                }
                .keyboardShortcut("a", modifiers: [.command, .shift])
            }
        }

        // Pairing window (separate window for registration flow)
        WindowGroup("Pair with Server", id: "pairing") {
            PairingView()
                .environmentObject(appState)
                .frame(width: 500, height: 600)
        }

        // Approval window (for challenge approval)
        WindowGroup("Approve Request", id: "approval") {
            ApprovalView()
                .environmentObject(appState)
                .frame(width: 450, height: 350)
        }

        // Settings window
        Settings {
            SettingsView()
                .environmentObject(appState)
        }
    }
}

/// AppDelegate for menubar icon and global shortcuts
class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    var appState: AppState?

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupMenubarIcon()
        setupGlobalShortcuts()
    }

    private func setupMenubarIcon() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)

        if let button = statusItem?.button {
            // Use SF Symbol for menubar icon
            button.image = NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "Sigil Auth")
            button.action = #selector(togglePopover)
            button.target = self
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }

        // Popover will be created lazily when first shown (to ensure appState is set)
    }

    @objc private func togglePopover() {
        guard let button = statusItem?.button else { return }

        if let event = NSApp.currentEvent, event.type == .rightMouseUp {
            // Right-click shows context menu
            showContextMenu()
        } else {
            // Left-click toggles popover
            if popover == nil, let appState = appState {
                // Create popover on first show with appState
                popover = NSPopover()
                popover?.contentSize = NSSize(width: 300, height: 200)
                popover?.behavior = .transient
                popover?.contentViewController = NSHostingController(
                    rootView: QuickApproveView().environmentObject(appState)
                )
            }

            if let popover = popover {
                if popover.isShown {
                    popover.performClose(nil)
                } else {
                    popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
                }
            }
        }
    }

    private func showContextMenu() {
        let menu = NSMenu()

        menu.addItem(NSMenuItem(title: "Quick Approve...", action: #selector(openQuickApprove), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Servers...", action: #selector(openServerList), keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Settings...", action: #selector(openSettings), keyEquivalent: ","))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Quit Sigil Auth", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))

        statusItem?.menu = menu
        statusItem?.button?.performClick(nil)
        statusItem?.menu = nil
    }

    @objc private func openQuickApprove() {
        NSApp.activate(ignoringOtherApps: true)
        // Open quick approve window
    }

    @objc private func openServerList() {
        NSApp.activate(ignoringOtherApps: true)
        // Open main window
    }

    @objc private func openSettings() {
        NSApp.sendAction(Selector(("showPreferencesWindow:")), to: nil, from: nil)
    }

    private func setupGlobalShortcuts() {
        // Global keyboard shortcuts (Cmd+Shift+A for quick approve)
        NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            guard event.modifierFlags.contains([.command, .shift]) else { return event }

            switch event.charactersIgnoringModifiers {
            case "a":
                self.openQuickApprove()
                return nil
            case "s":
                self.openServerList()
                return nil
            default:
                return event
            }
        }
    }
}

/// App-wide state management
@MainActor
class AppState: ObservableObject {
    @Published var showPairing = false
    @Published var showQuickApprove = false
    @Published var pendingApprovals: [PendingApproval] = []
    @Published var servers: [ServerConfig] = []
    @Published var relayState: RelayClient.State = .disconnected

    private let relayClient = RelayClient()
    private var deviceKey: SecureEnclaveKey?
    private let trustStorage = KeychainTrustStorage()
    private let challengeService = ChallengeService()

    init() {
        loadServers()
        Task {
            await connectToRelay()
        }
    }

    private func loadServers() {
        do {
            let trustedServers = try trustStorage.loadAllTrustedServers()
            servers = trustedServers.compactMap { trusted -> ServerConfig? in
                // Derive pictogram from server fingerprint
                guard let fingerprintData = Data(hex: trusted.serverFingerprint),
                      fingerprintData.count == 32 else {
                    // Skip servers with invalid fingerprints
                    return nil
                }

                let pictogram = Pictogram.derive(from: fingerprintData)

                return ServerConfig(
                    name: trusted.serverId,
                    url: trusted.serverUrl,
                    pictogram: pictogram
                )
            }
        } catch {
            print("Failed to load servers from Keychain: \(error)")
            servers = []
        }
    }

    func refreshServers() {
        loadServers()
    }

    func connectToRelay() async {
        do {
            // Generate or load device key
            if deviceKey == nil {
                deviceKey = try SecureEnclaveKey.generate()
            }

            guard let key = deviceKey else { return }

            // TODO: Make relay URL configurable
            guard let relayURL = URL(string: "ws://10.79.1.30:3104") else { return }

            await relayClient.setStateChangeHandler { [weak self] state in
                Task { @MainActor in
                    self?.relayState = state
                }
            }

            await relayClient.setNotificationHandler { [weak self] notification in
                Task { @MainActor in
                    self?.handleNotification(notification)
                }
            }

            try await relayClient.connect(to: relayURL, deviceKey: key)
        } catch {
            print("Failed to connect to relay: \(error)")
        }
    }

    private func handleNotification(_ notification: ChallengeNotification) {
        let approval = PendingApproval(
            serverName: notification.server_name ?? "Unknown Server",
            serverId: notification.server_id,
            serverPubkey: notification.server_pubkey,
            action: notification.action ?? "Authenticate",
            expiresAt: ISO8601DateFormatter().date(from: notification.expires_at) ?? Date(),
            challenge: notification.challenge,
            notification: notification
        )
        pendingApprovals.append(approval)
        showQuickApprove = true
    }

    func approveChallenge(_ approval: PendingApproval) async throws {
        // Look up trusted server
        guard let serverPubkey = approval.serverPubkey,
              let serverPubkeyData = Data(base64Encoded: serverPubkey) else {
            throw ApprovalError.missingServerInfo
        }

        // Compute server fingerprint
        let serverFingerprint = serverPubkeyData.hexString

        // Look up from trust storage
        guard let trustedServer = try? trustStorage.loadTrustedServer(fingerprint: serverFingerprint) else {
            throw ApprovalError.serverNotTrusted
        }

        // Decode challenge
        guard let challengeData = Data(base64Encoded: approval.challenge) else {
            throw ApprovalError.invalidChallenge
        }

        // Sign with device key (biometric gate happens inside)
        guard let deviceKey = deviceKey else {
            throw ApprovalError.noDeviceKey
        }

        let signature = try await deviceKey.sign(challengeData, reason: "Approve \(approval.action) for \(approval.serverName)")

        // Extract device fingerprint (SHA256 of device public key)
        let deviceFingerprint = Data(SHA256.hash(data: deviceKey.publicKey)).hexString

        // Get challenge ID from notification
        guard let challengeId = approval.notification.challenge_id else {
            throw ApprovalError.missingServerInfo
        }

        // Post signed response to server
        try await challengeService.respondToChallenge(
            serverURL: trustedServer.serverUrl,
            challengeId: challengeId,
            fingerprint: deviceFingerprint,
            signature: signature
        )

        // Success - remove from pending queue
        pendingApprovals.removeAll { $0.id == approval.id }
    }

    func denyChallenge(_ approval: PendingApproval) {
        pendingApprovals.removeAll { $0.id == approval.id }
    }
}

struct PendingApproval: Identifiable {
    let id = UUID()
    let serverName: String
    let serverId: String?
    let serverPubkey: String?
    let action: String
    let expiresAt: Date
    let challenge: String
    let notification: ChallengeNotification
}

struct ServerConfig: Identifiable {
    let id = UUID()
    let name: String
    let url: URL
    let pictogram: Pictogram
}

enum ApprovalError: Error, LocalizedError {
    case missingServerInfo
    case serverNotTrusted
    case invalidChallenge
    case noDeviceKey
    case signatureFailed

    var errorDescription: String? {
        switch self {
        case .missingServerInfo:
            return "Server information missing from challenge"
        case .serverNotTrusted:
            return "Server not found in trusted servers"
        case .invalidChallenge:
            return "Invalid challenge format"
        case .noDeviceKey:
            return "Device key not available"
        case .signatureFailed:
            return "Failed to sign challenge"
        }
    }
}
