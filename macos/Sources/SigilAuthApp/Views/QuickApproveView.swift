import SwiftUI
import SigilAuth

/// Quick approve flyout from menubar icon
struct QuickApproveView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Pending Approvals")
                .font(.headline)
                .padding(.horizontal)
                .accessibilityAddTraits(.isHeader)
                .accessibilityLabel("Pending Approvals")

            if appState.pendingApprovals.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "checkmark.circle")
                        .font(.largeTitle)
                        .foregroundColor(.green)
                        .accessibilityHidden(true)

                    Text("No pending requests")
                        .foregroundColor(Color(hex: "9ca0b0"))
                }
                .frame(maxWidth: .infinity)
                .padding()
                .accessibilityElement(children: .combine)
                .accessibilityLabel("No pending authentication requests")
            } else {
                ScrollView {
                    VStack(spacing: 8) {
                        ForEach(appState.pendingApprovals) { approval in
                            PendingApprovalRow(
                                approval: approval,
                                onApprove: {
                                    Task {
                                        do {
                                            try await appState.approveChallenge(approval)
                                        } catch {
                                            print("Approval failed: \(error)")
                                        }
                                    }
                                },
                                onReject: {
                                    appState.denyChallenge(approval)
                                }
                            )
                        }
                    }
                    .padding(.horizontal)
                }
                .accessibilityLabel("Pending requests list")
            }
        }
        .padding(.vertical)
        .frame(width: 300, height: 200)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Quick Approve")
    }
}

struct PendingApprovalRow: View {
    let approval: PendingApproval
    let onApprove: () -> Void
    let onReject: () -> Void

    private var timeRemaining: String {
        let now = Date()
        let remaining = approval.expiresAt.timeIntervalSince(now)
        if remaining <= 0 {
            return "Expired"
        } else if remaining < 60 {
            return "\(Int(remaining))s"
        } else {
            return "\(Int(remaining / 60))m"
        }
    }

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(approval.serverName)
                    .font(.subheadline)
                    .fontWeight(.medium)
                    .accessibilityLabel("Server: \(approval.serverName)")

                Text(approval.action)
                    .font(.caption)
                    .foregroundColor(Color(hex: "9ca0b0"))
                    .accessibilityLabel("Action: \(approval.action)")

                Text("Expires: \(timeRemaining)")
                    .font(.caption2)
                    .foregroundColor(.orange)
                    .accessibilityLabel("Expires in \(timeRemaining)")
            }

            Spacer()

            HStack(spacing: 8) {
                Button("Deny") {
                    onReject()
                }
                .buttonStyle(.bordered)
                .controlSize(.small)

                Button("Approve") {
                    onApprove()
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
                .accessibilityLabel("Approve \(approval.action) for \(approval.serverName)")
                .accessibilityHint("Double tap to approve this authentication request")
            }
        }
        .padding(16)
        .background(Color(hex: "141420"))
        .cornerRadius(10)
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color(hex: "252536"), lineWidth: 1)
        )
        .accessibilityElement(children: .contain)
    }
}

#Preview {
    QuickApproveView()
}
