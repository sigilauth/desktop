import SwiftUI
import AppKit

/// SwiftUI wrapper for QRScannerViewController
struct QRScannerView: NSViewControllerRepresentable {
    @Binding var scannedCode: String?
    @Binding var errorMessage: String?
    @Environment(\.dismiss) private var dismiss

    func makeNSViewController(context: Context) -> QRScannerViewController {
        let controller = QRScannerViewController()
        controller.onCodeScanned = { code in
            scannedCode = code
            dismiss()
        }
        controller.onError = { error in
            errorMessage = error
        }
        return controller
    }

    func updateNSViewController(_ nsViewController: QRScannerViewController, context: Context) {
        // No updates needed
    }
}
