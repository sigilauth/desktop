import Foundation
import Combine
import OSLog
import CryptoKit

@MainActor
public final class PairFlowViewModel: ObservableObject {
    public enum State: Equatable {
        case idle
        case fetchingInit
        case derivingPictogram
        case displayingPictogram(SessionPictogram, Date)
        case submittingComplete
        case persistingTrust
        case success(TrustedServer)
        case waitingForApproval
        case error(String)
        case denied
        case timeout
    }

    @Published public private(set) var state: State = .idle

    private let pairService: PairFlowService
    private let trustStorage: TrustStorageService
    private let pictogramDerivation: SessionPictogramDerivation
    private let logger = Logger(subsystem: "com.wagmilabs.sigil", category: "pair-flow-vm")

    private var serverURL: URL?
    private var deviceKey: SecureEnclaveKey?
    private var pairInitResponse: PairInitResponse?

    public init(
        pairService: PairFlowService = PairFlowService(),
        trustStorage: TrustStorageService = KeychainTrustStorage(),
        pictogramDerivation: SessionPictogramDerivation = SessionPictogramDerivation()
    ) {
        self.pairService = pairService
        self.trustStorage = trustStorage
        self.pictogramDerivation = pictogramDerivation
    }

    public func startPairing(serverURL: URL, deviceKey: SecureEnclaveKey) async {
        self.serverURL = serverURL
        self.deviceKey = deviceKey
        state = .fetchingInit

        do {
            let initResponse = try await pairService.fetchPairInit(serverURL: serverURL)
            self.pairInitResponse = initResponse

            state = .derivingPictogram

            let pictogram = try derivePictogram(
                serverPublicKey: initResponse.serverPublicKey,
                clientPublicKey: deviceKey.publicKey.base64EncodedString(),
                serverNonce: initResponse.serverNonce
            )

            state = .displayingPictogram(pictogram, initResponse.expiresAt)

        } catch let error as PairFlowError {
            logger.error("Pair init failed: \(error.localizedDescription)")
            state = .error(error.localizedDescription)
        } catch {
            logger.error("Pair init failed: \(error.localizedDescription)")
            state = .error(error.localizedDescription)
        }
    }

    public func confirmPairing() async {
        guard case .displayingPictogram = state,
              let serverURL = serverURL,
              let deviceKey = deviceKey,
              let initResponse = pairInitResponse else {
            logger.error("confirmPairing called in invalid state")
            return
        }

        state = .submittingComplete

        do {
            let deviceName = Host.current().localizedName ?? "macOS Device"
            let osVersion = ProcessInfo.processInfo.operatingSystemVersionString

            let completeRequest = PairCompleteRequest(
                serverNonce: initResponse.serverNonce,
                clientPublicKey: deviceKey.publicKey.base64EncodedString(),
                deviceInfo: PairCompleteRequest.DeviceInfo(
                    name: deviceName,
                    platform: "macos",
                    osVersion: osVersion
                )
            )

            let completeResponse = try await pairService.submitPairComplete(
                serverURL: serverURL,
                request: completeRequest
            )

            state = .persistingTrust

            guard let serverPubKeyData = Data(base64Encoded: completeResponse.serverPublicKey) else {
                throw PairFlowError.decodingFailed
            }

            let serverFingerprint = SHA256.hash(data: serverPubKeyData)
                .map { String(format: "%02x", $0) }
                .joined()

            let trustedServer = TrustedServer(
                serverUrl: serverURL,
                serverId: initResponse.serverId,
                serverPublicKey: completeResponse.serverPublicKey,
                serverFingerprint: serverFingerprint,
                pairedAt: completeResponse.pairedAt
            )

            try trustStorage.saveTrustedServer(trustedServer)

            logger.info("Pairing complete: \(serverFingerprint.prefix(16))...")

            state = .success(trustedServer)

        } catch PairFlowError.notApproved {
            logger.warning("Pairing not yet approved by admin")
            state = .waitingForApproval
        } catch let error as PairFlowError {
            logger.error("Pair complete failed: \(error.localizedDescription)")
            state = .error(error.localizedDescription)
        } catch {
            logger.error("Pair complete failed: \(error.localizedDescription)")
            state = .error(error.localizedDescription)
        }
    }

    public func denyPairing() {
        logger.info("User denied pairing")
        state = .denied
    }

    public func handleTimeout() {
        logger.warning("Pairing session timed out")
        state = .timeout
    }

    public func reset() {
        state = .idle
        serverURL = nil
        deviceKey = nil
        pairInitResponse = nil
    }

    private func derivePictogram(
        serverPublicKey: String,
        clientPublicKey: String,
        serverNonce: String
    ) throws -> SessionPictogram {
        guard let serverPubKeyData = Data(base64Encoded: serverPublicKey),
              let clientPubKeyData = Data(base64Encoded: clientPublicKey),
              let serverNonceData = Data(base64Encoded: serverNonce) else {
            throw SessionPictogramError.invalidPublicKeySize
        }

        return try pictogramDerivation.derive(
            serverPublicKey: serverPubKeyData,
            clientPublicKey: clientPubKeyData,
            serverNonce: serverNonceData
        )
    }
}
