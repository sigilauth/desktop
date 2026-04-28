import Foundation
import OSLog

public enum PairFlowError: Error, LocalizedError {
    case invalidURL
    case networkError(Error)
    case timeout
    case invalidResponse
    case decodingFailed
    case httpError(Int, String?)
    case notApproved

    public var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Invalid server URL"
        case .networkError(let error):
            return "Network error: \(error.localizedDescription)"
        case .timeout:
            return "Request timed out after 10 seconds"
        case .invalidResponse:
            return "Invalid response from server"
        case .decodingFailed:
            return "Failed to decode server response"
        case .httpError(let code, let message):
            if let msg = message {
                return "HTTP \(code): \(msg)"
            }
            return "HTTP error \(code)"
        case .notApproved:
            return "Pairing not approved by administrator yet"
        }
    }
}

public actor PairFlowService {
    private let logger = Logger(subsystem: "com.wagmilabs.sigil", category: "pair-flow")
    private let timeout: TimeInterval = 10.0

    public init() {}

    public func fetchPairInit(serverURL: URL) async throws -> PairInitResponse {
        let initURL = serverURL.appendingPathComponent("pair/init")

        logger.info("Fetching /pair/init from \(initURL.absoluteString)")

        var request = URLRequest(url: initURL)
        request.httpMethod = "GET"
        request.timeoutInterval = timeout
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw PairFlowError.invalidResponse
        }

        guard httpResponse.statusCode == 200 else {
            let errorMessage = String(data: data, encoding: .utf8)
            throw PairFlowError.httpError(httpResponse.statusCode, errorMessage)
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        guard let pairInit = try? decoder.decode(PairInitResponse.self, from: data) else {
            logger.error("Failed to decode /pair/init response: \(String(data: data, encoding: .utf8) ?? "(binary)")")
            throw PairFlowError.decodingFailed
        }

        logger.debug("Received pair init: server_id=\(pairInit.serverId), expires=\(pairInit.expiresAt)")

        return pairInit
    }

    public func submitPairComplete(
        serverURL: URL,
        request: PairCompleteRequest
    ) async throws -> PairCompleteResponse {
        let completeURL = serverURL.appendingPathComponent("pair/complete")

        logger.info("Submitting /pair/complete to \(completeURL.absoluteString)")

        var urlRequest = URLRequest(url: completeURL)
        urlRequest.httpMethod = "POST"
        urlRequest.timeoutInterval = timeout
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")

        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        urlRequest.httpBody = try encoder.encode(request)

        let (data, response) = try await URLSession.shared.data(for: urlRequest)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw PairFlowError.invalidResponse
        }

        if httpResponse.statusCode == 403 {
            logger.warning("Pair complete rejected: 403 NOT_APPROVED")
            throw PairFlowError.notApproved
        }

        guard httpResponse.statusCode == 200 else {
            let errorMessage = String(data: data, encoding: .utf8)
            throw PairFlowError.httpError(httpResponse.statusCode, errorMessage)
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        guard let completeResponse = try? decoder.decode(PairCompleteResponse.self, from: data) else {
            logger.error("Failed to decode /pair/complete response: \(String(data: data, encoding: .utf8) ?? "(binary)")")
            throw PairFlowError.decodingFailed
        }

        logger.info("Pair complete successful: status=\(completeResponse.status)")

        return completeResponse
    }
}
