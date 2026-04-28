import Foundation

/// Service for posting challenge responses to server
/// Per OpenAPI spec: POST /respond
public actor ChallengeService {
    private let session: URLSession
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(session: URLSession = .shared) {
        self.session = session

        self.encoder = JSONEncoder()
        self.encoder.keyEncodingStrategy = .convertToSnakeCase

        self.decoder = JSONDecoder()
        self.decoder.keyDecodingStrategy = .convertFromSnakeCase
    }

    /// Post challenge response to server
    /// POST /respond with { challenge_id, fingerprint, signature }
    public func respondToChallenge(
        serverURL: URL,
        challengeId: String,
        fingerprint: String,
        signature: Data
    ) async throws {
        let url = serverURL.appendingPathComponent("/respond")

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let response = ChallengeResponse(
            challengeId: challengeId,
            fingerprint: fingerprint,
            signature: signature.base64EncodedString()
        )

        request.httpBody = try encoder.encode(response)

        let (data, httpResponse) = try await session.data(for: request)

        guard let httpResponse = httpResponse as? HTTPURLResponse else {
            throw ChallengeServiceError.invalidResponse
        }

        guard (200..<300).contains(httpResponse.statusCode) else {
            // Try to decode error message
            if let errorResponse = try? decoder.decode(ErrorResponse.self, from: data) {
                throw ChallengeServiceError.serverError(
                    statusCode: httpResponse.statusCode,
                    error: errorResponse.error
                )
            }
            throw ChallengeServiceError.serverError(
                statusCode: httpResponse.statusCode,
                error: "HTTP \(httpResponse.statusCode)"
            )
        }

        // Success - server verified the signature
    }
}

// MARK: - Request/Response Models

private struct ChallengeResponse: Codable {
    let challengeId: String
    let fingerprint: String
    let signature: String
}

private struct ErrorResponse: Codable {
    let error: String
}

// MARK: - Errors

public enum ChallengeServiceError: Error, LocalizedError {
    case invalidResponse
    case serverError(statusCode: Int, error: String)

    public var errorDescription: String? {
        switch self {
        case .invalidResponse:
            return "Invalid server response"
        case .serverError(let statusCode, let error):
            return "Server error \(statusCode): \(error)"
        }
    }
}
