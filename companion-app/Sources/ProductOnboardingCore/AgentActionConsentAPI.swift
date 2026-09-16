import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public enum AgentActionConsentAPIError: Error, Equatable, Sendable {
    case invalidAuthority
    case invalidBearerToken
    case invalidDeviceBinding
    case transport
    case invalidResponse
    case rejected
}

@MainActor
public protocol AgentActionConsentServicing: AnyObject {
    func submit(
        ticket: AgentActionConsentTicket,
        decision: AgentActionConsentDecision,
        bearerToken: String,
        now: Date
    ) async throws

    func fetchPending(
        deviceID: String,
        ownerRevision: UInt64,
        bearerToken: String,
        now: Date
    ) async throws -> AgentActionConsentTicket?
}

@MainActor
public final class AgentActionConsentAPI: AgentActionConsentServicing {
    private let authority: URL
    private let transport: DeviceClaimHTTPTransport

    public convenience init(authority: URL) throws {
        try self.init(
            authority: authority,
            transport: URLSessionDeviceClaimTransport()
        )
    }

    public init(
        authority: URL,
        transport: DeviceClaimHTTPTransport
    ) throws {
        guard authority.scheme == "https", authority.user == nil,
              authority.password == nil, authority.query == nil,
              authority.fragment == nil,
              authority.path.isEmpty || authority.path == "/",
              authority.host != nil else {
            throw AgentActionConsentAPIError.invalidAuthority
        }
        self.authority = authority
        self.transport = transport
    }

    public func submit(
        ticket: AgentActionConsentTicket,
        decision: AgentActionConsentDecision,
        bearerToken: String,
        now: Date = Date()
    ) async throws {
        guard Self.validBearer(bearerToken) else {
            throw AgentActionConsentAPIError.invalidBearerToken
        }
        let consent: AgentActionConsentDecisionRequest
        do {
            consent = try ticket.consume(decision, now: now)
        } catch {
            throw error
        }
        let device = consent.deviceID.addingPercentEncoding(
            withAllowedCharacters: .urlPathAllowed
        )!
        let challenge = consent.challengeID.addingPercentEncoding(
            withAllowedCharacters: .urlPathAllowed
        )!
        guard let url = URL(
            string: "/v1/devices/\(device)/action-consents/\(challenge)/decision",
            relativeTo: authority
        )?.absoluteURL else {
            throw AgentActionConsentAPIError.invalidAuthority
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = consent.body
        request.setValue(
            String(consent.body.count), forHTTPHeaderField: "Content-Length"
        )
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
        request.setValue(
            AgentActionConsentTicket.contract,
            forHTTPHeaderField: "X-Xiaozhi-Action-Consent"
        )
        defer { request.setValue(nil, forHTTPHeaderField: "Authorization") }

        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await transport.data(for: request)
        } catch {
            throw AgentActionConsentAPIError.transport
        }
        guard response.statusCode == 200 else {
            throw AgentActionConsentAPIError.rejected
        }
        guard response.value(forHTTPHeaderField: "Cache-Control") == "no-store",
              response.value(forHTTPHeaderField: "X-Xiaozhi-Action-Consent") ==
                AgentActionConsentTicket.contract,
              data.count <= 512,
              data == Data(
                #"{"version":1,"challenge_id":"\#(consent.challengeID)","status":"accepted"}"#.utf8
              ) else {
            throw AgentActionConsentAPIError.invalidResponse
        }
    }

    /// Polls the authenticated owner's durable inbox and returns at most one
    /// exact undecided action. A nil result is an exact no-content response,
    /// not an authorization or transport failure.
    public func fetchPending(
        deviceID: String,
        ownerRevision: UInt64,
        bearerToken: String,
        now: Date = Date()
    ) async throws -> AgentActionConsentTicket? {
        guard Self.validBearer(bearerToken) else {
            throw AgentActionConsentAPIError.invalidBearerToken
        }
        guard Self.validIdentifier(deviceID), ownerRevision > 0,
              ownerRevision <= UInt64(UInt32.max) else {
            throw AgentActionConsentAPIError.invalidDeviceBinding
        }
        let device = deviceID.addingPercentEncoding(
            withAllowedCharacters: .urlPathAllowed
        )!
        guard let url = URL(
            string: "/v1/devices/\(device)/action-consents/pending",
            relativeTo: authority
        )?.absoluteURL else {
            throw AgentActionConsentAPIError.invalidAuthority
        }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.httpBody = nil
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = AgentActionConsentTicket.maximumLifetime
        request.setValue("0", forHTTPHeaderField: "Content-Length")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
        request.setValue(
            AgentActionConsentTicket.contract,
            forHTTPHeaderField: "X-Xiaozhi-Action-Consent"
        )
        defer { request.setValue(nil, forHTTPHeaderField: "Authorization") }

        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await transport.data(for: request)
        } catch {
            throw AgentActionConsentAPIError.transport
        }
        guard response.value(forHTTPHeaderField: "Cache-Control") == "no-store",
              response.value(forHTTPHeaderField: "X-Xiaozhi-Action-Consent") ==
                AgentActionConsentTicket.contract else {
            throw AgentActionConsentAPIError.invalidResponse
        }
        if response.statusCode == 204 {
            guard data.isEmpty else {
                throw AgentActionConsentAPIError.invalidResponse
            }
            return nil
        }
        guard response.statusCode == 200 else {
            throw AgentActionConsentAPIError.rejected
        }
        guard response.value(forHTTPHeaderField: "Content-Type") ==
                "application/json" else {
            throw AgentActionConsentAPIError.invalidResponse
        }
        return try AgentActionConsentTicket.parse(
            data,
            expectedDeviceID: deviceID,
            expectedOwnerRevision: ownerRevision,
            now: now
        )
    }

    private static func validBearer(_ value: String) -> Bool {
        let bytes = value.utf8
        return !bytes.isEmpty && bytes.count <= 4_096 && bytes.allSatisfy {
            $0 >= 0x21 && $0 <= 0x7E
        }
    }

    private static func validIdentifier(_ value: String) -> Bool {
        let bytes = value.utf8
        return !bytes.isEmpty && bytes.count <= 64 && bytes.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) ||
            ($0 >= 0x41 && $0 <= 0x5A) ||
            ($0 >= 0x61 && $0 <= 0x7A) ||
            $0 == 0x3A || $0 == 0x2D || $0 == 0x5F || $0 == 0x2E
        }
    }
}
