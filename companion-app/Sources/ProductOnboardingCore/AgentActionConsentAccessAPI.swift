import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public enum AgentActionConsentAccessAPIError: Error, Equatable, Sendable {
    case invalidAuthority
    case invalidDeviceBinding
    case sessionUnavailable
    case invalidSessionAuthorization
    case transport
    case invalidResponse
    case unauthorized
    case bindingChanged
    case rateLimited
    case rejected
}

/// Supplies a fresh product-login authorization for one BFF request. The
/// selected IdP adapter owns login, MFA, recovery and session rotation; this
/// protocol deliberately cannot mint an action-consent bearer itself.
@MainActor
public protocol CompanionSessionAuthorizationProviding: AnyObject {
    func acquireCompanionSessionAuthorization(
        now: Date
    ) async throws -> CompanionAuthorizationTicket

    func discardCompanionSessionAuthorization()
}

/// Product BFF adapter for just-in-time `device:action-consent` access. It
/// exchanges a fresh authenticated App session for one short-lived bearer
/// bound to the exact device. Neither the login authorization nor the issued
/// bearer is retained by this object.
@MainActor
public final class HTTPSAgentActionConsentAccessProvider:
    AgentActionConsentAccessProviding {
    public static let contract = "xz-companion-access-v1"
    public static let maximumResponseBytes = 6_144

    private let endpoint: URL
    private let sessionProvider: CompanionSessionAuthorizationProviding
    private let transport: DeviceClaimHTTPTransport

    public convenience init(
        accountAuthority: URL,
        sessionProvider: CompanionSessionAuthorizationProviding
    ) throws {
        try self.init(
            accountAuthority: accountAuthority,
            sessionProvider: sessionProvider,
            transport: URLSessionDeviceClaimTransport()
        )
    }

    public init(
        accountAuthority: URL,
        sessionProvider: CompanionSessionAuthorizationProviding,
        transport: DeviceClaimHTTPTransport
    ) throws {
        guard accountAuthority.scheme == "https",
              accountAuthority.user == nil,
              accountAuthority.password == nil,
              accountAuthority.query == nil,
              accountAuthority.fragment == nil,
              accountAuthority.path.isEmpty || accountAuthority.path == "/",
              accountAuthority.host != nil,
              let endpoint = URL(
                string: "/v1/companion/action-consent-access",
                relativeTo: accountAuthority
              )?.absoluteURL else {
            throw AgentActionConsentAccessAPIError.invalidAuthority
        }
        self.endpoint = endpoint
        self.sessionProvider = sessionProvider
        self.transport = transport
    }

    public func acquireActionConsentAccess(
        deviceID: String,
        ownerRevision: UInt64,
        now: Date
    ) async throws -> AgentActionConsentAccess {
        guard Self.validIdentifier(deviceID), ownerRevision > 0,
              ownerRevision <= UInt64(UInt32.max) else {
            throw AgentActionConsentAccessAPIError.invalidDeviceBinding
        }

        let authorization: CompanionAuthorizationTicket
        do {
            authorization = try await sessionProvider
                .acquireCompanionSessionAuthorization(now: now)
        } catch {
            sessionProvider.discardCompanionSessionAuthorization()
            throw AgentActionConsentAccessAPIError.sessionUnavailable
        }
        defer {
            authorization.invalidate()
            sessionProvider.discardCompanionSessionAuthorization()
        }

        let body = Data(
            #"{"version":1,"device_id":"\#(deviceID)","owner_revision":\#(ownerRevision),"purpose":"action-consent"}"#.utf8
        )
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.httpBody = body
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = AgentActionConsentTicket.maximumLifetime
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue(String(body.count), forHTTPHeaderField: "Content-Length")
        request.setValue(
            Self.contract,
            forHTTPHeaderField: "X-Xiaozhi-Companion-Access"
        )
        do {
            try authorization.withBearer {
                request.setValue(
                    "Bearer \($0)", forHTTPHeaderField: "Authorization"
                )
            }
        } catch {
            throw AgentActionConsentAccessAPIError.invalidSessionAuthorization
        }
        defer { request.setValue(nil, forHTTPHeaderField: "Authorization") }

        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await transport.data(for: request)
        } catch {
            throw AgentActionConsentAccessAPIError.transport
        }
        switch response.statusCode {
        case 200:
            break
        case 401, 403:
            throw AgentActionConsentAccessAPIError.unauthorized
        case 409:
            throw AgentActionConsentAccessAPIError.bindingChanged
        case 429:
            throw AgentActionConsentAccessAPIError.rateLimited
        default:
            throw AgentActionConsentAccessAPIError.rejected
        }
        guard response.value(forHTTPHeaderField: "Content-Type") ==
                "application/json",
              response.value(forHTTPHeaderField: "Cache-Control") == "no-store",
              response.value(forHTTPHeaderField: "X-Xiaozhi-Companion-Access") ==
                Self.contract,
              !data.isEmpty, data.count <= Self.maximumResponseBytes else {
            throw AgentActionConsentAccessAPIError.invalidResponse
        }
        return try Self.parseResponse(
            data,
            expectedDeviceID: deviceID,
            expectedOwnerRevision: ownerRevision,
            now: now
        )
    }

    public func discardActionConsentAccess() {
        // Defensive propagation for cancellation paths. This provider retains
        // no issued bearer of its own.
        sessionProvider.discardCompanionSessionAuthorization()
    }

    private static func parseResponse(
        _ data: Data,
        expectedDeviceID: String,
        expectedOwnerRevision: UInt64,
        now: Date
    ) throws -> AgentActionConsentAccess {
        let raw: Any
        do {
            raw = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw AgentActionConsentAccessAPIError.invalidResponse
        }
        let keys: Set<String> = [
            "version", "device_id", "owner_revision", "expires_at_unix",
            "access_token",
        ]
        guard let document = raw as? [String: Any],
              Set(document.keys) == keys,
              exactUnsigned(document["version"]) == 1,
              let deviceID = document["device_id"] as? String,
              let ownerRevision = exactUnsigned(document["owner_revision"]),
              let expiresUnix = exactUnsigned(document["expires_at_unix"]),
              let accessToken = document["access_token"] as? String,
              deviceID == expectedDeviceID,
              ownerRevision == expectedOwnerRevision,
              expiresUnix <= UInt64(Int64.max),
              validAccessToken(accessToken) else {
            throw AgentActionConsentAccessAPIError.invalidResponse
        }
        let canonical = Data(
            #"{"version":1,"device_id":"\#(deviceID)","owner_revision":\#(ownerRevision),"expires_at_unix":\#(expiresUnix),"access_token":"\#(accessToken)"}"#.utf8
        )
        guard canonical == data else {
            throw AgentActionConsentAccessAPIError.invalidResponse
        }
        let expiresAt = Date(
            timeIntervalSince1970: TimeInterval(expiresUnix)
        )
        let lifetime = expiresAt.timeIntervalSince(now)
        guard lifetime > 0,
              lifetime <= AgentActionConsentAccess.maximumLifetime else {
            throw AgentActionConsentAccessAPIError.invalidResponse
        }
        do {
            return try AgentActionConsentAccess(
                bearerToken: accessToken,
                deviceID: deviceID,
                ownerRevision: ownerRevision,
                expiresAt: expiresAt,
                now: now
            )
        } catch {
            throw AgentActionConsentAccessAPIError.invalidResponse
        }
    }

    private static func exactUnsigned(_ value: Any?) -> UInt64? {
        guard let number = value as? NSNumber,
              String(cString: number.objCType) != "c" else {
            return nil
        }
        let text = number.stringValue
        guard !text.isEmpty,
              text.allSatisfy({ $0 >= "0" && $0 <= "9" }) else {
            return nil
        }
        return UInt64(text)
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

    private static func validAccessToken(_ value: String) -> Bool {
        let bytes = value.utf8
        return !bytes.isEmpty && bytes.count <= 4_096 && bytes.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) ||
            ($0 >= 0x41 && $0 <= 0x5A) ||
            ($0 >= 0x61 && $0 <= 0x7A) ||
            $0 == 0x2D || $0 == 0x2E || $0 == 0x5F || $0 == 0x7E
        }
    }
}
