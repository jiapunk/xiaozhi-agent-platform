import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public enum CompanionPushPlatform: String, Equatable, Sendable {
    case apnsProduction = "apns-production"
    case apnsDevelopment = "apns-development"
    case fcm
}

public enum PushInstallationAPIError: Error, Equatable, Sendable {
    case invalidAuthority
    case invalidInstallation
    case invalidProviderToken
    case sessionUnavailable
    case invalidSessionAuthorization
    case transport
    case invalidResponse
    case unauthorized
    case conflict
    case rejected
}

/// Registers the latest APNs/FCM token against the currently authenticated
/// account revision. The selected IdP owns the session and the product App owns
/// generation/keychain storage of the random installation ID. This client
/// retains neither the product-login bearer nor the provider token.
@MainActor
public final class HTTPSPushInstallationClient {
    public static let contract = "xz-companion-push-v1"
    public static let maximumRequestBytes = 5_120

    private let authority: URL
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
              accountAuthority.host != nil else {
            throw PushInstallationAPIError.invalidAuthority
        }
        self.authority = accountAuthority
        self.sessionProvider = sessionProvider
        self.transport = transport
    }

    public func register(
        installationID: String,
        platform: CompanionPushPlatform,
        providerToken: String,
        now: Date
    ) async throws {
        guard Self.validInstallationID(installationID) else {
            throw PushInstallationAPIError.invalidInstallation
        }
        guard Self.validProviderToken(providerToken, platform: platform) else {
            throw PushInstallationAPIError.invalidProviderToken
        }
        let body = Data(
            #"{"version":1,"platform":"\#(platform.rawValue)","token":"\#(providerToken)"}"#.utf8
        )
        guard body.count <= Self.maximumRequestBytes else {
            throw PushInstallationAPIError.invalidProviderToken
        }
        try await perform(
            method: "PUT", installationID: installationID,
            body: body, now: now
        )
    }

    public func remove(
        installationID: String,
        now: Date
    ) async throws {
        guard Self.validInstallationID(installationID) else {
            throw PushInstallationAPIError.invalidInstallation
        }
        try await perform(
            method: "DELETE", installationID: installationID,
            body: nil, now: now
        )
    }

    private func perform(
        method: String,
        installationID: String,
        body: Data?,
        now: Date
    ) async throws {
        guard let endpoint = URL(
            string: "/v1/companion/push-installations/\(installationID)",
            relativeTo: authority
        )?.absoluteURL else {
            throw PushInstallationAPIError.invalidAuthority
        }
        let authorization: CompanionAuthorizationTicket
        do {
            authorization = try await sessionProvider
                .acquireCompanionSessionAuthorization(now: now)
        } catch {
            sessionProvider.discardCompanionSessionAuthorization()
            throw PushInstallationAPIError.sessionUnavailable
        }
        defer {
            authorization.invalidate()
            sessionProvider.discardCompanionSessionAuthorization()
        }

        var request = URLRequest(url: endpoint)
        request.httpMethod = method
        request.httpBody = body
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 5
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue(
            Self.contract, forHTTPHeaderField: "X-Xiaozhi-Companion-Push"
        )
        if let body {
            request.setValue(
                "application/json", forHTTPHeaderField: "Content-Type"
            )
            request.setValue(
                String(body.count), forHTTPHeaderField: "Content-Length"
            )
        }
        do {
            try authorization.withBearer {
                request.setValue(
                    "Bearer \($0)", forHTTPHeaderField: "Authorization"
                )
            }
        } catch {
            throw PushInstallationAPIError.invalidSessionAuthorization
        }
        defer { request.setValue(nil, forHTTPHeaderField: "Authorization") }

        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await transport.data(for: request)
        } catch {
            throw PushInstallationAPIError.transport
        }
        switch response.statusCode {
        case 204:
            guard data.isEmpty,
                  response.value(forHTTPHeaderField: "Content-Type") == nil,
                  response.value(forHTTPHeaderField: "Cache-Control") ==
                    "no-store",
                  response.value(
                    forHTTPHeaderField: "X-Xiaozhi-Companion-Push"
                  ) == Self.contract else {
                throw PushInstallationAPIError.invalidResponse
            }
        case 401, 403:
            throw PushInstallationAPIError.unauthorized
        case 409:
            throw PushInstallationAPIError.conflict
        default:
            throw PushInstallationAPIError.rejected
        }
    }

    public static func canonicalAPNsToken(_ data: Data) throws -> String {
        guard !data.isEmpty, data.count <= 256 else {
            throw PushInstallationAPIError.invalidProviderToken
        }
        return data.map { String(format: "%02x", $0) }.joined()
    }

    private static func validInstallationID(_ value: String) -> Bool {
        guard value.utf8.count == 22,
              value.utf8.allSatisfy({
                ($0 >= 0x30 && $0 <= 0x39) ||
                ($0 >= 0x41 && $0 <= 0x5A) ||
                ($0 >= 0x61 && $0 <= 0x7A) || $0 == 0x2D || $0 == 0x5F
              }) else {
            return false
        }
        let standard = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/") + "=="
        guard let decoded = Data(base64Encoded: standard), decoded.count == 16 else {
            return false
        }
        return decoded.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "") == value
    }

    private static func validProviderToken(
        _ value: String,
        platform: CompanionPushPlatform
    ) -> Bool {
        let bytes = value.utf8
        switch platform {
        case .apnsProduction, .apnsDevelopment:
            return bytes.count >= 32 && bytes.count <= 512 &&
                bytes.count.isMultiple(of: 2) && bytes.allSatisfy {
                    ($0 >= 0x30 && $0 <= 0x39) ||
                    ($0 >= 0x61 && $0 <= 0x66)
                }
        case .fcm:
            return bytes.count >= 20 && bytes.count <= 4_096 &&
                bytes.allSatisfy {
                    ($0 >= 0x30 && $0 <= 0x39) ||
                    ($0 >= 0x41 && $0 <= 0x5A) ||
                    ($0 >= 0x61 && $0 <= 0x7A) ||
                    $0 == 0x3A || $0 == 0x5F || $0 == 0x2D ||
                    $0 == 0x2E || $0 == 0x7E
                }
        }
    }
}
