import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(Security)
import Security
#endif

public enum DeviceClaimStatus: String, Equatable, Sendable {
    case pending
    case bound
}

public struct DeviceClaimRequest: Equatable, Sendable {
    public let requestID: String
    public let deviceID: String
    public let status: DeviceClaimStatus
    public let expiresAt: Date

    public init(requestID: String, deviceID: String,
                status: DeviceClaimStatus, expiresAt: Date) {
        self.requestID = requestID
        self.deviceID = deviceID
        self.status = status
        self.expiresAt = expiresAt
    }
}

public struct DeviceOwnershipRelease: Equatable, Sendable {
    public let deviceID: String
    public let bindingRevision: UInt64

    public init(deviceID: String, bindingRevision: UInt64) {
        self.deviceID = deviceID
        self.bindingRevision = bindingRevision
    }
}

public enum DeviceClaimAPIError: Error, Equatable, Sendable {
    case invalidConfiguration
    case invalidAuthorization
    case invalidRequest
    case transport
    case invalidResponse
    case unauthorized
    case notFound
    case conflict
    case expired
    case rateLimited
}

/// Short-lived product-login credential. It is never derived from label PoP.
/// Foundation necessarily creates temporary Strings for HTTP headers; callers
/// must invalidate this ticket when the flow terminates.
public final class CompanionAuthorizationTicket: @unchecked Sendable {
    private let lock = NSLock()
    private var bearer: ContiguousArray<UInt8>
    private var invalidated = false

    public init(bearerToken: String) throws {
        let bytes = ContiguousArray(bearerToken.utf8)
        guard !bytes.isEmpty, bytes.count <= 4096,
              bytes.allSatisfy({ $0 > 0x20 && $0 < 0x7F }) else {
            throw DeviceClaimAPIError.invalidAuthorization
        }
        bearer = bytes
    }

    func withBearer<T>(_ body: (String) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        guard !invalidated else {
            throw DeviceClaimAPIError.invalidAuthorization
        }
        return try body(String(decoding: bearer, as: UTF8.self))
    }

    public func invalidate() {
        lock.lock()
        defer { lock.unlock() }
        invalidated = true
        wipe(&bearer)
    }

    deinit { invalidate() }
}

@MainActor
public protocol ProductDeviceClaimAPI: AnyObject {
    func begin(
        using claim: DeviceClaimTicket,
        authorization: CompanionAuthorizationTicket,
        now: Date
    ) async throws -> DeviceClaimRequest

    func status(
        for request: DeviceClaimRequest,
        authorization: CompanionAuthorizationTicket,
        now: Date
    ) async throws -> DeviceClaimRequest

    /// The account service must issue this ticket only after a fresh,
    /// high-assurance user reauthentication and bind it to device:release plus
    /// the exact device ID. This client never converts a claim token into a
    /// release token.
    func release(
        deviceID: String,
        authorization: CompanionAuthorizationTicket
    ) async throws -> DeviceOwnershipRelease
}

@MainActor
public protocol DeviceClaimHTTPTransport: AnyObject {
    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

@MainActor
public final class URLSessionDeviceClaimTransport: NSObject,
    DeviceClaimHTTPTransport {
    private let redirectDelegate = NoRedirectDelegate()
    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 30
        return URLSession(configuration: configuration,
                          delegate: redirectDelegate, delegateQueue: nil)
    }()

    public override init() {}

    public func data(for request: URLRequest) async throws
        -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw DeviceClaimAPIError.invalidResponse
        }
        return (data, http)
    }

}

private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate,
    @unchecked Sendable {
    nonisolated func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

@MainActor
public final class HTTPSDeviceClaimAPI: ProductDeviceClaimAPI {
    private let appEndpoint: URL
    private let statusEndpoint: URL
    private let releaseEndpoint: URL
    private let transport: DeviceClaimHTTPTransport

    public convenience init(controlAuthority: URL) throws {
        try self.init(
            controlAuthority: controlAuthority,
            transport: URLSessionDeviceClaimTransport()
        )
    }

    public init(controlAuthority: URL,
                transport: DeviceClaimHTTPTransport) throws {
        guard let endpoints = Self.endpoints(authority: controlAuthority) else {
            throw DeviceClaimAPIError.invalidConfiguration
        }
        appEndpoint = endpoints.app
        statusEndpoint = endpoints.status
        releaseEndpoint = endpoints.release
        self.transport = transport
    }

    public func begin(
        using ticket: DeviceClaimTicket,
        authorization: CompanionAuthorizationTicket,
        now: Date = Date()
    ) async throws -> DeviceClaimRequest {
        let claim: EphemeralDeviceClaim
        do {
            claim = try ticket.consume()
        } catch {
            throw DeviceClaimAPIError.invalidRequest
        }
        let nonce = try Self.randomBase64URL(byteCount: 16)
        var request = URLRequest(url: appEndpoint)
        request.httpMethod = "POST"
        request.httpBody = nil
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 30
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("0", forHTTPHeaderField: "Content-Length")
        request.setValue(claim.deviceID, forHTTPHeaderField: "Device-Id")
        request.setValue(claim.claim, forHTTPHeaderField: "X-Device-Claim")
        request.setValue(nonce, forHTTPHeaderField: "X-App-Nonce")
        try authorization.withBearer {
            request.setValue("Bearer \($0)", forHTTPHeaderField: "Authorization")
        }
        defer {
            request.setValue(nil, forHTTPHeaderField: "Authorization")
            request.setValue(nil, forHTTPHeaderField: "X-Device-Claim")
        }
        let (data, response) = try await send(request)
        return try Self.parseResponse(
            data, response: response, expectedDeviceID: claim.deviceID,
            now: now
        )
    }

    public func status(
        for pending: DeviceClaimRequest,
        authorization: CompanionAuthorizationTicket,
        now: Date = Date()
    ) async throws -> DeviceClaimRequest {
        guard now < pending.expiresAt,
              Self.canonicalBase64URL(pending.requestID, byteCount: 16),
              DeviceClaimTicket.validIdentifier(pending.deviceID) else {
            throw DeviceClaimAPIError.expired
        }
        var request = URLRequest(url: statusEndpoint)
        request.httpMethod = "GET"
        request.httpBody = nil
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 30
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("0", forHTTPHeaderField: "Content-Length")
        request.setValue(pending.requestID,
                         forHTTPHeaderField: "X-Claim-Request-ID")
        try authorization.withBearer {
            request.setValue("Bearer \($0)", forHTTPHeaderField: "Authorization")
        }
        defer { request.setValue(nil, forHTTPHeaderField: "Authorization") }
        let (data, response) = try await send(request)
        let update = try Self.parseResponse(
            data, response: response, expectedDeviceID: pending.deviceID,
            now: now
        )
        guard update.requestID == pending.requestID else {
            throw DeviceClaimAPIError.invalidResponse
        }
        return DeviceClaimRequest(
            requestID: update.requestID, deviceID: update.deviceID,
            status: update.status,
            expiresAt: min(update.expiresAt, pending.expiresAt)
        )
    }

    public func release(
        deviceID: String,
        authorization: CompanionAuthorizationTicket
    ) async throws -> DeviceOwnershipRelease {
        guard DeviceClaimTicket.validIdentifier(deviceID) else {
            throw DeviceClaimAPIError.invalidRequest
        }
        var request = URLRequest(url: releaseEndpoint)
        request.httpMethod = "POST"
        request.httpBody = nil
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 30
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("0", forHTTPHeaderField: "Content-Length")
        request.setValue(deviceID, forHTTPHeaderField: "Device-Id")
        try authorization.withBearer {
            request.setValue("Bearer \($0)", forHTTPHeaderField: "Authorization")
        }
        defer { request.setValue(nil, forHTTPHeaderField: "Authorization") }
        let (data, response) = try await send(request)
        _ = response
        return try Self.parseReleaseResponse(data, expectedDeviceID: deviceID)
    }

    private func send(_ request: URLRequest) async throws
        -> (Data, HTTPURLResponse) {
        do {
            let result = try await transport.data(for: request)
            switch result.1.statusCode {
            case 200:
                guard result.0.count <= 4096,
                      let contentType = result.1.value(
                        forHTTPHeaderField: "Content-Type"
                      )?.lowercased(),
                      contentType == "application/json" ||
                        contentType.hasPrefix("application/json;") else {
                    throw DeviceClaimAPIError.invalidResponse
                }
                return result
            case 401: throw DeviceClaimAPIError.unauthorized
            case 404: throw DeviceClaimAPIError.notFound
            case 409: throw DeviceClaimAPIError.conflict
            case 410: throw DeviceClaimAPIError.expired
            case 429: throw DeviceClaimAPIError.rateLimited
            default: throw DeviceClaimAPIError.invalidResponse
            }
        } catch let error as DeviceClaimAPIError {
            throw error
        } catch {
            throw DeviceClaimAPIError.transport
        }
    }

    private static func parseResponse(
        _ data: Data,
        response: HTTPURLResponse,
        expectedDeviceID: String,
        now: Date
    ) throws -> DeviceClaimRequest {
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw DeviceClaimAPIError.invalidResponse
        }
        let keys: Set<String> = [
            "version", "request_id", "device_id", "status",
            "expires_in_seconds",
        ]
        guard let document = object as? [String: Any],
              Set(document.keys) == keys,
              let version = document["version"] as? Int, version == 1,
              let requestID = document["request_id"] as? String,
              canonicalBase64URL(requestID, byteCount: 16),
              let deviceID = document["device_id"] as? String,
              deviceID == expectedDeviceID,
              let statusText = document["status"] as? String,
              let status = DeviceClaimStatus(rawValue: statusText),
              let expires = document["expires_in_seconds"] as? Int,
              expires >= 0, expires <= 600 else {
            throw DeviceClaimAPIError.invalidResponse
        }
        let canonical =
            #"{"version":1,"request_id":"\#(requestID)","device_id":"\#(deviceID)","status":"\#(status.rawValue)","expires_in_seconds":\#(expires)}"#
        guard data == Data(canonical.utf8) ||
              data == Data((canonical + "\n").utf8) else {
            throw DeviceClaimAPIError.invalidResponse
        }
        _ = response
        return DeviceClaimRequest(
            requestID: requestID, deviceID: deviceID, status: status,
            expiresAt: now.addingTimeInterval(TimeInterval(expires))
        )
    }

    private static func parseReleaseResponse(
        _ data: Data,
        expectedDeviceID: String
    ) throws -> DeviceOwnershipRelease {
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw DeviceClaimAPIError.invalidResponse
        }
        let keys: Set<String> = [
            "version", "device_id", "status", "binding_revision",
        ]
        guard let document = object as? [String: Any],
              Set(document.keys) == keys,
              let version = document["version"] as? Int, version == 1,
              let deviceID = document["device_id"] as? String,
              deviceID == expectedDeviceID,
              document["status"] as? String == "released",
              let revision = document["binding_revision"] as? Int,
              revision >= 2 else {
            throw DeviceClaimAPIError.invalidResponse
        }
        let canonical =
            #"{"version":1,"device_id":"\#(deviceID)","status":"released","binding_revision":\#(revision)}"#
        guard data == Data(canonical.utf8) ||
              data == Data((canonical + "\n").utf8) else {
            throw DeviceClaimAPIError.invalidResponse
        }
        return DeviceOwnershipRelease(
            deviceID: deviceID, bindingRevision: UInt64(revision)
        )
    }

    private static func endpoints(authority: URL)
        -> (app: URL, status: URL, release: URL)? {
        guard authority.scheme?.lowercased() == "https",
              authority.host != nil,
              authority.user == nil, authority.password == nil,
              authority.query == nil, authority.fragment == nil,
              authority.path.isEmpty else {
            return nil
        }
        var app = URLComponents(url: authority,
                                resolvingAgainstBaseURL: false)
        var status = app
        var release = app
        app?.path = "/v1/device-claim/app"
        status?.path = "/v1/device-claim/status"
        release?.path = "/v1/device-ownership/release"
        guard let appURL = app?.url, let statusURL = status?.url,
              let releaseURL = release?.url else {
            return nil
        }
        return (appURL, statusURL, releaseURL)
    }

    private static func randomBase64URL(byteCount: Int) throws -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
#if canImport(Security)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess
        else {
            throw DeviceClaimAPIError.invalidRequest
        }
#else
        var generator = SystemRandomNumberGenerator()
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: .min ... .max, using: &generator)
        }
#endif
        defer { bytes.resetBytes(in: bytes.indices) }
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func canonicalBase64URL(_ value: String,
                                           byteCount: Int) -> Bool {
        var text = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = (4 - text.utf8.count % 4) % 4
        text += String(repeating: "=", count: padding)
        guard let decoded = Data(base64Encoded: text),
              decoded.count == byteCount else { return false }
        let encoded = decoded.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return encoded == value
    }
}
