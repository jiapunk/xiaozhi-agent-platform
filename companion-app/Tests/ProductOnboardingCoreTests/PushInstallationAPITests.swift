import Foundation
import ProductOnboardingCore

@MainActor
enum PushInstallationAPITests {
    private static let now = Date(timeIntervalSince1970: 1_786_233_600)
    private static let installationID = "AAECAwQFBgcICQoLDA0ODw"
    private static let fcmToken =
        "fcm-token:abcdefghijklmnopqrstuvwxyz_0123456789"

    static func run() async throws {
        try await registrationAndRemovalAreExactAndEphemeral()
        await malformedInputsNeverAcquireSession()
        await authorizationAndConflictRemainDistinct()
        try canonicalAPNsTokenIsLowercaseAndBounded()
    }

    private static func registrationAndRemovalAreExactAndEphemeral() async throws {
        let transport = PushHTTPTransport()
        let sessions = PushSessionProvider()
        let client = try HTTPSPushInstallationClient(
            accountAuthority: URL(string: "https://accounts.example")!,
            sessionProvider: sessions,
            transport: transport
        )
        try await client.register(
            installationID: installationID, platform: .fcm,
            providerToken: fcmToken, now: now
        )
        try check(sessions.acquireCount == 1 && sessions.discardCount == 1)
        var request = try require(transport.requests.last)
        try check(
            request.url?.absoluteString ==
                "https://accounts.example/v1/companion/push-installations/\(installationID)"
        )
        try check(request.httpMethod == "PUT")
        try check(
            request.httpBody == Data(
                #"{"version":1,"platform":"fcm","token":"\#(fcmToken)"}"#.utf8
            )
        )
        try check(
            request.value(forHTTPHeaderField: "Authorization") ==
                "Bearer fresh-product-login"
        )
        try check(
            request.value(forHTTPHeaderField: "X-Xiaozhi-Companion-Push") ==
                HTTPSPushInstallationClient.contract
        )

        try await client.remove(installationID: installationID, now: now)
        try check(sessions.acquireCount == 2 && sessions.discardCount == 2)
        request = try require(transport.requests.last)
        try check(request.httpMethod == "DELETE" && request.httpBody == nil)
        try check(request.value(forHTTPHeaderField: "Content-Type") == nil)
    }

    private static func malformedInputsNeverAcquireSession() async {
        let sessions = PushSessionProvider()
        let client = try! HTTPSPushInstallationClient(
            accountAuthority: URL(string: "https://accounts.example")!,
            sessionProvider: sessions,
            transport: PushHTTPTransport()
        )
        await expectAsyncThrows(PushInstallationAPIError.invalidInstallation) {
            try await client.register(
                installationID: "not-canonical", platform: .fcm,
                providerToken: fcmToken, now: now
            )
        }
        await expectAsyncThrows(PushInstallationAPIError.invalidProviderToken) {
            try await client.register(
                installationID: installationID, platform: .fcm,
                providerToken: "token with spaces", now: now
            )
        }
        do {
            try check(sessions.acquireCount == 0)
        } catch {
            fatalError("unexpected session acquisition")
        }
    }

    private static func authorizationAndConflictRemainDistinct() async {
        let transport = PushHTTPTransport(status: 401)
        let client = try! HTTPSPushInstallationClient(
            accountAuthority: URL(string: "https://accounts.example")!,
            sessionProvider: PushSessionProvider(), transport: transport
        )
        await expectAsyncThrows(PushInstallationAPIError.unauthorized) {
            try await client.register(
                installationID: installationID, platform: .fcm,
                providerToken: fcmToken, now: now
            )
        }
        transport.status = 409
        await expectAsyncThrows(PushInstallationAPIError.conflict) {
            try await client.register(
                installationID: installationID, platform: .fcm,
                providerToken: fcmToken, now: now
            )
        }
    }

    private static func canonicalAPNsTokenIsLowercaseAndBounded() throws {
        let bytes = Data((0..<32).map(UInt8.init))
        let token = try HTTPSPushInstallationClient.canonicalAPNsToken(bytes)
        try check(
            token ==
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        )
        try expectThrows(PushInstallationAPIError.invalidProviderToken) {
            try HTTPSPushInstallationClient.canonicalAPNsToken(Data())
        }
    }

    private static func require<T>(_ value: T?) throws -> T {
        guard let value else {
            try check(false, "missing value")
            fatalError()
        }
        return value
    }
}

@MainActor
private final class PushSessionProvider:
    CompanionSessionAuthorizationProviding {
    private(set) var acquireCount = 0
    private(set) var discardCount = 0

    func acquireCompanionSessionAuthorization(
        now: Date
    ) async throws -> CompanionAuthorizationTicket {
        acquireCount += 1
        return try CompanionAuthorizationTicket(
            bearerToken: "fresh-product-login"
        )
    }

    func discardCompanionSessionAuthorization() {
        discardCount += 1
    }
}

@MainActor
private final class PushHTTPTransport: DeviceClaimHTTPTransport {
    var status: Int
    private(set) var requests: [URLRequest] = []

    init(status: Int = 204) {
        self.status = status
    }

    func data(for request: URLRequest) async throws
        -> (Data, HTTPURLResponse) {
        requests.append(request)
        let response = HTTPURLResponse(
            url: request.url!, statusCode: status, httpVersion: "HTTP/1.1",
            headerFields: [
                "Cache-Control": "no-store",
                "X-Xiaozhi-Companion-Push":
                    HTTPSPushInstallationClient.contract,
            ]
        )!
        return (Data(), response)
    }
}
