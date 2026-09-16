import Foundation
import ProductOnboardingCore

@MainActor
enum AgentActionConsentAccessAPITests {
    private static let now = Date(timeIntervalSince1970: 1_786_233_600)
    private static let token = "v1.eyJhbGciOiJFZERTQSJ9.signature"

    static func run() async throws {
        try await canonicalExchangeIsExactAndEphemeral()
        await nonCanonicalOrMismatchedResponseIsRejected()
        await longLivedOrUnsafeBearerIsRejected()
        await authenticationAndBindingFailuresRemainDistinct()
    }

    private static func canonicalExchangeIsExactAndEphemeral() async throws {
        let response = canonicalResponse()
        let transport = AccessHTTPTransport(data: response.data,
                                            response: response.response)
        let sessions = AccessSessionProvider()
        let provider = try HTTPSAgentActionConsentAccessProvider(
            accountAuthority: URL(string: "https://accounts.example")!,
            sessionProvider: sessions,
            transport: transport
        )
        let access = try await provider.acquireActionConsentAccess(
            deviceID: "xz-device-1", ownerRevision: 42, now: now
        )
        try check(access.bearerToken == token)
        try check(access.deviceID == "xz-device-1")
        try check(access.ownerRevision == 42)
        try check(access.expiresAt == now.addingTimeInterval(120))
        try check(sessions.acquireCount == 1 && sessions.discardCount == 1)
        let request = try require(transport.request)
        try check(
            request.url?.absoluteString ==
                "https://accounts.example/v1/companion/action-consent-access"
        )
        try check(request.httpMethod == "POST")
        try check(
            request.httpBody == Data(
                #"{"version":1,"device_id":"xz-device-1","owner_revision":42,"purpose":"action-consent"}"#.utf8
            )
        )
        try check(
            request.value(forHTTPHeaderField: "Authorization") ==
                "Bearer fresh-product-login"
        )
        try check(
            request.value(forHTTPHeaderField: "X-Xiaozhi-Companion-Access") ==
                HTTPSAgentActionConsentAccessProvider.contract
        )
        provider.discardActionConsentAccess()
        try check(sessions.discardCount == 2)
    }

    private static func nonCanonicalOrMismatchedResponseIsRejected() async {
        for data in [
            canonicalResponse(deviceID: "xz-device-2").data,
            canonicalResponse(ownerRevision: 43).data,
            canonicalResponse().data + Data("\n".utf8),
        ] {
            let valid = canonicalResponse()
            let transport = AccessHTTPTransport(
                data: data, response: valid.response
            )
            let provider = try! HTTPSAgentActionConsentAccessProvider(
                accountAuthority: URL(string: "https://accounts.example")!,
                sessionProvider: AccessSessionProvider(),
                transport: transport
            )
            await expectAsyncThrows(
                AgentActionConsentAccessAPIError.invalidResponse
            ) {
                try await provider.acquireActionConsentAccess(
                    deviceID: "xz-device-1", ownerRevision: 42, now: now
                )
            }
        }
    }

    private static func longLivedOrUnsafeBearerIsRejected() async {
        for response in [
            canonicalResponse(expiresAt: now.addingTimeInterval(301)),
            canonicalResponse(token: "unsafe/token"),
        ] {
            let provider = try! HTTPSAgentActionConsentAccessProvider(
                accountAuthority: URL(string: "https://accounts.example")!,
                sessionProvider: AccessSessionProvider(),
                transport: AccessHTTPTransport(
                    data: response.data, response: response.response
                )
            )
            await expectAsyncThrows(
                AgentActionConsentAccessAPIError.invalidResponse
            ) {
                try await provider.acquireActionConsentAccess(
                    deviceID: "xz-device-1", ownerRevision: 42, now: now
                )
            }
        }
    }

    private static func authenticationAndBindingFailuresRemainDistinct() async {
        let response = canonicalResponse(status: 401)
        let provider = try! HTTPSAgentActionConsentAccessProvider(
            accountAuthority: URL(string: "https://accounts.example")!,
            sessionProvider: AccessSessionProvider(),
            transport: AccessHTTPTransport(
                data: Data(), response: response.response
            )
        )
        await expectAsyncThrows(AgentActionConsentAccessAPIError.unauthorized) {
            try await provider.acquireActionConsentAccess(
                deviceID: "xz-device-1", ownerRevision: 42, now: now
            )
        }
        await expectAsyncThrows(
            AgentActionConsentAccessAPIError.invalidDeviceBinding
        ) {
            try await provider.acquireActionConsentAccess(
                deviceID: "../device", ownerRevision: 42, now: now
            )
        }
    }

    private static func canonicalResponse(
        deviceID: String = "xz-device-1",
        ownerRevision: UInt64 = 42,
        expiresAt: Date = now.addingTimeInterval(120),
        token: String = token,
        status: Int = 200
    ) -> (data: Data, response: HTTPURLResponse) {
        let expires = UInt64(expiresAt.timeIntervalSince1970)
        let data = Data(
            #"{"version":1,"device_id":"\#(deviceID)","owner_revision":\#(ownerRevision),"expires_at_unix":\#(expires),"access_token":"\#(token)"}"#.utf8
        )
        let response = HTTPURLResponse(
            url: URL(string: "https://accounts.example/v1/companion/action-consent-access")!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: [
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                "X-Xiaozhi-Companion-Access":
                    HTTPSAgentActionConsentAccessProvider.contract,
            ]
        )!
        return (data, response)
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
private final class AccessSessionProvider:
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
private final class AccessHTTPTransport: DeviceClaimHTTPTransport {
    let data: Data
    let response: HTTPURLResponse
    private(set) var request: URLRequest?

    init(data: Data, response: HTTPURLResponse) {
        self.data = data
        self.response = response
    }

    func data(for request: URLRequest) async throws
        -> (Data, HTTPURLResponse) {
        self.request = request
        return (data, response)
    }
}
