import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import ProductOnboardingCore

enum DeviceClaimTests {
    private static let claim =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    private static let document =
        #"{"version":1,"device_id":"xz-device-1","claim":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}"#
    private static let requestID = "AAECAwQFBgcICQoLDA0ODw"

    static func run() async throws {
        try canonicalEndpointResponseIsAcceptedOnce()
        try rejectsExpandedOrNonCanonicalEndpointResponse()
        try await concurrentConsumeHasOneWinner()
        try await controlPlaneBeginAndStatusAreAuthenticatedAndExact()
        try await ownershipReleaseRequiresExactActionBoundRequest()
        try await controlPlaneRejectsWrongAuthorityAndExpandedResponse()
    }

    @MainActor
    private static func ownershipReleaseRequiresExactActionBoundRequest()
        async throws {
        let releaseBody = Data(
            #"{"version":1,"device_id":"xz-device-1","status":"released","binding_revision":2}"#.utf8
        )
        let transport = FakeDeviceClaimHTTPTransport(
            responses: [response(releaseBody)]
        )
        let api = try HTTPSDeviceClaimAPI(
            controlAuthority: URL(string: "https://control.example")!,
            transport: transport
        )
        let authorization = try CompanionAuthorizationTicket(
            bearerToken: "account-step-up.release-token"
        )
        let released = try await api.release(
            deviceID: "xz-device-1", authorization: authorization
        )
        try check(released == DeviceOwnershipRelease(
            deviceID: "xz-device-1", bindingRevision: 2
        ))
        try check(transport.requests.count == 1)
        let request = transport.requests[0]
        try check(request.url?.absoluteString ==
                  "https://control.example/v1/device-ownership/release")
        try check(request.httpMethod == "POST" && request.httpBody == nil)
        try check(request.value(forHTTPHeaderField: "Content-Length") == "0")
        try check(request.value(forHTTPHeaderField: "Device-Id") ==
                  "xz-device-1")
        try check(request.value(forHTTPHeaderField: "Authorization") ==
                  "Bearer account-step-up.release-token")

        await expectAsyncThrows(DeviceClaimAPIError.invalidRequest) {
            try await api.release(
                deviceID: "bad/device", authorization: authorization
            )
        }

        let expandedTransport = FakeDeviceClaimHTTPTransport(
            responses: [response(Data(
                #"{"version":1,"device_id":"xz-device-1","status":"released","binding_revision":2,"owner_id":"user-1"}"#.utf8
            ))]
        )
        let expandedAPI = try HTTPSDeviceClaimAPI(
            controlAuthority: URL(string: "https://control.example")!,
            transport: expandedTransport
        )
        await expectAsyncThrows(DeviceClaimAPIError.invalidResponse) {
            try await expandedAPI.release(
                deviceID: "xz-device-1", authorization: authorization
            )
        }
    }

    private static func canonicalEndpointResponseIsAcceptedOnce() throws {
        let ticket = try DeviceClaimTicket.parse(Data(document.utf8))
        try check(ticket.deviceID == "xz-device-1")
        let value = try ticket.consume()
        try check(value.deviceID == "xz-device-1")
        try check(value.claim == claim)
        try expectThrows(DeviceClaimContractError.alreadyConsumed) {
            try ticket.consume()
        }
    }

    private static func rejectsExpandedOrNonCanonicalEndpointResponse() throws {
        let variants = [
            " " + document,
            document + "\n",
            document.replacingOccurrences(
                of: #""claim":""#,
                with: #""extra":true,"claim":""#
            ),
            document.replacingOccurrences(of: #""version":1"#,
                                           with: #""version":2"#),
            document.replacingOccurrences(of: "xz-device-1",
                                           with: "bad/device"),
            document.replacingOccurrences(of: claim,
                                           with: String(claim.dropLast())),
            document.replacingOccurrences(of: claim,
                                           with: String(claim.dropLast()) + "9"),
        ]
        for variant in variants {
            try expectAnyThrow { try DeviceClaimTicket.parse(Data(variant.utf8)) }
        }
    }

    private static func concurrentConsumeHasOneWinner() async throws {
        let ticket = try DeviceClaimTicket.parse(Data(document.utf8))
        let outcomes = await withTaskGroup(of: Bool.self,
                                           returning: [Bool].self) { group in
            for _ in 0..<64 {
                group.addTask { (try? ticket.consume()) != nil }
            }
            var values: [Bool] = []
            for await value in group { values.append(value) }
            return values
        }
        try check(outcomes.filter { $0 }.count == 1)
    }

    @MainActor
    private static func controlPlaneBeginAndStatusAreAuthenticatedAndExact()
        async throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let beginBody = Data(
            #"{"version":1,"request_id":"AAECAwQFBgcICQoLDA0ODw","device_id":"xz-device-1","status":"pending","expires_in_seconds":300}"#.utf8
        )
        let statusBody = Data(
            #"{"version":1,"request_id":"AAECAwQFBgcICQoLDA0ODw","device_id":"xz-device-1","status":"bound","expires_in_seconds":250}"#.utf8
        )
        let transport = FakeDeviceClaimHTTPTransport(
            responses: [response(beginBody), response(statusBody)]
        )
        let api = try HTTPSDeviceClaimAPI(
            controlAuthority: URL(string: "https://control.example:8443")!,
            transport: transport
        )
        let authorization = try CompanionAuthorizationTicket(
            bearerToken: "v1.companion.signature"
        )
        let ticket = try DeviceClaimTicket.parse(Data(document.utf8))
        let pending = try await api.begin(
            using: ticket, authorization: authorization, now: now
        )
        try check(pending.requestID == requestID)
        try check(pending.status == .pending)
        try check(transport.requests.count == 1)
        let begin = transport.requests[0]
        try check(begin.url?.absoluteString ==
                  "https://control.example:8443/v1/device-claim/app")
        try check(begin.httpMethod == "POST" && begin.httpBody == nil)
        try check(begin.value(forHTTPHeaderField: "Authorization") ==
                  "Bearer v1.companion.signature")
        try check(begin.value(forHTTPHeaderField: "X-Device-Claim") == claim)
        try check(begin.value(forHTTPHeaderField: "X-App-Nonce")?.count == 22)

        let bound = try await api.status(
            for: pending, authorization: authorization,
            now: now.addingTimeInterval(1)
        )
        try check(bound.status == .bound)
        try check(transport.requests[1].url?.absoluteString ==
                  "https://control.example:8443/v1/device-claim/status")
        try check(transport.requests[1].httpMethod == "GET")
        try check(transport.requests[1].value(
            forHTTPHeaderField: "X-Claim-Request-ID") == requestID)
        authorization.invalidate()
        await expectAsyncThrows(DeviceClaimAPIError.invalidAuthorization) {
            try await api.status(for: bound, authorization: authorization,
                                 now: now.addingTimeInterval(2))
        }
    }

    @MainActor
    private static func controlPlaneRejectsWrongAuthorityAndExpandedResponse()
        async throws {
        try expectThrows(DeviceClaimAPIError.invalidConfiguration) {
            try HTTPSDeviceClaimAPI(
                controlAuthority: URL(string: "http://control.example")!,
                transport: FakeDeviceClaimHTTPTransport(responses: [])
            )
        }
        try expectThrows(DeviceClaimAPIError.invalidConfiguration) {
            try HTTPSDeviceClaimAPI(
                controlAuthority: URL(string: "https://control.example/path")!,
                transport: FakeDeviceClaimHTTPTransport(responses: [])
            )
        }
        let expanded = Data(
            #"{"version":1,"request_id":"AAECAwQFBgcICQoLDA0ODw","device_id":"xz-device-1","status":"pending","expires_in_seconds":300,"owner":"secret"}"#.utf8
        )
        let transport = FakeDeviceClaimHTTPTransport(
            responses: [response(expanded)]
        )
        let api = try HTTPSDeviceClaimAPI(
            controlAuthority: URL(string: "https://control.example")!,
            transport: transport
        )
        let authorization = try CompanionAuthorizationTicket(bearerToken: "token")
        let ticket = try DeviceClaimTicket.parse(Data(document.utf8))
        await expectAsyncThrows(DeviceClaimAPIError.invalidResponse) {
            try await api.begin(using: ticket, authorization: authorization,
                                now: Date())
        }
    }

    private static func response(_ body: Data) -> FakeHTTPResponse {
        FakeHTTPResponse(
            data: body,
            status: 200,
            headers: ["Content-Type": "application/json",
                      "Cache-Control": "no-store"]
        )
    }
}

private struct FakeHTTPResponse {
    let data: Data
    let status: Int
    let headers: [String: String]
}

@MainActor
private final class FakeDeviceClaimHTTPTransport: DeviceClaimHTTPTransport {
    private var responses: [FakeHTTPResponse]
    private(set) var requests: [URLRequest] = []

    init(responses: [FakeHTTPResponse]) { self.responses = responses }

    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        requests.append(request)
        guard !responses.isEmpty else { throw DeviceClaimAPIError.transport }
        let response = responses.removeFirst()
        let http = HTTPURLResponse(
            url: request.url!, statusCode: response.status,
            httpVersion: "HTTP/1.1", headerFields: response.headers
        )!
        return (response.data, http)
    }
}
