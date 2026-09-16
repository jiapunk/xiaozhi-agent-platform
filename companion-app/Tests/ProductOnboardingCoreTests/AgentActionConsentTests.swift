import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import ProductOnboardingCore

enum AgentActionConsentTests {
    private static let now = Date(timeIntervalSince1970: 1_786_233_600)
    private static let challengeID = "AAECAwQFBgcICQoLDA0ODw"
    private static let canonical = Data(
        #"{"version":1,"challenge_id":"AAECAwQFBgcICQoLDA0ODw","device_id":"xz-device-1","owner_revision":42,"session_id":"voice:xz-device-1","request_id":7,"capability":"device.set_indicator","arguments":{"on":true},"expires_at_unix":1786233620}"#.utf8
    )

    @MainActor
    static func run() async throws {
        try validExactActionIsOneUse()
        try rejectsMutationAndNonCanonicalInput()
        try rejectsWrongOwnerDeviceAndTime()
        try await concurrentConsumeHasOneWinner()
        try await apiFetchesExactOwnerInbox()
        try await apiSendsExactDecisionAndValidatesAck()
    }

    private static func ticket() throws -> AgentActionConsentTicket {
        try AgentActionConsentTicket.parse(
            canonical,
            expectedDeviceID: "xz-device-1",
            expectedOwnerRevision: 42,
            now: now
        )
    }

    private static func validExactActionIsOneUse() throws {
        let value = try ticket()
        try check(value.challengeID == challengeID)
        try check(value.requestID == 7)
        try check(value.sessionID == "voice:xz-device-1")
        try check(value.action.indicatorOn)
        let decision = try value.consume(.approve, now: now)
        try check(
            decision.body == Data(
                #"{"version":1,"challenge_id":"AAECAwQFBgcICQoLDA0ODw","device_id":"xz-device-1","owner_revision":42,"session_id":"voice:xz-device-1","request_id":7,"capability":"device.set_indicator","arguments":{"on":true},"decision":"approve"}"#.utf8
            )
        )
        try expectThrows(AgentActionConsentContractError.alreadyConsumed) {
            try value.consume(.deny, now: now)
        }
    }

    private static func rejectsMutationAndNonCanonicalInput() throws {
        let exactOff = Data(String(decoding: canonical, as: UTF8.self)
            .replacingOccurrences(of: #""on":true"#, with: #""on":false"#)
            .utf8)
        let offTicket = try AgentActionConsentTicket.parse(
            exactOff, expectedDeviceID: "xz-device-1",
            expectedOwnerRevision: 42, now: now
        )
        try check(!offTicket.action.indicatorOn)
        let bound = try offTicket.consume(.approve, now: now)
        try check(String(decoding: bound.body, as: UTF8.self).contains(
            #""arguments":{"on":false}"#
        ))
        let invalid = [
            Data(String(decoding: canonical, as: UTF8.self)
                .replacingOccurrences(
                    of: #""device.set_indicator"#,
                    with: #""shell.execute"#
                ).utf8),
            Data((String(decoding: canonical, as: UTF8.self) + "\n").utf8),
            Data(String(decoding: canonical, as: UTF8.self)
                .replacingOccurrences(
                    of: #""expires_at_unix":1786233620"#,
                    with: #""expires_at_unix":1786233620,"extra":false"#
                ).utf8),
        ]
        try expectThrows(AgentActionConsentContractError.invalidCapability) {
            try AgentActionConsentTicket.parse(
                invalid[0], expectedDeviceID: "xz-device-1",
                expectedOwnerRevision: 42, now: now
            )
        }
        try expectThrows(AgentActionConsentContractError.invalidJSON) {
            try AgentActionConsentTicket.parse(
                invalid[1], expectedDeviceID: "xz-device-1",
                expectedOwnerRevision: 42, now: now
            )
        }
        try expectThrows(AgentActionConsentContractError.invalidFields) {
            try AgentActionConsentTicket.parse(
                invalid[2], expectedDeviceID: "xz-device-1",
                expectedOwnerRevision: 42, now: now
            )
        }
    }

    private static func rejectsWrongOwnerDeviceAndTime() throws {
        let oversizedRevision = Data(String(decoding: canonical, as: UTF8.self)
            .replacingOccurrences(
                of: #""owner_revision":42"#,
                with: #""owner_revision":4294967296"#
            ).utf8)
        try expectThrows(AgentActionConsentContractError.invalidOwnerRevision) {
            try AgentActionConsentTicket.parse(
                oversizedRevision, expectedDeviceID: "xz-device-1",
                expectedOwnerRevision: 4_294_967_296, now: now
            )
        }
        try expectThrows(AgentActionConsentContractError.deviceMismatch) {
            try AgentActionConsentTicket.parse(
                canonical, expectedDeviceID: "xz-device-2",
                expectedOwnerRevision: 42, now: now
            )
        }
        try expectThrows(AgentActionConsentContractError.ownerRevisionMismatch) {
            try AgentActionConsentTicket.parse(
                canonical, expectedDeviceID: "xz-device-1",
                expectedOwnerRevision: 43, now: now
            )
        }
        try expectThrows(AgentActionConsentContractError.expired) {
            try AgentActionConsentTicket.parse(
                canonical, expectedDeviceID: "xz-device-1",
                expectedOwnerRevision: 42,
                now: Date(timeIntervalSince1970: 1_786_233_620)
            )
        }
        try expectThrows(AgentActionConsentContractError.invalidExpiry) {
            try AgentActionConsentTicket.parse(
                canonical, expectedDeviceID: "xz-device-1",
                expectedOwnerRevision: 42,
                now: Date(timeIntervalSince1970: 1_786_233_580)
            )
        }
    }

    private static func concurrentConsumeHasOneWinner() async throws {
        let value = try ticket()
        let outcomes = await withTaskGroup(of: Bool.self, returning: [Bool].self) {
            group in
            for _ in 0..<32 {
                group.addTask {
                    (try? value.consume(.approve, now: now)) != nil
                }
            }
            var values: [Bool] = []
            for await outcome in group { values.append(outcome) }
            return values
        }
        try check(outcomes.filter { $0 }.count == 1)
        try check(outcomes.filter { !$0 }.count == 31)
    }

    @MainActor
    private static func apiFetchesExactOwnerInbox() async throws {
        let transport = FakeActionConsentTransport(
            responseData: canonical,
            headers: [
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
                "X-Xiaozhi-Action-Consent": "xz-action-consent-v1",
            ]
        )
        let api = try AgentActionConsentAPI(
            authority: URL(string: "https://control.example")!,
            transport: transport
        )
        let pending = try await api.fetchPending(
            deviceID: "xz-device-1", ownerRevision: 42,
            bearerToken: "v1.account.action-consent", now: now
        )
        try check(pending?.challengeID == challengeID)
        try check(pending?.action.indicatorOn == true)
        let request = try transport.onlyRequest()
        try check(
            request.url?.absoluteString ==
                "https://control.example/v1/devices/xz-device-1/action-consents/pending"
        )
        try check(request.httpMethod == "GET")
        try check(request.httpBody == nil)
        try check(request.value(forHTTPHeaderField: "Content-Length") == "0")
        try check(request.value(forHTTPHeaderField: "Cache-Control") == "no-store")
        try check(
            request.value(forHTTPHeaderField: "Authorization") ==
                "Bearer v1.account.action-consent"
        )

        let emptyTransport = FakeActionConsentTransport(
            responseData: Data(),
            headers: [
                "Cache-Control": "no-store",
                "X-Xiaozhi-Action-Consent": "xz-action-consent-v1",
            ],
            statusCode: 204
        )
        let emptyAPI = try AgentActionConsentAPI(
            authority: URL(string: "https://control.example")!,
            transport: emptyTransport
        )
        let empty = try await emptyAPI.fetchPending(
            deviceID: "xz-device-1", ownerRevision: 42,
            bearerToken: "v1.account.action-consent", now: now
        )
        try check(empty == nil)

        await expectAsyncThrows(
            AgentActionConsentAPIError.invalidDeviceBinding
        ) {
            try await api.fetchPending(
                deviceID: "../other", ownerRevision: 42,
                bearerToken: "v1.account.action-consent", now: now
            )
        }
    }

    @MainActor
    private static func apiSendsExactDecisionAndValidatesAck() async throws {
        let transport = FakeActionConsentTransport(
            responseData: Data(
                #"{"version":1,"challenge_id":"AAECAwQFBgcICQoLDA0ODw","status":"accepted"}"#.utf8
            ),
            headers: [
                "Cache-Control": "no-store",
                "X-Xiaozhi-Action-Consent": "xz-action-consent-v1",
            ]
        )
        let api = try AgentActionConsentAPI(
            authority: URL(string: "https://control.example")!,
            transport: transport
        )
        let value = try ticket()
        try await api.submit(
            ticket: value,
            decision: .deny,
            bearerToken: "v1.account.action-consent",
            now: now
        )
        let request = try transport.onlyRequest()
        try check(
            request.url?.absoluteString ==
                "https://control.example/v1/devices/xz-device-1/action-consents/AAECAwQFBgcICQoLDA0ODw/decision"
        )
        try check(request.httpMethod == "POST")
        try check(
            request.value(forHTTPHeaderField: "Content-Length") ==
                String(request.httpBody!.count)
        )
        try check(request.value(forHTTPHeaderField: "Cache-Control") == "no-store")
        try check(
            request.value(forHTTPHeaderField: "X-Xiaozhi-Action-Consent") ==
                "xz-action-consent-v1"
        )
        try check(
            request.value(forHTTPHeaderField: "Authorization") ==
                "Bearer v1.account.action-consent"
        )
        try check(
            request.httpBody == Data(
                #"{"version":1,"challenge_id":"AAECAwQFBgcICQoLDA0ODw","device_id":"xz-device-1","owner_revision":42,"session_id":"voice:xz-device-1","request_id":7,"capability":"device.set_indicator","arguments":{"on":true},"decision":"deny"}"#.utf8
            )
        )

        let unused = try ticket()
        await expectAsyncThrows(AgentActionConsentAPIError.invalidBearerToken) {
            try await api.submit(
                ticket: unused, decision: .approve,
                bearerToken: "bad token", now: now
            )
        }
        _ = try unused.consume(.deny, now: now)
    }
}

@MainActor
private final class FakeActionConsentTransport: DeviceClaimHTTPTransport {
    private let responseData: Data
    private let headers: [String: String]
    private let statusCode: Int
    private var requests: [URLRequest] = []

    init(
        responseData: Data,
        headers: [String: String],
        statusCode: Int = 200
    ) {
        self.responseData = responseData
        self.headers = headers
        self.statusCode = statusCode
    }

    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        requests.append(request)
        let response = HTTPURLResponse(
            url: request.url!, statusCode: statusCode,
            httpVersion: "HTTP/1.1", headerFields: headers
        )!
        return (responseData, response)
    }

    func onlyRequest() throws -> URLRequest {
        try check(requests.count == 1)
        return requests[0]
    }
}
