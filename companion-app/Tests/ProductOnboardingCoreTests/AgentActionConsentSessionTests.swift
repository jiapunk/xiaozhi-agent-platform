import Foundation
import ProductOnboardingCore

@MainActor
enum AgentActionConsentSessionTests {
    private static let now = Date(timeIntervalSince1970: 1_786_233_600)
    private static let challengeID = "AAECAwQFBgcICQoLDA0ODw"
    private static let canonical = Data(
        #"{"version":1,"challenge_id":"AAECAwQFBgcICQoLDA0ODw","device_id":"xz-device-1","owner_revision":42,"session_id":"voice:xz-device-1","request_id":7,"capability":"device.set_indicator","arguments":{"on":true},"expires_at_unix":1786233620}"#.utf8
    )

    static func run() async throws {
        try accessContractRejectsLongLivedOrWrongBindingValues()
        try await foregroundFlowUsesFreshAccessAndSerializesApproval()
        try await backgroundAndSignOutInvalidateTheExactPrompt()
        try await authorizationFailureCanRetryBeforeTicketConsumption()
        try await uncertainDecisionDeliveryCannotBeReplayed()
        try wakePayloadIsConstantAndContainsNoAuthority()
        try await foregroundWakeOnlyAcceleratesAuthenticatedFetch()
        try await backgroundWakeDoesNotFetch()
        try await qualificationRecorderBindsBackgroundWakeToFetch()
        try qualificationRecorderRejectsForegroundWake()
    }

    private static func ticket() throws -> AgentActionConsentTicket {
        try AgentActionConsentTicket.parse(
            canonical,
            expectedDeviceID: "xz-device-1",
            expectedOwnerRevision: 42,
            now: now
        )
    }

    private static func accessContractRejectsLongLivedOrWrongBindingValues() throws {
        try expectThrows(AgentActionConsentAccessError.invalidBearerToken) {
            try AgentActionConsentAccess(
                bearerToken: "bad token", deviceID: "xz-device-1",
                ownerRevision: 42,
                expiresAt: now.addingTimeInterval(60), now: now
            )
        }
        try expectThrows(AgentActionConsentAccessError.invalidDeviceBinding) {
            try AgentActionConsentAccess(
                bearerToken: "valid-token", deviceID: "../other",
                ownerRevision: 42,
                expiresAt: now.addingTimeInterval(60), now: now
            )
        }
        try expectThrows(AgentActionConsentAccessError.invalidLifetime) {
            try AgentActionConsentAccess(
                bearerToken: "valid-token", deviceID: "xz-device-1",
                ownerRevision: 42,
                expiresAt: now.addingTimeInterval(301), now: now
            )
        }
    }

    private static func foregroundFlowUsesFreshAccessAndSerializesApproval() async throws {
        let service = SessionConsentService(pending: try ticket())
        let access = SessionAccessProvider()
        let session = AgentActionConsentSession(
            service: service, accessProvider: access, now: { now }
        )
        var shown: AgentActionConsentPresentation?
        try session.enterForeground(deviceID: "xz-device-1", ownerRevision: 42)
        try await waitUntil {
            if case .presenting(let prompt) = session.state {
                shown = prompt
                return prompt.challengeID == challengeID && prompt.indicatorOn &&
                    prompt.deviceID == "xz-device-1" && prompt.ownerRevision == 42
            }
            return false
        }
        try check(access.acquireCount == 1)
        try check(access.discardCount >= 2)
        session.approve(challengeID: challengeID)
        session.approve(challengeID: challengeID)
        try await waitUntil {
            guard let shown else { return false }
            return session.state == .completed(shown, .approve)
        }
        try check(service.fetchCount == 1)
        try check(service.submitCount == 1)
        try check(service.lastDecision == .approve)
        try check(access.acquireCount == 2)
    }

    private static func backgroundAndSignOutInvalidateTheExactPrompt() async throws {
        let service = SessionConsentService(pending: try ticket())
        let access = SessionAccessProvider()
        let session = AgentActionConsentSession(
            service: service, accessProvider: access, now: { now }
        )
        try session.enterForeground(deviceID: "xz-device-1", ownerRevision: 42)
        try await waitUntil {
            if case .presenting = session.state { return true }
            return false
        }
        session.leaveForeground()
        try check(session.state == .idle)
        session.approve(challengeID: challengeID)
        await Task.yield()
        try check(service.submitCount == 0)

        try session.enterForeground(deviceID: "xz-device-1", ownerRevision: 42)
        try await waitUntil { service.fetchCount == 2 }
        session.signOut()
        try check(session.state == .signedOut)
        session.deny(challengeID: challengeID)
        await Task.yield()
        try check(service.submitCount == 0)
    }

    private static func authorizationFailureCanRetryBeforeTicketConsumption() async throws {
        let service = SessionConsentService(pending: try ticket())
        let access = SessionAccessProvider()
        access.failAtAcquire = [2]
        let session = AgentActionConsentSession(
            service: service, accessProvider: access, now: { now }
        )
        try session.enterForeground(deviceID: "xz-device-1", ownerRevision: 42)
        try await waitUntil {
            if case .presenting = session.state { return true }
            return false
        }
        session.deny(challengeID: challengeID)
        try await waitUntil {
            if case .authorizationUnavailable = session.state { return true }
            return false
        }
        try check(service.submitCount == 0)
        session.deny(challengeID: challengeID)
        try await waitUntil {
            if case .completed(_, .deny) = session.state { return true }
            return false
        }
        try check(service.submitCount == 1)
    }

    private static func uncertainDecisionDeliveryCannotBeReplayed() async throws {
        let service = SessionConsentService(pending: try ticket())
        service.submitFailure = true
        let access = SessionAccessProvider()
        let session = AgentActionConsentSession(
            service: service, accessProvider: access, now: { now }
        )
        try session.enterForeground(deviceID: "xz-device-1", ownerRevision: 42)
        try await waitUntil {
            if case .presenting = session.state { return true }
            return false
        }
        session.approve(challengeID: challengeID)
        try await waitUntil {
            if case .decisionDeliveryUnknown = session.state { return true }
            return false
        }
        session.approve(challengeID: challengeID)
        await Task.yield()
        try check(service.submitCount == 1)
    }

    private static func wakePayloadIsConstantAndContainsNoAuthority() throws {
        _ = try AgentActionConsentWake.parse(
            AgentActionConsentWake.canonicalPayload
        )
        for data in [
            Data(),
            AgentActionConsentWake.canonicalPayload + Data("\n".utf8),
            Data(
                #"{"version":1,"kind":"action-consent-wake","decision":"approve"}"#.utf8
            ),
        ] {
            try expectAnyThrow { try AgentActionConsentWake.parse(data) }
        }
    }

    private static func foregroundWakeOnlyAcceleratesAuthenticatedFetch()
        async throws {
        let service = SessionConsentService(pending: nil)
        let session = AgentActionConsentSession(
            service: service,
            accessProvider: SessionAccessProvider(),
            now: { now }
        )
        try session.enterForeground(deviceID: "xz-device-1", ownerRevision: 42)
        try await waitUntil { session.state == .noPending }
        service.enqueue(try ticket())
        try session.receiveWake(AgentActionConsentWake.canonicalPayload)
        try await waitUntil {
            if case .presenting(let prompt) = session.state {
                return prompt.challengeID == challengeID
            }
            return false
        }
        try check(service.fetchCount == 2)
        try session.receiveWake(AgentActionConsentWake.canonicalPayload)
        await Task.yield()
        try check(service.fetchCount == 2)
    }

    private static func backgroundWakeDoesNotFetch() async throws {
        let service = SessionConsentService(pending: nil)
        let session = AgentActionConsentSession(
            service: service,
            accessProvider: SessionAccessProvider(),
            now: { now }
        )
        try session.enterForeground(deviceID: "xz-device-1", ownerRevision: 42)
        try await waitUntil { session.state == .noPending }
        session.leaveForeground()
        service.enqueue(try ticket())
        try session.receiveWake(AgentActionConsentWake.canonicalPayload)
        await Task.yield()
        try check(service.fetchCount == 1)
        try session.enterForeground(deviceID: "xz-device-1", ownerRevision: 42)
        try await waitUntil {
            if case .presenting = session.state { return true }
            return false
        }
        try check(service.fetchCount == 2)
    }

    private static func qualificationRecorderBindsBackgroundWakeToFetch()
        async throws {
        var clock = now
        let configuration = try deliveryQualificationConfiguration()
        let recorder = AgentActionConsentDeliveryQualificationRecorder(
            configuration: configuration
        )
        recorder.actionConsentDidReceiveContentFreeWake(
            inForeground: true, at: now.addingTimeInterval(-2)
        )
        recorder.actionConsentDidEnterForeground(
            deviceID: "unrelated-device", ownerRevision: 1,
            at: now.addingTimeInterval(-1)
        )
        try recorder.arm()
        let service = SessionConsentService(pending: try ticket())
        let session = AgentActionConsentSession(
            service: service,
            accessProvider: SessionAccessProvider(),
            deliveryObserver: recorder,
            now: { clock }
        )
        try session.receiveWake(AgentActionConsentWake.canonicalPayload)
        await Task.yield()
        try check(service.fetchCount == 0)
        clock = now.addingTimeInterval(1)
        try session.enterForeground(deviceID: "xz-device-1", ownerRevision: 42)
        try await waitUntil {
            if case .presenting = session.state { return true }
            return false
        }
        let observation = try recorder.exportCanonicalObservation()
        try check(observation.last == 0x0A)
        let raw = try JSONSerialization.jsonObject(with: observation)
        try check(raw is [String: Any])
        let document = raw as! [String: Any]
        try check(document["schema"] as? Int == 1)
        try check(document["content_free_wake"] as? Bool == true)
        try check(document["background_network_request"] as? Bool == false)
        try check(document["decision_issued"] as? Bool == false)
        try check(document["wake_to_fetch_ms"] as? Int == 1_000)
        try check(document["challenge_binding_sha256"] as? String != nil)
        try check(document["device_binding_sha256"] as? String != nil)
        try check(!observation.contains(Data(challengeID.utf8)))
        try check(!observation.contains(Data("xz-device-1".utf8)))
        try check(!observation.contains(Data("indicator".utf8)))
        try expectThrows(
            AgentActionConsentDeliveryQualificationError
                .observationAlreadyExported
        ) {
            try recorder.exportCanonicalObservation()
        }
    }

    private static func qualificationRecorderRejectsForegroundWake() throws {
        let recorder = AgentActionConsentDeliveryQualificationRecorder(
            configuration: try deliveryQualificationConfiguration()
        )
        try recorder.arm()
        recorder.actionConsentDidReceiveContentFreeWake(
            inForeground: true, at: now
        )
        try expectThrows(
            AgentActionConsentDeliveryQualificationError
                .observationUnavailable
        ) {
            try recorder.exportCanonicalObservation()
        }
    }

    private static func deliveryQualificationConfiguration() throws
        -> AgentActionConsentDeliveryQualificationConfiguration {
        try AgentActionConsentDeliveryQualificationConfiguration(
            qualificationID: "m70-fixture-1",
            qualificationNonce: "AAAAAAAAAAAAAAAAAAAAAA",
            environment: "staging",
            developmentOnly: true,
            platform: "ios",
            applicationID: "com.example.product",
            appBuildID: "ios-fixture-1",
            appBinarySHA256: String(repeating: "a", count: 64),
            expectedChallengeID: challengeID,
            expectedDeviceID: "xz-device-1",
            expectedOwnerRevision: 42
        )
    }

    private static func waitUntil(
        _ condition: @MainActor () -> Bool
    ) async throws {
        for _ in 0..<500 {
            if condition() { return }
            await Task.yield()
        }
        try check(false, "timed out waiting for action-consent session state")
    }
}

private enum SessionConsentTestError: Error {
    case unavailable
}

@MainActor
private final class SessionConsentService: AgentActionConsentServicing {
    private var pending: AgentActionConsentTicket?
    private(set) var fetchCount = 0
    private(set) var submitCount = 0
    private(set) var lastDecision: AgentActionConsentDecision?
    var submitFailure = false

    init(pending: AgentActionConsentTicket?) {
        self.pending = pending
    }

    func enqueue(_ ticket: AgentActionConsentTicket) {
        pending = ticket
    }

    func fetchPending(
        deviceID: String,
        ownerRevision: UInt64,
        bearerToken: String,
        now: Date
    ) async throws -> AgentActionConsentTicket? {
        fetchCount += 1
        try check(deviceID == "xz-device-1" && ownerRevision == 42)
        try check(bearerToken == "action-token-\(fetchCount)")
        let result = pending
        pending = nil
        return result
    }

    func submit(
        ticket: AgentActionConsentTicket,
        decision: AgentActionConsentDecision,
        bearerToken: String,
        now: Date
    ) async throws {
        submitCount += 1
        lastDecision = decision
        if submitFailure {
            throw SessionConsentTestError.unavailable
        }
        _ = try ticket.consume(decision, now: now)
    }
}

@MainActor
private final class SessionAccessProvider: AgentActionConsentAccessProviding {
    private(set) var acquireCount = 0
    private(set) var discardCount = 0
    var failAtAcquire: Set<Int> = []

    func acquireActionConsentAccess(
        deviceID: String,
        ownerRevision: UInt64,
        now: Date
    ) async throws -> AgentActionConsentAccess {
        acquireCount += 1
        if failAtAcquire.contains(acquireCount) {
            throw SessionConsentTestError.unavailable
        }
        return try AgentActionConsentAccess(
            bearerToken: "action-token-\(acquireCount)",
            deviceID: deviceID,
            ownerRevision: ownerRevision,
            expiresAt: now.addingTimeInterval(60),
            now: now
        )
    }

    func discardActionConsentAccess() {
        discardCount += 1
    }
}
