import Foundation
import ProductOnboardingCore

struct OnboardingFlowTests {
    private let flowID = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
    private let startTime = Date(timeIntervalSince1970: 1_700_000_000)
    private let device = OnboardingDevice(name: "XA-12ABEF")
    private var claimRequest: DeviceClaimRequest {
        DeviceClaimRequest(
            requestID: "AAECAwQFBgcICQoLDA0ODw",
            deviceID: "xz-device-1", status: .pending,
            expiresAt: startTime.addingTimeInterval(300)
        )
    }

    func run() throws {
        try happyPathRequiresAuthenticatedOnlineObservation()
        try candidateFailureReturnsToManualEntryWithoutAutomaticRetry()
        try sessionFailureClearsEverythingAndRequiresExplicitRetry()
        try timeoutLockoutCancelAndStaleCallbacksFailClosed()
    }

    private func happyPathRequiresAuthenticatedOnlineObservation() throws {
        var flow = OnboardingFlow()
        try check(try flow.start(id: flowID) == [.showPhysicalInstructions])
        try check(
            try flow.handle(.instructionsAccepted, flowID: flowID, now: startTime) == []
        )
        try check(flow.state == .waitingForPhysicalWindow)
        try check(
            try flow.handle(.physicalWindowConfirmed, flowID: flowID, now: startTime)
                == [.startScanner]
        )
        try check(
            try flow.handle(.qrAccepted(device), flowID: flowID, now: startTime)
                == [.connectTransport]
        )
        try check(
            try flow.handle(.transportConnected, flowID: flowID, now: startTime)
                == [.readDeviceClaim]
        )
        try check(flow.state == .readingDeviceClaim("XA-12ABEF"))
        try check(
            try flow.handle(
                .deviceClaimRead("xz-device-1"), flowID: flowID,
                now: startTime
            ) == [.beginDeviceClaim]
        )
        try check(
            try flow.handle(
                .claimIntentRegistered(claimRequest), flowID: flowID,
                now: startTime
            ) == [.requestWiFiCredentials]
        )
        try check(flow.state == .enteringWiFi("XA-12ABEF", nil))
        try check(
            try flow.handle(.wifiSubmitted, flowID: flowID, now: startTime)
                == [.submitWiFiCredentials]
        )
        try check(
            try flow.handle(.configurationApplied, flowID: flowID, now: startTime)
                == [.clearWiFiCredentials]
        )
        try check(flow.state == .waitingForNetwork("XA-12ABEF"))

        try check(
            try flow.handle(.networkJoined, flowID: flowID, now: startTime)
                == [.disconnectTransport, .scheduleOwnershipStatusPoll]
        )
        try check(flow.state == .verifyingOwnership("XA-12ABEF"))
        let staleStatus = DeviceClaimRequest(
            requestID: "AQECAwQFBgcICQoLDA0ODw",
            deviceID: claimRequest.deviceID, status: .bound,
            expiresAt: startTime.addingTimeInterval(299)
        )
        try check(
            try flow.handle(
                .ownershipStatus(staleStatus), flowID: flowID, now: startTime
            ) == []
        )
        try check(flow.state == .verifyingOwnership("XA-12ABEF"))
        let pendingStatus = DeviceClaimRequest(
            requestID: claimRequest.requestID,
            deviceID: claimRequest.deviceID, status: .pending,
            expiresAt: startTime.addingTimeInterval(299)
        )
        try check(
            try flow.handle(
                .ownershipStatus(pendingStatus), flowID: flowID, now: startTime
            )
                == [.scheduleOwnershipStatusPoll]
        )
        let boundStatus = DeviceClaimRequest(
            requestID: claimRequest.requestID,
            deviceID: claimRequest.deviceID, status: .bound,
            expiresAt: startTime.addingTimeInterval(298)
        )
        try check(
            try flow.handle(
                .ownershipStatus(boundStatus), flowID: flowID, now: startTime
            )
                == [.disconnectTransport, .clearAllSecrets]
        )
        try check(flow.state == .succeeded("XA-12ABEF"))
        try check(flow.deadline == nil)
    }

    private func candidateFailureReturnsToManualEntryWithoutAutomaticRetry() throws {
        var flow = try flowAtApplying()
        try check(
            try flow.handle(
                .candidateRejected(.authentication), flowID: flowID, now: startTime
            ) == [.clearWiFiCredentials, .requestWiFiCredentials]
        )
        try check(flow.state == .enteringWiFi("XA-12ABEF", .authentication))
    }

    private func sessionFailureClearsEverythingAndRequiresExplicitRetry() throws {
        var flow = try flowAtConnecting()
        try check(
            try flow.handle(
                .sessionAuthenticationFailed, flowID: flowID, now: startTime
            ) == [.disconnectTransport, .clearAllSecrets]
        )
        try check(flow.state == .recoverableFailure(.sessionAuthentication))
        try check(
            try flow.handle(.retry, flowID: flowID, now: startTime) == [.startScanner]
        )
        try check(flow.state == .scanning)

        var applying = try flowAtApplying()
        try check(
            try applying.handle(
                .sessionAuthenticationFailed, flowID: flowID, now: startTime
            ) == [.disconnectTransport, .clearAllSecrets]
        )
        try check(applying.state == .recoverableFailure(.sessionAuthentication))

        var verifying = try flowAtApplying()
        try verifying.handle(.configurationApplied, flowID: flowID, now: startTime)
        try check(
            try verifying.handle(.transportFailed, flowID: flowID, now: startTime)
                == [.disconnectTransport, .clearAllSecrets]
        )
        try check(verifying.state == .recoverableFailure(.transportUnavailable))

        var claimReading = try flowAtConnecting()
        try claimReading.handle(.transportConnected, flowID: flowID, now: startTime)
        try check(
            try claimReading.handle(
                .sessionAuthenticationFailed, flowID: flowID, now: startTime
            ) == [.disconnectTransport, .clearAllSecrets]
        )
    }

    private func timeoutLockoutCancelAndStaleCallbacksFailClosed() throws {
        var timedOut = try flowAtConnecting()
        try check(
            try timedOut.handle(
                .transportConnected,
                flowID: flowID,
                now: startTime.addingTimeInterval(OnboardingFlow.defaultWindowDuration)
            ) == [.disconnectTransport, .clearAllSecrets]
        )
        try check(timedOut.state == .requiresPhysicalPresence(.timeout))

        var locked = try flowAtConnecting()
        try check(
            try locked.handle(.deviceLockedOut, flowID: flowID, now: startTime)
                == [.disconnectTransport, .clearAllSecrets]
        )
        try check(locked.state == .requiresPhysicalPresence(.lockedOut))

        var cancelled = try flowAtConnecting()
        try check(
            try cancelled.handle(.cancel, flowID: flowID, now: startTime)
                == [.disconnectTransport, .clearAllSecrets]
        )
        try check(cancelled.state == .cancelled)

        var current = try flowAtConnecting()
        try check(
            try current.handle(.transportConnected, flowID: UUID(), now: startTime) == []
        )
        try check(current.state == .connecting("XA-12ABEF"))
    }

    private func flowAtConnecting() throws -> OnboardingFlow {
        var flow = OnboardingFlow()
        try flow.start(id: flowID)
        try flow.handle(.instructionsAccepted, flowID: flowID, now: startTime)
        try flow.handle(.physicalWindowConfirmed, flowID: flowID, now: startTime)
        try flow.handle(.qrAccepted(device), flowID: flowID, now: startTime)
        return flow
    }

    private func flowAtApplying() throws -> OnboardingFlow {
        var flow = try flowAtConnecting()
        try flow.handle(.transportConnected, flowID: flowID, now: startTime)
        try flow.handle(
            .deviceClaimRead("xz-device-1"), flowID: flowID, now: startTime
        )
        try flow.handle(
            .claimIntentRegistered(claimRequest), flowID: flowID, now: startTime
        )
        try flow.handle(.wifiSubmitted, flowID: flowID, now: startTime)
        return flow
    }
}
