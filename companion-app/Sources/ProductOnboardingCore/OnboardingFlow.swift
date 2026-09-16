import Foundation

public enum WiFiCandidateFailure: Equatable, Sendable {
    case authentication
    case networkNotFound
    case unknown
}

public enum OnboardingFailure: Equatable, Sendable {
    case invalidQRCode
    case cameraPermission
    case transportUnavailable
    case sessionAuthentication
    case deviceClaimUnavailable
    case companionAuthorization
    case ownershipConflict
    case ownershipVerification
    case candidate(WiFiCandidateFailure)
    case windowExpired
    case lockedOut
    case timeout
}

public enum OnboardingState: Equatable, Sendable {
    case idle
    case instructions
    case waitingForPhysicalWindow
    case scanning
    case connecting(String)
    case readingDeviceClaim(String)
    case registeringOwnership(String, String)
    case enteringWiFi(String, WiFiCandidateFailure?)
    case applying(String)
    case waitingForNetwork(String)
    case verifyingOwnership(String)
    case succeeded(String)
    case recoverableFailure(OnboardingFailure)
    case requiresPhysicalPresence(OnboardingFailure)
    case cancelled
}

public enum OnboardingEvent: Equatable, Sendable {
    case instructionsAccepted
    case physicalWindowConfirmed
    case qrAccepted(OnboardingDevice)
    case invalidQR
    case cameraPermissionDenied
    case transportConnected
    case deviceClaimRead(String)
    case claimIntentRegistered(DeviceClaimRequest)
    case claimRegistrationFailed(OnboardingFailure)
    case transportFailed
    case sessionAuthenticationFailed
    case wifiSubmitted
    case configurationApplied
    case networkJoined
    case ownershipStatus(DeviceClaimRequest)
    case candidateRejected(WiFiCandidateFailure)
    case windowExpired
    case deviceLockedOut
    case retry
    case cancel
}

public enum OnboardingCommand: Equatable, Sendable {
    case showPhysicalInstructions
    case startScanner
    case connectTransport
    case readDeviceClaim
    case beginDeviceClaim
    case requestWiFiCredentials
    case submitWiFiCredentials
    case clearWiFiCredentials
    case scheduleOwnershipStatusPoll
    case clearAllSecrets
    case disconnectTransport
}

public enum OnboardingFlowError: Error, Equatable, Sendable {
    case alreadyActive
    case noActiveFlow
    case invalidTransition
}

public struct OnboardingFlow: Sendable {
    public static let defaultWindowDuration: TimeInterval = 5 * 60

    public private(set) var state: OnboardingState = .idle
    public private(set) var flowID: UUID?
    public private(set) var deadline: Date?
    public private(set) var claimRequest: DeviceClaimRequest?
    public let windowDuration: TimeInterval

    public init(windowDuration: TimeInterval = defaultWindowDuration) {
        precondition(windowDuration >= 30 && windowDuration <= 10 * 60)
        self.windowDuration = windowDuration
    }

    @discardableResult
    public mutating func start(id: UUID = UUID()) throws -> [OnboardingCommand] {
        guard !isActive else {
            throw OnboardingFlowError.alreadyActive
        }
        flowID = id
        deadline = nil
        claimRequest = nil
        state = .instructions
        return [.showPhysicalInstructions]
    }

    @discardableResult
    public mutating func handle(_ event: OnboardingEvent, flowID suppliedID: UUID,
                                now: Date) throws -> [OnboardingCommand] {
        guard let activeID = flowID else {
            throw OnboardingFlowError.noActiveFlow
        }
        guard activeID == suppliedID else {
            return []
        }
        if isWindowTimedOut(at: now), event != .cancel {
            state = .requiresPhysicalPresence(.timeout)
            deadline = nil
            claimRequest = nil
            return [.disconnectTransport, .clearAllSecrets]
        }
        switch (state, event) {
        case (.instructions, .instructionsAccepted):
            state = .waitingForPhysicalWindow
            return []
        case (.waitingForPhysicalWindow, .physicalWindowConfirmed):
            deadline = now.addingTimeInterval(windowDuration)
            state = .scanning
            return [.startScanner]
        case (.scanning, .qrAccepted(let device)):
            state = .connecting(device.name)
            return [.connectTransport]
        case (.scanning, .invalidQR):
            state = .recoverableFailure(.invalidQRCode)
            return [.clearAllSecrets]
        case (.scanning, .cameraPermissionDenied):
            state = .recoverableFailure(.cameraPermission)
            return [.clearAllSecrets]
        case (.connecting(let name), .transportConnected):
            state = .readingDeviceClaim(name)
            return [.readDeviceClaim]
        case (.readingDeviceClaim(let name), .deviceClaimRead(let deviceID))
            where DeviceClaimTicket.validIdentifier(deviceID):
            state = .registeringOwnership(name, deviceID)
            return [.beginDeviceClaim]
        case (.registeringOwnership(let name, let expectedDeviceID),
              .claimIntentRegistered(let request))
            where request.deviceID == expectedDeviceID &&
                  request.status == .pending:
            claimRequest = request
            state = .enteringWiFi(name, nil)
            return [.requestWiFiCredentials]
        case (.readingDeviceClaim, .claimRegistrationFailed(let failure)):
            state = .recoverableFailure(failure)
            claimRequest = nil
            return [.disconnectTransport, .clearAllSecrets]
        case (.registeringOwnership, .claimRegistrationFailed(let failure)):
            state = .recoverableFailure(failure)
            claimRequest = nil
            return [.disconnectTransport, .clearAllSecrets]
        case (.readingDeviceClaim, .transportFailed):
            state = .recoverableFailure(.transportUnavailable)
            claimRequest = nil
            return [.disconnectTransport, .clearAllSecrets]
        case (.registeringOwnership, .transportFailed):
            state = .recoverableFailure(.transportUnavailable)
            claimRequest = nil
            return [.disconnectTransport, .clearAllSecrets]
        case (.connecting, .transportFailed):
            state = .recoverableFailure(.transportUnavailable)
            return [.disconnectTransport, .clearAllSecrets]
        case (.enteringWiFi, .transportFailed):
            state = .recoverableFailure(.transportUnavailable)
            return [.disconnectTransport, .clearAllSecrets]
        case (.applying, .transportFailed):
            state = .recoverableFailure(.transportUnavailable)
            return [.disconnectTransport, .clearAllSecrets]
        case (.waitingForNetwork, .transportFailed):
            state = .recoverableFailure(.transportUnavailable)
            return [.disconnectTransport, .clearAllSecrets]
        case (.connecting, .sessionAuthenticationFailed):
            state = .recoverableFailure(.sessionAuthentication)
            return [.disconnectTransport, .clearAllSecrets]
        case (.enteringWiFi, .sessionAuthenticationFailed):
            state = .recoverableFailure(.sessionAuthentication)
            return [.disconnectTransport, .clearAllSecrets]
        case (.applying, .sessionAuthenticationFailed):
            state = .recoverableFailure(.sessionAuthentication)
            return [.disconnectTransport, .clearAllSecrets]
        case (.readingDeviceClaim, .sessionAuthenticationFailed):
            state = .recoverableFailure(.sessionAuthentication)
            claimRequest = nil
            return [.disconnectTransport, .clearAllSecrets]
        case (.registeringOwnership, .sessionAuthenticationFailed):
            state = .recoverableFailure(.sessionAuthentication)
            claimRequest = nil
            return [.disconnectTransport, .clearAllSecrets]
        case (.waitingForNetwork, .sessionAuthenticationFailed):
            state = .recoverableFailure(.sessionAuthentication)
            return [.disconnectTransport, .clearAllSecrets]
        case (.enteringWiFi(let name, _), .wifiSubmitted):
            state = .applying(name)
            return [.submitWiFiCredentials]
        case (.applying(let name), .configurationApplied):
            state = .waitingForNetwork(name)
            return [.clearWiFiCredentials]
        case (.waitingForNetwork(let name), .networkJoined):
            guard claimRequest != nil else {
                throw OnboardingFlowError.invalidTransition
            }
            state = .verifyingOwnership(name)
            return [.disconnectTransport, .scheduleOwnershipStatusPoll]
        case (.verifyingOwnership(let name),
              .ownershipStatus(let status))
            where status.requestID == claimRequest?.requestID &&
                  status.deviceID == claimRequest?.deviceID &&
                  now < status.expiresAt:
            if status.status == .pending {
                claimRequest = status
                return [.scheduleOwnershipStatusPoll]
            }
            state = .succeeded(name)
            deadline = nil
            claimRequest = nil
            return [.disconnectTransport, .clearAllSecrets]
        case (.verifyingOwnership, .ownershipStatus):
            /* Ignore a late result for a superseded request in this flow. */
            return []
        case (.applying(let name), .candidateRejected(let reason)):
            state = .enteringWiFi(name, reason)
            return [.clearWiFiCredentials, .requestWiFiCredentials]
        case (.waitingForNetwork(let name), .candidateRejected(let reason)):
            state = .enteringWiFi(name, reason)
            return [.clearWiFiCredentials, .requestWiFiCredentials]
        case (.verifyingOwnership, .claimRegistrationFailed(let failure)):
            state = .recoverableFailure(failure)
            claimRequest = nil
            return [.disconnectTransport, .clearAllSecrets]
        case (.recoverableFailure, .retry):
            state = .scanning
            return [.startScanner]
        case (_, .windowExpired):
            state = .requiresPhysicalPresence(.windowExpired)
            deadline = nil
            claimRequest = nil
            return [.disconnectTransport, .clearAllSecrets]
        case (_, .deviceLockedOut):
            state = .requiresPhysicalPresence(.lockedOut)
            deadline = nil
            claimRequest = nil
            return [.disconnectTransport, .clearAllSecrets]
        case (_, .cancel):
            state = .cancelled
            deadline = nil
            claimRequest = nil
            return [.disconnectTransport, .clearAllSecrets]
        default:
            throw OnboardingFlowError.invalidTransition
        }
    }

    private var isActive: Bool {
        switch state {
        case .instructions, .waitingForPhysicalWindow, .scanning, .connecting,
             .readingDeviceClaim, .registeringOwnership, .enteringWiFi,
             .applying, .waitingForNetwork, .verifyingOwnership:
            return true
        default:
            return false
        }
    }

    private func isWindowTimedOut(at now: Date) -> Bool {
        guard let deadline else { return false }
        return now >= deadline
    }
}
