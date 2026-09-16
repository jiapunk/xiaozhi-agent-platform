import Foundation

public enum ProvisioningProgress: Equatable, Sendable {
    case configurationApplied
    /// The device joined the candidate network. This is deliberately not
    /// product-online proof; the app must still observe the device through an
    /// authenticated product service before completing onboarding.
    case networkJoined
}

public enum ProvisioningTransportError: Error, Equatable, Sendable {
    case unavailable
    case sessionAuthentication
    case candidate(WiFiCandidateFailure)
    case cancelled
}

@MainActor
public protocol ProductProvisioningTransport: AnyObject {
    func connect(using ticket: OnboardingTicket) async throws
    /* Reads xz-claim only after the Security2 session is established. */
    func readDeviceClaim() async throws -> DeviceClaimTicket
    func provision(using credentials: WiFiCredentialTicket,
                   progress: @escaping @MainActor @Sendable (ProvisioningProgress) -> Void)
        async throws
    func disconnect()
}
