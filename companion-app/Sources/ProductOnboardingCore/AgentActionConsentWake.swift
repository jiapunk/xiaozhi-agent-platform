import Foundation

public enum AgentActionConsentWakeError: Error, Equatable, Sendable {
    case invalidSize
    case nonCanonicalPayload
}

/// Provider-neutral wake hint. Platform APNs/FCM adapters may extract these
/// exact bytes, but must never add a challenge, device, action, argument,
/// decision, URL, token or notification text. Receipt grants no authority.
public struct AgentActionConsentWake: Equatable, Sendable {
    public static let contract = "xz-action-consent-wake-v1"
    public static let canonicalPayload = Data(
        #"{"version":1,"kind":"action-consent-wake"}"#.utf8
    )

    public static func parse(_ data: Data) throws -> AgentActionConsentWake {
        guard !data.isEmpty, data.count <= 64 else {
            throw AgentActionConsentWakeError.invalidSize
        }
        guard data == canonicalPayload else {
            throw AgentActionConsentWakeError.nonCanonicalPayload
        }
        return AgentActionConsentWake()
    }

    private init() {}
}
