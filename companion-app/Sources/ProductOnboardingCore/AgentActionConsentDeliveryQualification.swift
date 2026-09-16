import CryptoKit
import Foundation

public enum AgentActionConsentDeliveryQualificationError:
    Error, Equatable, Sendable {
    case invalidConfiguration
    case invalidSequence
    case observationUnavailable
    case observationAlreadyExported
}

/// Opt-in observer seam for a controlled delivery qualification. Ordinary App
/// composition leaves this nil. It cannot approve/deny an action or access an
/// account/provider token.
@MainActor
public protocol AgentActionConsentDeliveryObserving: AnyObject {
    func actionConsentDidReceiveContentFreeWake(
        inForeground: Bool,
        at: Date
    )

    func actionConsentDidEnterForeground(
        deviceID: String,
        ownerRevision: UInt64,
        at: Date
    )

    func actionConsentDidPresentAuthenticatedTicket(
        _ presentation: AgentActionConsentPresentation,
        at: Date
    )
}

public struct AgentActionConsentDeliveryQualificationConfiguration:
    Sendable {
    public let qualificationID: String
    public let qualificationNonce: String
    public let environment: String
    public let developmentOnly: Bool
    public let platform: String
    public let applicationID: String
    public let appBuildID: String
    public let appBinarySHA256: String
    public let expectedChallengeID: String
    public let expectedDeviceID: String
    public let expectedOwnerRevision: UInt64

    public init(
        qualificationID: String,
        qualificationNonce: String,
        environment: String,
        developmentOnly: Bool,
        platform: String,
        applicationID: String,
        appBuildID: String,
        appBinarySHA256: String,
        expectedChallengeID: String,
        expectedDeviceID: String,
        expectedOwnerRevision: UInt64
    ) throws {
        guard Self.validIdentifier(qualificationID, maximum: 64),
              Self.canonicalBase64URL128(qualificationNonce),
              environment == "staging" || environment == "production",
              !developmentOnly || environment == "staging",
              platform == "ios",
              Self.validIdentifier(applicationID, maximum: 128),
              Self.validIdentifier(appBuildID, maximum: 64),
              Self.validSHA256(appBinarySHA256),
              Self.canonicalBase64URL128(expectedChallengeID),
              Self.validIdentifier(expectedDeviceID, maximum: 64),
              expectedOwnerRevision > 0,
              expectedOwnerRevision <= UInt64(UInt32.max) else {
            throw AgentActionConsentDeliveryQualificationError
                .invalidConfiguration
        }
        self.qualificationID = qualificationID
        self.qualificationNonce = qualificationNonce
        self.environment = environment
        self.developmentOnly = developmentOnly
        self.platform = platform
        self.applicationID = applicationID
        self.appBuildID = appBuildID
        self.appBinarySHA256 = appBinarySHA256
        self.expectedChallengeID = expectedChallengeID
        self.expectedDeviceID = expectedDeviceID
        self.expectedOwnerRevision = expectedOwnerRevision
    }

    fileprivate static func validIdentifier(
        _ value: String,
        maximum: Int
    ) -> Bool {
        let bytes = value.utf8
        return !bytes.isEmpty && bytes.count <= maximum && bytes.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) ||
            ($0 >= 0x41 && $0 <= 0x5A) ||
            ($0 >= 0x61 && $0 <= 0x7A) ||
            $0 == 0x3A || $0 == 0x2D || $0 == 0x5F || $0 == 0x2E
        }
    }

    fileprivate static func validSHA256(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66)
        }
    }

    fileprivate static func canonicalBase64URL128(_ value: String) -> Bool {
        let alphabet = Array(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8
        )
        let bytes = Array(value.utf8)
        guard bytes.count == 22 else { return false }
        for (index, byte) in bytes.enumerated() {
            guard let decoded = alphabet.firstIndex(of: byte) else {
                return false
            }
            if index == bytes.count - 1 && (decoded & 0x0F) != 0 {
                return false
            }
        }
        return true
    }
}

/// Records one content-minimized qualification sequence. The exported bytes
/// are unsigned observation input: a live M70 receipt must additionally bind
/// platform attestation, a signed App artifact and an M69 live receipt.
@MainActor
public final class AgentActionConsentDeliveryQualificationRecorder:
    AgentActionConsentDeliveryObserving {
    public static let schema = 1
    public static let maximumWakeToFetchMilliseconds: UInt64 = 120_000
    private static let maximumUnixMilliseconds: Double = 253_402_300_799_999

    private let configuration:
        AgentActionConsentDeliveryQualificationConfiguration
    private var backgroundWakeCount: UInt32 = 0
    private var wakeReceivedAt: UInt64?
    private var foregroundEnteredAt: UInt64?
    private var authenticatedFetchPresentedAt: UInt64?
    private var armed = false
    private var failed = false
    private var exported = false

    public init(
        configuration: AgentActionConsentDeliveryQualificationConfiguration
    ) {
        self.configuration = configuration
    }

    /// Qualification control calls this immediately before placing the App in
    /// the background. Lifecycle events before arming are deliberately ignored.
    public func arm() throws {
        guard !armed, !exported, !failed, backgroundWakeCount == 0,
              wakeReceivedAt == nil, foregroundEnteredAt == nil,
              authenticatedFetchPresentedAt == nil else {
            throw AgentActionConsentDeliveryQualificationError.invalidSequence
        }
        armed = true
    }

    public func actionConsentDidReceiveContentFreeWake(
        inForeground: Bool,
        at: Date
    ) {
        guard armed else { return }
        guard !exported, !failed, !inForeground,
              foregroundEnteredAt == nil,
              authenticatedFetchPresentedAt == nil,
              let timestamp = Self.unixMilliseconds(at),
              backgroundWakeCount < 8 else {
            failed = true
            return
        }
        backgroundWakeCount += 1
        if wakeReceivedAt == nil {
            wakeReceivedAt = timestamp
        }
    }

    public func actionConsentDidEnterForeground(
        deviceID: String,
        ownerRevision: UInt64,
        at: Date
    ) {
        guard armed else { return }
        guard !exported, !failed, backgroundWakeCount > 0,
              foregroundEnteredAt == nil,
              authenticatedFetchPresentedAt == nil,
              deviceID == configuration.expectedDeviceID,
              ownerRevision == configuration.expectedOwnerRevision,
              let timestamp = Self.unixMilliseconds(at),
              let wakeReceivedAt,
              timestamp >= wakeReceivedAt,
              timestamp - wakeReceivedAt <=
                Self.maximumWakeToFetchMilliseconds else {
            failed = true
            return
        }
        foregroundEnteredAt = timestamp
    }

    public func actionConsentDidPresentAuthenticatedTicket(
        _ presentation: AgentActionConsentPresentation,
        at: Date
    ) {
        guard armed else { return }
        guard !exported, !failed,
              authenticatedFetchPresentedAt == nil,
              presentation.challengeID == configuration.expectedChallengeID,
              presentation.deviceID == configuration.expectedDeviceID,
              presentation.ownerRevision ==
                configuration.expectedOwnerRevision,
              let timestamp = Self.unixMilliseconds(at),
              let wakeReceivedAt, let foregroundEnteredAt,
              timestamp >= foregroundEnteredAt,
              timestamp - wakeReceivedAt <=
                Self.maximumWakeToFetchMilliseconds else {
            failed = true
            return
        }
        authenticatedFetchPresentedAt = timestamp
    }

    public func exportCanonicalObservation() throws -> Data {
        guard !exported else {
            throw AgentActionConsentDeliveryQualificationError
                .observationAlreadyExported
        }
        guard !failed, backgroundWakeCount > 0,
              let wakeReceivedAt,
              let foregroundEnteredAt,
              let authenticatedFetchPresentedAt else {
            throw AgentActionConsentDeliveryQualificationError
                .observationUnavailable
        }
        let latency = authenticatedFetchPresentedAt - wakeReceivedAt
        guard latency <= Self.maximumWakeToFetchMilliseconds else {
            throw AgentActionConsentDeliveryQualificationError.invalidSequence
        }
        let challengeBinding = Self.bindingDigest(
            domain: "XIAOZHI-M70-CHALLENGE-BINDING-V1\0",
            nonce: configuration.qualificationNonce,
            values: [configuration.expectedChallengeID]
        )
        let deviceBinding = Self.bindingDigest(
            domain: "XIAOZHI-M70-DEVICE-BINDING-V1\0",
            nonce: configuration.qualificationNonce,
            values: [
                configuration.expectedDeviceID,
                String(configuration.expectedOwnerRevision),
            ]
        )
        let development = configuration.developmentOnly ? "true" : "false"
        let body = "{" +
            "\"schema\":1," +
            "\"qualification_id\":\"\(configuration.qualificationID)\"," +
            "\"qualification_nonce\":\"\(configuration.qualificationNonce)\"," +
            "\"environment\":\"\(configuration.environment)\"," +
            "\"development_only\":\(development)," +
            "\"platform\":\"\(configuration.platform)\"," +
            "\"application_id\":\"\(configuration.applicationID)\"," +
            "\"app_build_id\":\"\(configuration.appBuildID)\"," +
            "\"app_binary_sha256\":\"\(configuration.appBinarySHA256)\"," +
            "\"wake_contract\":\"\(AgentActionConsentWake.contract)\"," +
            "\"content_free_wake\":true," +
            "\"background_network_request\":false," +
            "\"background_wake_count\":\(backgroundWakeCount)," +
            "\"wake_received_at_unix_ms\":\(wakeReceivedAt)," +
            "\"foreground_entered_at_unix_ms\":\(foregroundEnteredAt)," +
            "\"authenticated_fetch_presented_at_unix_ms\":" +
                "\(authenticatedFetchPresentedAt)," +
            "\"wake_to_fetch_ms\":\(latency)," +
            "\"challenge_binding_sha256\":\"\(challengeBinding)\"," +
            "\"device_binding_sha256\":\"\(deviceBinding)\"," +
            "\"decision_issued\":false}\n"
        exported = true
        armed = false
        return Data(body.utf8)
    }

    private static func unixMilliseconds(_ date: Date) -> UInt64? {
        let value = date.timeIntervalSince1970 * 1_000
        guard value.isFinite, value >= 0,
              value <= maximumUnixMilliseconds else { return nil }
        return UInt64(value.rounded(.down))
    }

    private static func bindingDigest(
        domain: String,
        nonce: String,
        values: [String]
    ) -> String {
        var payload = Data(domain.utf8)
        payload.append(Data(nonce.utf8))
        for value in values {
            payload.append(0)
            payload.append(Data(value.utf8))
        }
        return SHA256.hash(data: payload).map {
            String(format: "%02x", $0)
        }.joined()
    }
}
