import Foundation

public enum AgentActionConsentContractError: Error, Equatable, Sendable {
    case invalidSize
    case invalidEncoding
    case invalidJSON
    case invalidFields
    case invalidVersion
    case invalidChallengeID
    case invalidDeviceID
    case invalidSessionID
    case invalidRequestID
    case invalidOwnerRevision
    case invalidCapability
    case invalidExpiry
    case deviceMismatch
    case ownerRevisionMismatch
    case expired
    case alreadyConsumed
}

public enum AgentActionConsentDecision: String, Sendable {
    case approve
    case deny
}

public struct AgentActionConsentAction: Equatable, Sendable {
    public let indicatorOn: Bool
}

public struct AgentActionConsentDecisionRequest: Sendable {
    public let challengeID: String
    public let deviceID: String
    public let ownerRevision: UInt64
    public let body: Data
}

/// One-use, short-lived holder for one exact action proposed by the Agent.
/// The App may approve or deny it but cannot rewrite its capability/arguments.
public final class AgentActionConsentTicket: @unchecked Sendable {
    public static let contract = "xz-action-consent-v1"
    public static let maximumLifetime: TimeInterval = 30

    public let challengeID: String
    public let deviceID: String
    public let ownerRevision: UInt64
    public let sessionID: String
    public let requestID: UInt32
    public let action: AgentActionConsentAction
    public let expiresAt: Date

    private let lock = NSLock()
    private var consumed = false

    private init(
        challengeID: String,
        deviceID: String,
        ownerRevision: UInt64,
        sessionID: String,
        requestID: UInt32,
        action: AgentActionConsentAction,
        expiresAt: Date
    ) {
        self.challengeID = challengeID
        self.deviceID = deviceID
        self.ownerRevision = ownerRevision
        self.sessionID = sessionID
        self.requestID = requestID
        self.action = action
        self.expiresAt = expiresAt
    }

    public static func parse(
        _ data: Data,
        expectedDeviceID: String,
        expectedOwnerRevision: UInt64,
        now: Date
    ) throws -> AgentActionConsentTicket {
        guard !data.isEmpty, data.count <= 1_024 else {
            throw AgentActionConsentContractError.invalidSize
        }
        guard String(data: data, encoding: .utf8) != nil else {
            throw AgentActionConsentContractError.invalidEncoding
        }
        let raw: Any
        do {
            raw = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw AgentActionConsentContractError.invalidJSON
        }
        let exactKeys: Set<String> = [
            "version", "challenge_id", "device_id", "owner_revision",
            "session_id", "request_id", "capability", "arguments",
            "expires_at_unix",
        ]
        guard let document = raw as? [String: Any],
              Set(document.keys) == exactKeys,
              let version = exactUnsigned(document["version"]),
              let challengeID = document["challenge_id"] as? String,
              let deviceID = document["device_id"] as? String,
              let ownerRevision = exactUnsigned(document["owner_revision"]),
              let sessionID = document["session_id"] as? String,
              let requestValue = exactUnsigned(document["request_id"]),
              let capability = document["capability"] as? String,
              let arguments = document["arguments"] as? [String: Any],
              Set(arguments.keys) == ["on"],
              let indicatorOn = arguments["on"] as? Bool,
              let expiresUnix = exactUnsigned(document["expires_at_unix"])
        else {
            throw AgentActionConsentContractError.invalidFields
        }
        guard version == 1 else {
            throw AgentActionConsentContractError.invalidVersion
        }
        guard canonicalBase64URL128(challengeID) else {
            throw AgentActionConsentContractError.invalidChallengeID
        }
        guard validIdentifier(deviceID) else {
            throw AgentActionConsentContractError.invalidDeviceID
        }
        guard validIdentifier(sessionID) else {
            throw AgentActionConsentContractError.invalidSessionID
        }
        guard requestValue > 0, requestValue <= UInt64(UInt32.max) else {
            throw AgentActionConsentContractError.invalidRequestID
        }
        guard ownerRevision > 0, ownerRevision <= UInt64(UInt32.max) else {
            throw AgentActionConsentContractError.invalidOwnerRevision
        }
        guard capability == "device.set_indicator" else {
            throw AgentActionConsentContractError.invalidCapability
        }
        guard deviceID == expectedDeviceID else {
            throw AgentActionConsentContractError.deviceMismatch
        }
        guard ownerRevision == expectedOwnerRevision else {
            throw AgentActionConsentContractError.ownerRevisionMismatch
        }
        guard expiresUnix <= UInt64(Int64.max) else {
            throw AgentActionConsentContractError.invalidExpiry
        }
        let expiresAt = Date(timeIntervalSince1970: TimeInterval(expiresUnix))
        let lifetime = expiresAt.timeIntervalSince(now)
        guard lifetime > 0 else {
            throw AgentActionConsentContractError.expired
        }
        guard lifetime <= maximumLifetime else {
            throw AgentActionConsentContractError.invalidExpiry
        }

        let canonical = canonicalChallenge(
            challengeID: challengeID,
            deviceID: deviceID,
            ownerRevision: ownerRevision,
            sessionID: sessionID,
            requestID: UInt32(requestValue),
            indicatorOn: indicatorOn,
            expiresUnix: expiresUnix
        )
        guard canonical == data else {
            throw AgentActionConsentContractError.invalidJSON
        }
        return AgentActionConsentTicket(
            challengeID: challengeID,
            deviceID: deviceID,
            ownerRevision: ownerRevision,
            sessionID: sessionID,
            requestID: UInt32(requestValue),
            action: AgentActionConsentAction(indicatorOn: indicatorOn),
            expiresAt: expiresAt
        )
    }

    public func consume(
        _ decision: AgentActionConsentDecision,
        now: Date
    ) throws -> AgentActionConsentDecisionRequest {
        lock.lock()
        defer { lock.unlock() }
        guard !consumed else {
            throw AgentActionConsentContractError.alreadyConsumed
        }
        guard now < expiresAt else {
            consumed = true
            throw AgentActionConsentContractError.expired
        }
        consumed = true
        let body = Data(
            #"{"version":1,"challenge_id":"\#(challengeID)","device_id":"\#(deviceID)","owner_revision":\#(ownerRevision),"session_id":"\#(sessionID)","request_id":\#(requestID),"capability":"device.set_indicator","arguments":{"on":\#(action.indicatorOn ? "true" : "false")},"decision":"\#(decision.rawValue)"}"#.utf8
        )
        return AgentActionConsentDecisionRequest(
            challengeID: challengeID,
            deviceID: deviceID,
            ownerRevision: ownerRevision,
            body: body
        )
    }

    public func invalidate() {
        lock.lock()
        consumed = true
        lock.unlock()
    }

    deinit { invalidate() }

    private static func exactUnsigned(_ value: Any?) -> UInt64? {
        guard let number = value as? NSNumber,
              String(cString: number.objCType) != "c" else {
            return nil
        }
        let text = number.stringValue
        guard !text.isEmpty, text.allSatisfy({ $0 >= "0" && $0 <= "9" }) else {
            return nil
        }
        return UInt64(text)
    }

    private static func validIdentifier(_ value: String) -> Bool {
        let bytes = value.utf8
        guard !bytes.isEmpty, bytes.count <= 64 else { return false }
        return bytes.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) ||
            ($0 >= 0x41 && $0 <= 0x5A) ||
            ($0 >= 0x61 && $0 <= 0x7A) ||
            $0 == 0x3A || $0 == 0x2D || $0 == 0x5F || $0 == 0x2E
        }
    }

    private static func canonicalBase64URL128(_ value: String) -> Bool {
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

    private static func canonicalChallenge(
        challengeID: String,
        deviceID: String,
        ownerRevision: UInt64,
        sessionID: String,
        requestID: UInt32,
        indicatorOn: Bool,
        expiresUnix: UInt64
    ) -> Data {
        Data(
            #"{"version":1,"challenge_id":"\#(challengeID)","device_id":"\#(deviceID)","owner_revision":\#(ownerRevision),"session_id":"\#(sessionID)","request_id":\#(requestID),"capability":"device.set_indicator","arguments":{"on":\#(indicatorOn ? "true" : "false")},"expires_at_unix":\#(expiresUnix)}"#.utf8
        )
    }
}
