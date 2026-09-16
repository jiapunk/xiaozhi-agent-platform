import Foundation

public enum DeviceClaimContractError: Error, Equatable, Sendable {
    case invalidEncoding
    case invalidSize
    case nonCanonicalJSON
    case invalidFields
    case invalidVersion
    case invalidDeviceID
    case invalidClaim
    case alreadyConsumed
}

public struct EphemeralDeviceClaim: Sendable {
    public let deviceID: String
    public let claim: String
}

/// One-use holder for the 256-bit claim read inside the Security2 session.
public final class DeviceClaimTicket: @unchecked Sendable {
    public let deviceID: String

    private let lock = NSLock()
    private var claim: ContiguousArray<UInt8>
    private var consumed = false

    private init(deviceID: String, claim: String) {
        self.deviceID = deviceID
        self.claim = ContiguousArray(claim.utf8)
    }

    public static func parse(_ data: Data) throws -> DeviceClaimTicket {
        guard !data.isEmpty, data.count <= 512 else {
            throw DeviceClaimContractError.invalidSize
        }
        guard String(data: data, encoding: .utf8) != nil else {
            throw DeviceClaimContractError.invalidEncoding
        }
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw DeviceClaimContractError.nonCanonicalJSON
        }
        let exactKeys: Set<String> = ["version", "device_id", "claim"]
        guard let document = object as? [String: Any],
              Set(document.keys) == exactKeys,
              let version = document["version"] as? Int,
              let deviceID = document["device_id"] as? String,
              let claim = document["claim"] as? String else {
            throw DeviceClaimContractError.invalidFields
        }
        guard version == 1 else {
            throw DeviceClaimContractError.invalidVersion
        }
        guard Self.validIdentifier(deviceID) else {
            throw DeviceClaimContractError.invalidDeviceID
        }
        guard Self.canonicalClaim(claim) else {
            throw DeviceClaimContractError.invalidClaim
        }
        let canonical =
            #"{"version":1,"device_id":"\#(deviceID)","claim":"\#(claim)"}"#
        guard Data(canonical.utf8) == data else {
            throw DeviceClaimContractError.nonCanonicalJSON
        }
        return DeviceClaimTicket(deviceID: deviceID, claim: claim)
    }

    public func consume() throws -> EphemeralDeviceClaim {
        lock.lock()
        defer { lock.unlock() }
        guard !consumed else {
            throw DeviceClaimContractError.alreadyConsumed
        }
        consumed = true
        let result = EphemeralDeviceClaim(
            deviceID: deviceID,
            claim: String(decoding: claim, as: UTF8.self)
        )
        wipe(&claim)
        return result
    }

    public func invalidate() {
        lock.lock()
        defer { lock.unlock() }
        consumed = true
        wipe(&claim)
    }

    deinit { invalidate() }

    static func validIdentifier(_ value: String) -> Bool {
        let bytes = value.utf8
        guard !bytes.isEmpty, bytes.count <= 64 else { return false }
        return bytes.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) ||
            ($0 >= 0x41 && $0 <= 0x5A) ||
            ($0 >= 0x61 && $0 <= 0x7A) ||
            $0 == 0x3A || $0 == 0x2D || $0 == 0x5F || $0 == 0x2E
        }
    }

    static func canonicalClaim(_ value: String) -> Bool {
        let alphabet = Array(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8
        )
        let bytes = Array(value.utf8)
        guard bytes.count == 43 else { return false }
        for (index, byte) in bytes.enumerated() {
            guard let decoded = alphabet.firstIndex(of: byte) else {
                return false
            }
            if index == bytes.count - 1 && (decoded & 0x03) != 0 {
                return false
            }
        }
        return true
    }
}
