import Foundation
#if canImport(Darwin)
import Darwin
#endif

public enum OnboardingContractError: Error, Equatable, Sendable {
    case invalidEncoding
    case invalidSize
    case nonCanonicalJSON
    case invalidFields
    case invalidVersion
    case invalidDeviceName
    case invalidUsername
    case unsupportedTransport
    case unsupportedSecurity
    case invalidProofOfPossession
    case invalidSoftAPPassword
    case alreadyConsumed
}

public struct OnboardingDevice: Equatable, Sendable {
    public let name: String

    public init(name: String) {
        self.name = name
    }
}

public struct EphemeralProvisioningIdentity: Sendable {
    public let device: OnboardingDevice
    public let username: String
    public let proofOfPossession: String
    public let softAPPassword: String
}

/// One-use holder for label credentials. It wipes its owned UTF-8 buffers on
/// consumption/deinit. The downstream ESPProvision API necessarily creates
/// temporary Swift Strings; the adapter releases its ESPDevice immediately
/// after completion or cancellation.
public final class OnboardingTicket: @unchecked Sendable {
    public let device: OnboardingDevice

    private let lock = NSLock()
    private var username: ContiguousArray<UInt8>
    private var proof: ContiguousArray<UInt8>
    private var softAPPassword: ContiguousArray<UInt8>
    private var consumed = false

    init(device: OnboardingDevice, username: String, proof: String,
         softAPPassword: String) {
        self.device = device
        self.username = ContiguousArray(username.utf8)
        self.proof = ContiguousArray(proof.utf8)
        self.softAPPassword = ContiguousArray(softAPPassword.utf8)
    }

    public func consume() throws -> EphemeralProvisioningIdentity {
        lock.lock()
        defer { lock.unlock() }
        guard !consumed else {
            throw OnboardingContractError.alreadyConsumed
        }
        consumed = true
        let identity = EphemeralProvisioningIdentity(
            device: device,
            username: String(decoding: username, as: UTF8.self),
            proofOfPossession: String(decoding: proof, as: UTF8.self),
            softAPPassword: String(decoding: softAPPassword, as: UTF8.self)
        )
        wipe(&username)
        wipe(&proof)
        wipe(&softAPPassword)
        return identity
    }

    public func invalidate() {
        lock.lock()
        defer { lock.unlock() }
        consumed = true
        wipe(&username)
        wipe(&proof)
        wipe(&softAPPassword)
    }

    deinit {
        invalidate()
    }
}

public enum OnboardingQRCode {
    public static let maximumBytes = 512
    public static let productUsername = "xiaozhi"

    private static let exactKeys: Set<String> = [
        "name", "password", "pop", "security", "transport", "username", "ver",
    ]
    private static let base32Alphabet = Set("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")

    public static func parse(_ payload: String,
                             expectedUsername: String = productUsername) throws
        -> OnboardingTicket {
        guard let bytes = payload.data(using: .utf8) else {
            throw OnboardingContractError.invalidEncoding
        }
        guard !bytes.isEmpty, bytes.count <= maximumBytes else {
            throw OnboardingContractError.invalidSize
        }
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: bytes)
        } catch {
            throw OnboardingContractError.nonCanonicalJSON
        }
        guard let document = object as? [String: Any],
              Set(document.keys) == exactKeys,
              JSONSerialization.isValidJSONObject(document),
              let canonical = try? JSONSerialization.data(
                withJSONObject: document,
                options: [.sortedKeys, .withoutEscapingSlashes]
              ),
              canonical == bytes else {
            throw OnboardingContractError.nonCanonicalJSON
        }
        guard let version = document["ver"] as? String else {
            throw OnboardingContractError.invalidFields
        }
        guard version == "v1" else {
            throw OnboardingContractError.invalidVersion
        }
        guard let name = document["name"] as? String,
              validDeviceName(name) else {
            throw OnboardingContractError.invalidDeviceName
        }
        guard let username = document["username"] as? String,
              username == expectedUsername,
              validUsername(username) else {
            throw OnboardingContractError.invalidUsername
        }
        guard let transport = document["transport"] as? String,
              transport == "softap" else {
            throw OnboardingContractError.unsupportedTransport
        }
        guard let security = document["security"] as? Int,
              security == 2 else {
            throw OnboardingContractError.unsupportedSecurity
        }
        guard let proof = document["pop"] as? String,
              validBase32(proof, count: 26) else {
            throw OnboardingContractError.invalidProofOfPossession
        }
        guard let softAPPassword = document["password"] as? String,
              validBase32(softAPPassword, count: 20) else {
            throw OnboardingContractError.invalidSoftAPPassword
        }
        return OnboardingTicket(
            device: OnboardingDevice(name: name),
            username: username,
            proof: proof,
            softAPPassword: softAPPassword
        )
    }

    private static func validDeviceName(_ value: String) -> Bool {
        guard value.utf8.count == 9, value.hasPrefix("XA-") else {
            return false
        }
        return value.dropFirst(3).allSatisfy {
            ($0 >= "0" && $0 <= "9") || ($0 >= "A" && $0 <= "F")
        }
    }

    private static func validUsername(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 32 else {
            return false
        }
        return value.utf8.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) ||
            ($0 >= 0x61 && $0 <= 0x7A) || $0 == 0x2D || $0 == 0x2E ||
            $0 == 0x5F
        }
    }

    private static func validBase32(_ value: String, count: Int) -> Bool {
        value.count == count && value.allSatisfy { base32Alphabet.contains($0) }
    }
}

func wipe(_ bytes: inout ContiguousArray<UInt8>) {
    bytes.withUnsafeMutableBytes { buffer in
        guard let baseAddress = buffer.baseAddress else { return }
#if canImport(Darwin)
        _ = memset_s(baseAddress, buffer.count, 0, buffer.count)
#else
        for index in 0..<buffer.count {
            buffer[index] = 0
        }
#endif
    }
    bytes.removeAll(keepingCapacity: false)
}
