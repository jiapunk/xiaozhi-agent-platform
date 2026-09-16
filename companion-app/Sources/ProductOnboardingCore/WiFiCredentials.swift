import Foundation

public struct EphemeralWiFiCredentials: Sendable {
    public let ssid: String
    public let passphrase: String
}

public final class WiFiCredentialTicket: @unchecked Sendable {
    private let lock = NSLock()
    private var ssid: ContiguousArray<UInt8>
    private var passphrase: ContiguousArray<UInt8>
    private var consumed = false

    public init(ssid: String, passphrase: String) throws {
        let ssidBytes = ContiguousArray(ssid.utf8)
        let passphraseBytes = ContiguousArray(passphrase.utf8)
        guard !ssidBytes.isEmpty, ssidBytes.count <= 32,
              ssid.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7F }) else {
            throw OnboardingContractError.invalidFields
        }
        guard passphraseBytes.count >= 8, passphraseBytes.count <= 63,
              passphraseBytes.allSatisfy({ $0 >= 0x20 && $0 <= 0x7E }) else {
            throw OnboardingContractError.invalidFields
        }
        self.ssid = ssidBytes
        self.passphrase = passphraseBytes
    }

    public func consume() throws -> EphemeralWiFiCredentials {
        lock.lock()
        defer { lock.unlock() }
        guard !consumed else {
            throw OnboardingContractError.alreadyConsumed
        }
        consumed = true
        let credentials = EphemeralWiFiCredentials(
            ssid: String(decoding: ssid, as: UTF8.self),
            passphrase: String(decoding: passphrase, as: UTF8.self)
        )
        wipe(&ssid)
        wipe(&passphrase)
        return credentials
    }

    public func invalidate() {
        lock.lock()
        defer { lock.unlock() }
        consumed = true
        wipe(&ssid)
        wipe(&passphrase)
    }

    deinit {
        invalidate()
    }
}
