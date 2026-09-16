import Foundation

public enum ESPTransport: Sendable {
    case softap
}

public enum ESPSecurity: Sendable {
    case secure2
}

public enum ESPNetworkType: Sendable {
    case wifi
}

public enum ESPSessionError: Error, Sendable {
    case securityMismatch
    case sessionInitError
    case encryptionError
    case noPOP
    case noUsername
    case sessionNotEstablished
    case sendDataError
    case unavailable
}

public enum ESPSessionStatus: Sendable {
    case connected
    case failedToConnect(ESPSessionError)
    case disconnected
}

public enum ESPProvisionError: Error, Sendable {
    case wifiStatusAuthenticationError
    case wifiStatusNetworkNotFound
    case sessionError
    case unavailable
}

public enum ESPProvisionStatus: Sendable {
    case configApplied
    case success
    case failure(ESPProvisionError)
}

@MainActor
public final class ESPDevice {
    public func connect(
        completionHandler: @escaping (ESPSessionStatus) -> Void
    ) {
        completionHandler(.connected)
    }

    public func provision(
        ssid: String?,
        passPhrase: String? = "",
        completionHandler: @escaping (ESPProvisionStatus) -> Void
    ) {
        _ = ssid
        _ = passPhrase
        completionHandler(.success)
    }

    public func sendData(
        path: String,
        data: Data,
        completionHandler: @escaping (Data?, ESPSessionError?) -> Void
    ) {
        _ = path
        _ = data
        completionHandler(
            Data(
                #"{"version":1,"device_id":"xz-device-1","claim":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}"#.utf8
            ),
            nil
        )
    }

    public func disconnect() {}
}

@MainActor
public final class ESPProvisionManager {
    public static let shared = ESPProvisionManager()

    private init() {}

    public func enableLogs(_ enable: Bool) {
        _ = enable
    }

    public func createESPDevice(
        deviceName: String,
        transport: ESPTransport,
        security: ESPSecurity = .secure2,
        proofOfPossession: String? = nil,
        softAPPassword: String? = nil,
        username: String? = nil,
        network: ESPNetworkType? = nil,
        completionHandler: @escaping (ESPDevice?, Error?) -> Void
    ) {
        _ = deviceName
        _ = transport
        _ = security
        _ = proofOfPossession
        _ = softAPPassword
        _ = username
        _ = network
        completionHandler(ESPDevice(), nil)
    }
}
