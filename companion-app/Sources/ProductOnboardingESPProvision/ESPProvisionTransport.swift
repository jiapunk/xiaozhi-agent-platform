import ProductOnboardingCore

#if os(iOS) && canImport(ESPProvision)
@preconcurrency import ESPProvision
#elseif ESP_PROVISION_CONTRACT_CHECK
@preconcurrency import ESPProvisionContractStub
#endif

#if (os(iOS) && canImport(ESPProvision)) || ESP_PROVISION_CONTRACT_CHECK
import Foundation

@MainActor
public final class ESPProvisionTransport: ProductProvisioningTransport {
    private static let connectionTimeout: Duration = .seconds(30)
    private static let claimTimeout: Duration = .seconds(30)
    private static let provisioningTimeout: Duration = .seconds(120)

    private var device: ESPDevice?
    private var activeOperation: (any CallbackGateProtocol)?

    public init() {
        // ESPProvision contains debug messages with QR/Wi-Fi material. Product
        // builds keep the upstream logger disabled unconditionally.
        disableOfficialLogs()
    }

    public func connect(using ticket: OnboardingTicket) async throws {
        disconnect()
        disableOfficialLogs()
        try Task.checkCancellation()
        let identity: EphemeralProvisioningIdentity
        do {
            identity = try ticket.consume()
        } catch {
            throw ProvisioningTransportError.sessionAuthentication
        }
        let createdDevice: ESPDevice = try await withCheckedThrowingContinuation {
            continuation in
            ESPProvisionManager.shared.createESPDevice(
                deviceName: identity.device.name,
                transport: .softap,
                security: .secure2,
                proofOfPossession: identity.proofOfPossession,
                softAPPassword: identity.softAPPassword,
                username: identity.username,
                network: .wifi
            ) { device, error in
                if let device {
                    continuation.resume(returning: device)
                } else {
                    _ = error
                    continuation.resume(throwing: ProvisioningTransportError.unavailable)
                }
            }
        }
        device = createdDevice
        defer { activeOperation = nil }
        do {
            try await withTaskCancellationHandler(
                operation: {
                    try await withCheckedThrowingContinuation {
                        (continuation: CheckedContinuation<Void, Error>) in
                        let gate = CallbackGate(continuation: continuation)
                        activeOperation = gate
                        gate.armTimeout(Self.connectionTimeout) { [weak self] in
                            self?.disconnectDeviceOnly()
                            return .unavailable
                        }
                        createdDevice.connect { status in
                            Task { @MainActor in
                                switch status {
                                case .connected:
                                    gate.succeed()
                                case .failedToConnect(let error):
                                    switch error {
                                    case .securityMismatch, .sessionInitError,
                                         .encryptionError, .noPOP, .noUsername:
                                        gate.fail(.sessionAuthentication)
                                    default:
                                        gate.fail(.unavailable)
                                    }
                                case .disconnected:
                                    gate.fail(.unavailable)
                                }
                            }
                        }
                    }
                },
                onCancel: {
                    Task { @MainActor [weak self] in
                        self?.disconnect()
                    }
                }
            )
            try Task.checkCancellation()
        } catch {
            disconnectDeviceOnly()
            throw error
        }
    }

    public func provision(
        using ticket: WiFiCredentialTicket,
        progress: @escaping @MainActor @Sendable (ProvisioningProgress) -> Void
    ) async throws {
        guard let device else {
            throw ProvisioningTransportError.unavailable
        }
        disableOfficialLogs()
        try Task.checkCancellation()
        let credentials: EphemeralWiFiCredentials
        do {
            credentials = try ticket.consume()
        } catch {
            throw ProvisioningTransportError.cancelled
        }
        defer { activeOperation = nil }
        try await withTaskCancellationHandler(
            operation: {
                try await withCheckedThrowingContinuation {
                    (continuation: CheckedContinuation<Void, Error>) in
                    let gate = CallbackGate(continuation: continuation)
                    activeOperation = gate
                    gate.armTimeout(Self.provisioningTimeout) { [weak self] in
                        self?.disconnectDeviceOnly()
                        return .unavailable
                    }
                    device.provision(
                        ssid: credentials.ssid,
                        passPhrase: credentials.passphrase
                    ) { status in
                        Task { @MainActor in
                            guard !gate.isFinished else { return }
                            switch status {
                            case .configApplied:
                                progress(.configurationApplied)
                            case .success:
                                progress(.networkJoined)
                                gate.succeed()
                            case .failure(let error):
                                switch error {
                                case .wifiStatusAuthenticationError:
                                    gate.fail(.candidate(.authentication))
                                case .wifiStatusNetworkNotFound:
                                    gate.fail(.candidate(.networkNotFound))
                                case .sessionError:
                                    gate.fail(.sessionAuthentication)
                                default:
                                    gate.fail(.candidate(.unknown))
                                }
                            }
                        }
                    }
                }
            },
            onCancel: {
                Task { @MainActor [weak self] in
                    self?.disconnect()
                }
            }
        )
        try Task.checkCancellation()
    }

    public func readDeviceClaim() async throws -> DeviceClaimTicket {
        guard let device else {
            throw ProvisioningTransportError.unavailable
        }
        disableOfficialLogs()
        try Task.checkCancellation()
        defer { activeOperation = nil }
        do {
            let data = try await withTaskCancellationHandler(
                operation: {
                    try await withCheckedThrowingContinuation {
                        (continuation: CheckedContinuation<Data, Error>) in
                        let gate = DataCallbackGate(continuation: continuation)
                        activeOperation = gate
                        gate.armTimeout(Self.claimTimeout) { [weak self] in
                            self?.disconnectDeviceOnly()
                            return .unavailable
                        }
                        device.sendData(path: "xz-claim", data: Data()) {
                            response, error in
                            Task { @MainActor in
                                guard !gate.isFinished else { return }
                                if let error {
                                    switch error {
                                    case .securityMismatch, .sessionInitError,
                                         .sessionNotEstablished,
                                         .encryptionError, .noPOP, .noUsername:
                                        gate.fail(.sessionAuthentication)
                                    default:
                                        gate.fail(.unavailable)
                                    }
                                } else if let response {
                                    gate.succeed(response)
                                } else {
                                    gate.fail(.unavailable)
                                }
                            }
                        }
                    }
                },
                onCancel: {
                    Task { @MainActor [weak self] in self?.disconnect() }
                }
            )
            try Task.checkCancellation()
            do {
                return try DeviceClaimTicket.parse(data)
            } catch {
                disconnectDeviceOnly()
                throw ProvisioningTransportError.sessionAuthentication
            }
        } catch {
            disconnectDeviceOnly()
            throw error
        }
    }

    public func disconnect() {
        activeOperation?.fail(.cancelled)
        activeOperation = nil
        disconnectDeviceOnly()
    }

    private func disconnectDeviceOnly() {
        device?.disconnect()
        device = nil
    }

    private func disableOfficialLogs() {
        ESPProvisionManager.shared.enableLogs(false)
    }
}

@MainActor
private final class CallbackGate: CallbackGateProtocol {
    private var continuation: CheckedContinuation<Void, Error>?
    private var timeoutTask: Task<Void, Never>?

    var isFinished: Bool { continuation == nil }

    init(continuation: CheckedContinuation<Void, Error>) {
        self.continuation = continuation
    }

    func armTimeout(
        _ duration: Duration,
        error: @escaping @MainActor () -> ProvisioningTransportError
    ) {
        guard continuation != nil else { return }
        timeoutTask = Task { @MainActor in
            do {
                try await Task.sleep(for: duration)
            } catch {
                return
            }
            guard !isFinished else { return }
            fail(error())
        }
    }

    func succeed() {
        finish(.success(()))
    }

    func fail(_ error: ProvisioningTransportError) {
        finish(.failure(error))
    }

    private func finish(_ result: Result<Void, ProvisioningTransportError>) {
        guard let continuation else { return }
        self.continuation = nil
        timeoutTask?.cancel()
        timeoutTask = nil
        switch result {
        case .success:
            continuation.resume()
        case .failure(let error):
            continuation.resume(throwing: error)
        }
    }
}

@MainActor
private final class DataCallbackGate: CallbackGateProtocol {
    private var continuation: CheckedContinuation<Data, Error>?
    private var timeoutTask: Task<Void, Never>?

    var isFinished: Bool { continuation == nil }

    init(continuation: CheckedContinuation<Data, Error>) {
        self.continuation = continuation
    }

    func armTimeout(
        _ duration: Duration,
        error: @escaping @MainActor () -> ProvisioningTransportError
    ) {
        guard continuation != nil else { return }
        timeoutTask = Task { @MainActor in
            do { try await Task.sleep(for: duration) } catch { return }
            guard !isFinished else { return }
            fail(error())
        }
    }

    func succeed(_ data: Data) {
        finish(.success(data))
    }

    func fail(_ error: ProvisioningTransportError) {
        finish(.failure(error))
    }

    private func finish(_ result: Result<Data, ProvisioningTransportError>) {
        guard let continuation else { return }
        self.continuation = nil
        timeoutTask?.cancel()
        timeoutTask = nil
        switch result {
        case .success(let data): continuation.resume(returning: data)
        case .failure(let error): continuation.resume(throwing: error)
        }
    }
}

@MainActor
private protocol CallbackGateProtocol: AnyObject {
    func fail(_ error: ProvisioningTransportError)
}
#else
public enum ESPProvisionAdapterAvailability: Sendable {
    public static let requiresIOS = true
}
#endif
