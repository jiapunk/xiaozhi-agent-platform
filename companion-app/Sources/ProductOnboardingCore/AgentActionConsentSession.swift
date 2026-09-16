import Foundation

public enum AgentActionConsentAccessError: Error, Equatable, Sendable {
    case invalidBearerToken
    case invalidDeviceBinding
    case invalidLifetime
}

/// A just-in-time, device-bound access value returned by the product account
/// layer. The coordinator never stores this value; it discards provider state
/// immediately after each network operation.
public struct AgentActionConsentAccess: Sendable {
    public static let maximumLifetime: TimeInterval = 5 * 60

    public let bearerToken: String
    public let deviceID: String
    public let ownerRevision: UInt64
    public let expiresAt: Date

    public init(
        bearerToken: String,
        deviceID: String,
        ownerRevision: UInt64,
        expiresAt: Date,
        now: Date = Date()
    ) throws {
        let tokenBytes = bearerToken.utf8
        guard !tokenBytes.isEmpty, tokenBytes.count <= 4_096,
              tokenBytes.allSatisfy({ $0 >= 0x21 && $0 <= 0x7E }) else {
            throw AgentActionConsentAccessError.invalidBearerToken
        }
        guard Self.validIdentifier(deviceID), ownerRevision > 0,
              ownerRevision <= UInt64(UInt32.max) else {
            throw AgentActionConsentAccessError.invalidDeviceBinding
        }
        let lifetime = expiresAt.timeIntervalSince(now)
        guard lifetime > 0, lifetime <= Self.maximumLifetime else {
            throw AgentActionConsentAccessError.invalidLifetime
        }
        self.bearerToken = bearerToken
        self.deviceID = deviceID
        self.ownerRevision = ownerRevision
        self.expiresAt = expiresAt
    }

    fileprivate func valid(
        deviceID: String,
        ownerRevision: UInt64,
        now: Date
    ) -> Bool {
        self.deviceID == deviceID && self.ownerRevision == ownerRevision &&
            now < expiresAt
    }

    fileprivate static func validIdentifier(_ value: String) -> Bool {
        let bytes = value.utf8
        return !bytes.isEmpty && bytes.count <= 64 && bytes.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) ||
            ($0 >= 0x41 && $0 <= 0x5A) ||
            ($0 >= 0x61 && $0 <= 0x7A) ||
            $0 == 0x3A || $0 == 0x2D || $0 == 0x5F || $0 == 0x2E
        }
    }
}

@MainActor
public protocol AgentActionConsentAccessProviding: AnyObject {
    func acquireActionConsentAccess(
        deviceID: String,
        ownerRevision: UInt64,
        now: Date
    ) async throws -> AgentActionConsentAccess

    /// Clears any locally cached bearer material. Server-side logout/revocation
    /// remains the account service's responsibility and is checked online by
    /// the control plane for every use.
    func discardActionConsentAccess()
}

public struct AgentActionConsentPresentation: Equatable, Sendable {
    public let challengeID: String
    public let deviceID: String
    public let ownerRevision: UInt64
    public let requestID: UInt32
    public let indicatorOn: Bool
    public let expiresAt: Date

    fileprivate init(ticket: AgentActionConsentTicket) {
        challengeID = ticket.challengeID
        deviceID = ticket.deviceID
        ownerRevision = ticket.ownerRevision
        requestID = ticket.requestID
        indicatorOn = ticket.action.indicatorOn
        expiresAt = ticket.expiresAt
    }
}

public enum AgentActionConsentSessionState: Equatable, Sendable {
    case idle
    case checking
    case noPending
    case presenting(AgentActionConsentPresentation)
    case submitting(AgentActionConsentPresentation, AgentActionConsentDecision)
    case completed(AgentActionConsentPresentation, AgentActionConsentDecision)
    case authorizationUnavailable(AgentActionConsentPresentation)
    case inboxUnavailable
    case decisionDeliveryUnknown(AgentActionConsentPresentation)
    case expired(AgentActionConsentPresentation)
    case signedOut
}

/// Owns the foreground-only inbox lifecycle. It serializes fetch/decision work,
/// rejects stale callbacks with a generation ID, never defaults to approval,
/// and invalidates the exact ticket when the App backgrounds or signs out.
@MainActor
public final class AgentActionConsentSession {
    public typealias Sleep = @Sendable (UInt64) async throws -> Void

    public private(set) var state: AgentActionConsentSessionState = .idle
    public var stateDidChange:
        (@MainActor @Sendable (AgentActionConsentSessionState) -> Void)?

    private let service: AgentActionConsentServicing
    private let accessProvider: AgentActionConsentAccessProviding
    private let deliveryObserver:
        (any AgentActionConsentDeliveryObserving)?
    private let now: @MainActor @Sendable () -> Date
    private let sleep: Sleep
    private let pollNanoseconds: UInt64
    private var generation = UUID()
    private var operation: Task<Void, Never>?
    private var currentTicket: AgentActionConsentTicket?
    private var deviceID: String?
    private var ownerRevision: UInt64?
    private var foreground = false

    public init(
        service: AgentActionConsentServicing,
        accessProvider: AgentActionConsentAccessProviding,
        deliveryObserver: (any AgentActionConsentDeliveryObserving)? = nil,
        pollInterval: TimeInterval = 1,
        now: @escaping @MainActor @Sendable () -> Date = { Date() },
        sleep: @escaping Sleep = { nanoseconds in
            try await Task.sleep(nanoseconds: nanoseconds)
        }
    ) {
        precondition(pollInterval >= 0.1 && pollInterval <= 2)
        self.service = service
        self.accessProvider = accessProvider
        self.deliveryObserver = deliveryObserver
        self.pollNanoseconds = UInt64(pollInterval * 1_000_000_000)
        self.now = now
        self.sleep = sleep
    }

    public func enterForeground(
        deviceID: String,
        ownerRevision: UInt64
    ) throws {
        guard AgentActionConsentAccess.validIdentifier(deviceID),
              ownerRevision > 0, ownerRevision <= UInt64(UInt32.max) else {
            throw AgentActionConsentAccessError.invalidDeviceBinding
        }
        stopCurrent(nextState: nil)
        foreground = true
        self.deviceID = deviceID
        self.ownerRevision = ownerRevision
        deliveryObserver?.actionConsentDidEnterForeground(
            deviceID: deviceID, ownerRevision: ownerRevision, at: now()
        )
        let flow = UUID()
        generation = flow
        transition(.checking)
        operation = Task { [weak self] in
            await self?.poll(flow: flow, deviceID: deviceID,
                             ownerRevision: ownerRevision)
        }
    }

    public func approve(challengeID: String) {
        decide(.approve, challengeID: challengeID)
    }

    public func deny(challengeID: String) {
        decide(.deny, challengeID: challengeID)
    }

    /// A push hint can only accelerate the normal authenticated inbox fetch.
    /// Background receipt performs no network operation and no wake payload can
    /// create, approve, deny, select, or mutate a ticket.
    public func receiveWake(_ data: Data) throws {
        _ = try AgentActionConsentWake.parse(data)
        deliveryObserver?.actionConsentDidReceiveContentFreeWake(
            inForeground: foreground, at: now()
        )
        signalWake()
    }

    private func signalWake() {
        guard foreground, currentTicket == nil,
              let deviceID, let ownerRevision else { return }
        switch state {
        case .noPending, .inboxUnavailable, .completed, .expired:
            break
        default:
            return
        }
        operation?.cancel()
        let flow = UUID()
        generation = flow
        transition(.checking)
        operation = Task { [weak self] in
            await self?.poll(
                flow: flow, deviceID: deviceID,
                ownerRevision: ownerRevision
            )
        }
    }

    public func expireIfNeeded() {
        guard let ticket = currentTicket,
              now() >= ticket.expiresAt else { return }
        operation?.cancel()
        operation = nil
        ticket.invalidate()
        currentTicket = nil
        transition(.expired(AgentActionConsentPresentation(ticket: ticket)))
    }

    public func leaveForeground() {
        stopCurrent(nextState: .idle)
    }

    public func signOut() {
        stopCurrent(nextState: .signedOut)
    }

    deinit {
        operation?.cancel()
        currentTicket?.invalidate()
    }

    private func poll(flow: UUID, deviceID: String,
                      ownerRevision: UInt64) async {
        while current(flow), foreground {
            transition(.checking)
            do {
                let ticket = try await fetchPending(
                    deviceID: deviceID, ownerRevision: ownerRevision
                )
                guard current(flow), foreground else {
                    ticket?.invalidate()
                    return
                }
                if let ticket {
                    currentTicket = ticket
                    let presentation = AgentActionConsentPresentation(ticket: ticket)
                    deliveryObserver?.actionConsentDidPresentAuthenticatedTicket(
                        presentation, at: now()
                    )
                    transition(.presenting(presentation))
                    await waitForExpiry(
                        flow: flow, ticket: ticket, presentation: presentation
                    )
                    return
                }
                transition(.noPending)
            } catch is CancellationError {
                return
            } catch {
                guard current(flow), foreground else { return }
                transition(.inboxUnavailable)
            }
            do {
                try await sleep(pollNanoseconds)
            } catch {
                return
            }
        }
    }

    private func fetchPending(
        deviceID: String,
        ownerRevision: UInt64
    ) async throws -> AgentActionConsentTicket? {
        let access: AgentActionConsentAccess
        do {
            access = try await accessProvider.acquireActionConsentAccess(
                deviceID: deviceID, ownerRevision: ownerRevision, now: now()
            )
        } catch {
            accessProvider.discardActionConsentAccess()
            throw error
        }
        defer { accessProvider.discardActionConsentAccess() }
        guard access.valid(
            deviceID: deviceID, ownerRevision: ownerRevision, now: now()
        ) else {
            throw AgentActionConsentAccessError.invalidDeviceBinding
        }
        return try await service.fetchPending(
            deviceID: deviceID,
            ownerRevision: ownerRevision,
            bearerToken: access.bearerToken,
            now: now()
        )
    }

    private func decide(
        _ decision: AgentActionConsentDecision,
        challengeID: String
    ) {
        guard foreground, let ticket = currentTicket,
              ticket.challengeID == challengeID else { return }
        let presentation = AgentActionConsentPresentation(ticket: ticket)
        switch state {
        case .presenting(let shown) where shown.challengeID == challengeID:
            break
        case .authorizationUnavailable(let shown)
            where shown.challengeID == challengeID:
            break
        default:
            return
        }
        guard now() < ticket.expiresAt,
              let deviceID, let ownerRevision else {
            ticket.invalidate()
            currentTicket = nil
            transition(.expired(presentation))
            return
        }
        operation?.cancel()
        let flow = generation
        transition(.submitting(presentation, decision))
        operation = Task { [weak self] in
            guard let self else { return }
            let access: AgentActionConsentAccess
            do {
                access = try await accessProvider.acquireActionConsentAccess(
                    deviceID: deviceID, ownerRevision: ownerRevision, now: now()
                )
            } catch {
                accessProvider.discardActionConsentAccess()
                guard current(flow), currentTicket === ticket else { return }
                transition(.authorizationUnavailable(presentation))
                await waitForExpiry(
                    flow: flow, ticket: ticket, presentation: presentation
                )
                return
            }
            defer { accessProvider.discardActionConsentAccess() }
            guard access.valid(
                deviceID: deviceID, ownerRevision: ownerRevision, now: now()
            ) else {
                guard current(flow), currentTicket === ticket else { return }
                transition(.authorizationUnavailable(presentation))
                await waitForExpiry(
                    flow: flow, ticket: ticket, presentation: presentation
                )
                return
            }
            do {
                try await service.submit(
                    ticket: ticket, decision: decision,
                    bearerToken: access.bearerToken, now: now()
                )
                guard current(flow), foreground, currentTicket === ticket else {
                    return
                }
                currentTicket = nil
                transition(.completed(presentation, decision))
            } catch {
                guard current(flow), currentTicket === ticket else { return }
                ticket.invalidate()
                currentTicket = nil
                transition(.decisionDeliveryUnknown(presentation))
            }
        }
    }

    private func waitForExpiry(
        flow: UUID,
        ticket: AgentActionConsentTicket,
        presentation: AgentActionConsentPresentation
    ) async {
        let remaining = ticket.expiresAt.timeIntervalSince(now())
        if remaining > 0 {
            do {
                try await sleep(UInt64(remaining * 1_000_000_000))
            } catch {
                return
            }
        }
        guard current(flow), currentTicket === ticket else { return }
        ticket.invalidate()
        currentTicket = nil
        transition(.expired(presentation))
    }

    private func stopCurrent(nextState: AgentActionConsentSessionState?) {
        foreground = false
        generation = UUID()
        operation?.cancel()
        operation = nil
        currentTicket?.invalidate()
        currentTicket = nil
        deviceID = nil
        ownerRevision = nil
        accessProvider.discardActionConsentAccess()
        if let nextState {
            transition(nextState)
        }
    }

    private func current(_ flow: UUID) -> Bool {
        generation == flow && !Task.isCancelled
    }

    private func transition(_ nextState: AgentActionConsentSessionState) {
        state = nextState
        stateDidChange?(nextState)
    }
}
