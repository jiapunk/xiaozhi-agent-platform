import ProductOnboardingCore
import SwiftUI

/// Product-owned observable adapter. Scene lifecycle code must call
/// enterForeground/leaveForeground and signOut at the corresponding account
/// event; the underlying session invalidates stale tickets and cached access.
@MainActor
public final class AgentActionConsentViewModel: ObservableObject {
    @Published public private(set) var state: AgentActionConsentSessionState

    private let session: AgentActionConsentSession

    public init(session: AgentActionConsentSession) {
        self.session = session
        self.state = session.state
        session.stateDidChange = { [weak self] state in
            self?.state = state
        }
    }

    public func enterForeground(
        deviceID: String,
        ownerRevision: UInt64
    ) throws {
        try session.enterForeground(
            deviceID: deviceID, ownerRevision: ownerRevision
        )
    }

    public func leaveForeground() {
        session.leaveForeground()
    }

    public func signOut() {
        session.signOut()
    }

    public func approve(_ presentation: AgentActionConsentPresentation) {
        session.approve(challengeID: presentation.challengeID)
    }

    public func deny(_ presentation: AgentActionConsentPresentation) {
        session.deny(challengeID: presentation.challengeID)
    }

    /// Platform notification adapters pass only the provider-neutral product
    /// bytes. A valid hint merely accelerates the foreground authenticated
    /// inbox fetch; background receipt and malformed data do nothing.
    public func receiveWake(_ data: Data) throws {
        try session.receiveWake(data)
    }

    public func expireIfNeeded() {
        session.expireIfNeeded()
    }
}

/// Scene-aware composition boundary for the product App. It invalidates the
/// exact prompt when the scene backgrounds, the account signs out, the
/// selected device changes, or the trusted ownership revision advances.
public struct AgentActionConsentSceneGateView: View {
    @Environment(\.scenePhase) private var scenePhase
    @ObservedObject private var viewModel: AgentActionConsentViewModel
    private let accountSignedIn: Bool
    private let deviceID: String?
    private let ownerRevision: UInt64?
    @State private var activeBinding: SceneBinding?

    public init(
        viewModel: AgentActionConsentViewModel,
        accountSignedIn: Bool,
        deviceID: String?,
        ownerRevision: UInt64?
    ) {
        self.viewModel = viewModel
        self.accountSignedIn = accountSignedIn
        self.deviceID = deviceID
        self.ownerRevision = ownerRevision
    }

    public var body: some View {
        AgentActionConsentGateView(viewModel: viewModel)
            .onAppear { synchronize() }
            .onDisappear {
                viewModel.leaveForeground()
                activeBinding = nil
            }
            .onChange(of: scenePhase) { _ in synchronize() }
            .onChange(of: desiredBinding) { _ in synchronize() }
            .onChange(of: accountSignedIn) { signedIn in
                if !signedIn {
                    viewModel.signOut()
                    activeBinding = nil
                } else {
                    synchronize()
                }
            }
    }

    private var desiredBinding: SceneBinding? {
        guard accountSignedIn, let deviceID, let ownerRevision else {
            return nil
        }
        return SceneBinding(deviceID: deviceID, ownerRevision: ownerRevision)
    }

    private func synchronize() {
        guard accountSignedIn else {
            viewModel.signOut()
            activeBinding = nil
            return
        }
        guard scenePhase == .active, let desiredBinding else {
            viewModel.leaveForeground()
            activeBinding = nil
            return
        }
        guard desiredBinding != activeBinding else { return }
        do {
            try viewModel.enterForeground(
                deviceID: desiredBinding.deviceID,
                ownerRevision: desiredBinding.ownerRevision
            )
            activeBinding = desiredBinding
        } catch {
            // An absent or malformed trusted binding can never surface an
            // approval UI. The owning App may render account/device recovery
            // outside this security boundary.
            viewModel.leaveForeground()
            activeBinding = nil
        }
    }

    private struct SceneBinding: Equatable {
        let deviceID: String
        let ownerRevision: UInt64
    }
}

/// Foreground gate that renders only product-owned, typed fields. Prompt,
/// transcript, model output and arbitrary tool arguments never enter this UI.
public struct AgentActionConsentGateView: View {
    @ObservedObject private var viewModel: AgentActionConsentViewModel

    public init(viewModel: AgentActionConsentViewModel) {
        self.viewModel = viewModel
    }

    @ViewBuilder
    public var body: some View {
        switch viewModel.state {
        case .idle, .signedOut, .noPending:
            EmptyView()
        case .checking:
            ProgressView("Checking for Agent actions…")
                .accessibilityIdentifier("agent-action-consent-checking")
        case .presenting(let presentation):
            AgentActionConsentPromptView(
                presentation: presentation,
                submitting: false,
                approve: { viewModel.approve(presentation) },
                deny: { viewModel.deny(presentation) }
            )
        case .submitting(let presentation, _):
            AgentActionConsentPromptView(
                presentation: presentation,
                submitting: true,
                approve: {},
                deny: {}
            )
        case .authorizationUnavailable(let presentation):
            VStack(spacing: 16) {
                Text("Your account authorization changed. Confirm again or deny.")
                    .foregroundStyle(.red)
                    .accessibilityIdentifier(
                        "agent-action-consent-authorization-unavailable"
                    )
                AgentActionConsentPromptView(
                    presentation: presentation,
                    submitting: false,
                    approve: { viewModel.approve(presentation) },
                    deny: { viewModel.deny(presentation) }
                )
            }
        case .inboxUnavailable:
            ProgressView("Action requests are temporarily unavailable…")
                .accessibilityIdentifier("agent-action-consent-inbox-unavailable")
        case .completed(let presentation, let decision):
            AgentActionConsentOutcomeView(
                presentation: presentation,
                message: decision == .approve ? "Approved" : "Denied"
            )
        case .decisionDeliveryUnknown(let presentation):
            AgentActionConsentOutcomeView(
                presentation: presentation,
                message: "The decision result is unknown. Do not submit it again."
            )
        case .expired(let presentation):
            AgentActionConsentOutcomeView(
                presentation: presentation,
                message: "This request expired and was not approved."
            )
        }
    }
}

public struct AgentActionConsentPromptView: View {
    public let presentation: AgentActionConsentPresentation
    public let submitting: Bool
    private let approve: () -> Void
    private let deny: () -> Void

    public init(
        presentation: AgentActionConsentPresentation,
        submitting: Bool,
        approve: @escaping () -> Void,
        deny: @escaping () -> Void
    ) {
        self.presentation = presentation
        self.submitting = submitting
        self.approve = approve
        self.deny = deny
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Agent action request")
                .font(.headline)
            VStack(alignment: .leading, spacing: 4) {
                Text("Device")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(verbatim: presentation.deviceID)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .accessibilityIdentifier("agent-action-consent-device")
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Exact action")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(
                    presentation.indicatorOn
                        ? "Turn the indicator ON"
                        : "Turn the indicator OFF"
                )
                .font(.title3.weight(.semibold))
                .accessibilityIdentifier("agent-action-consent-exact-action")
            }
            HStack {
                Text("Expires in")
                Text(presentation.expiresAt, style: .timer)
                    .monospacedDigit()
            }
            .accessibilityIdentifier("agent-action-consent-expiry")
            HStack {
                Button("Deny", role: .cancel, action: deny)
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("agent-action-consent-deny")
                Spacer()
                Button("Approve", action: approve)
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("agent-action-consent-approve")
            }
            .disabled(submitting)
            if submitting {
                ProgressView("Submitting decision…")
                    .accessibilityIdentifier("agent-action-consent-submitting")
            }
        }
        .padding()
        .interactiveDismissDisabled(true)
        .accessibilityElement(children: .contain)
    }
}

private struct AgentActionConsentOutcomeView: View {
    let presentation: AgentActionConsentPresentation
    let message: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(verbatim: presentation.deviceID)
                .font(.system(.body, design: .monospaced))
            Text(verbatim: message)
        }
        .padding()
        .accessibilityIdentifier("agent-action-consent-outcome")
    }
}
