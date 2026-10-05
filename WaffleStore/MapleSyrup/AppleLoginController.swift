import Foundation
import Security
import SwiftUI
import PartyUI
import MapleSAP

// MainActor owns UI state; SAPSession runs the blocking native guest away from it.
extension AppData {
    func startAppleLogin() {
        guard !isAuthenticating, !appleId.isEmpty, !password.isEmpty else { return }
        let email = appleId.trimmingCharacters(in: .whitespacesAndNewlines)
        let secret = password
        let verification = hasSent2FACode ? code : ""
        let challengeCookies = hasSent2FACode ? pendingAuthenticationCookies : []
        signInTrials += 1
        recordSignInEvidence("build=\(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "0"); trial=\(signInTrials); mode=\(freshSAPForInvestigation ? "fresh" : "warm")")
        isAuthenticating = true
        authenticationError = ""
        authenticationRecovery = ""
        authenticationTask = Task {
            defer { isAuthenticating = false; authenticationTask = nil }
            var preparation: PreparedAppleLogin?
            var keepPrepared = false
            do {
                try Task.checkCancellation()
                // Reject invalid codes before creating a guest or contacting Apple.
                _ = try TwoFactorAuthentication.normalize(verification)
                let prepared: PreparedAppleLogin
                if !freshSAPForInvestigation, let existing = preparedAppleLogin, existing.canReuse(for: email) {
                    prepared = existing
                    recordSignInEvidence("preparation=\(prepared.diagnosticID); preparation-reused=yes")
                } else {
                    if let existing = preparedAppleLogin { await existing.close() }
                    preparedAppleLogin = nil
                    prepared = try PreparedAppleLogin(email: email, cookies: challengeCookies)
                    signInPreparations += 1; prepared.diagnosticID = signInPreparations
                    recordSignInEvidence("preparation=\(prepared.diagnosticID); preparation-reused=no")
                    preparedAppleLogin = prepared
                }
                preparation = prepared
                let signer = try await prepared.prepare(progress: { self.setAuthenticationStage($0) }, evidence: { self.recordSignInEvidence($0) })
                try Task.checkCancellation()
                let authentication = AppleAuthentication(transport: prepared.loginTransport, signer: signer,
                    persistence: KeychainStoreAccount(), diagnostic: { event in
                        await MainActor.run {
                            self.recordSignInEvidence(event)
                            if event.hasPrefix("authentication-recovery-attempt=") {
                                self.authenticationRecovery = "Automatic attempt " + event.replacingOccurrences(of: "authentication-recovery-attempt=", with: "")
                            }
                        }
                    }, automaticRecovery: true)
                guard let endpoint = prepared.endpoint else { throw CancellationError() }
                let outcome = try await authentication.login(email: email, password: secret, code: verification,
                    identity: prepared.identity, endpoint: endpoint, resolvedEndpoint: { endpoint in
                        await MainActor.run { prepared.endpoint = endpoint; self.recordSignInEndpoint(endpoint) }
                    }) { stage in
                        await MainActor.run { self.setAuthenticationStage(stage) }
                    }
                try Task.checkCancellation()
                switch outcome {
                case .twoFactorRequired(let cookies):
                    recordSignInEvidence("outcome=two-factor-required")
                    pendingAuthenticationCookies = cookies
                    keepPrepared = true
                    hasSent2FACode = true
                    code = ""
                    applicationStatus = AuthenticationStage.twoFactor.rawValue
                case .authenticated(let account):
                    recordSignInEvidence("outcome=authenticated")
                    applyStoreAccount(account, restored: false)
                }
            } catch let error where error is CancellationError || Task.isCancelled {
                recordSignInEvidence("outcome=cancelled")
                applicationStatus = "Sign-in cancelled."
            } catch {
                let category: String
                if let failure = error as? AuthenticationError {
                    switch failure {
                    case .http, .rateLimited, .retryLater, .invalidResponse: category = "temporary-http"
                    case .network: category = "network"
                    case .invalidCredentials, .verificationRejected, .accountDisabled, .invalidCode, .apple: category = "credential-or-verification"
                    default: category = "protocol"
                    }
                } else { category = error is SAPError ? "SAP" : "other" }
                recordSignInEvidence("outcome=\(category)")
                if let preparation {
                    if hasSent2FACode { pendingAuthenticationCookies = await preparation.loginTransport.cookies() }
                    if let error = error as? AuthenticationError {
                        switch error {
                        case .http, .network, .rateLimited, .retryLater, .invalidResponse, .verificationRejected, .invalidCode:
                            keepPrepared = true
                        default: break
                        }
                    }
                }
                // Apple/SAP errors have sanitized, bounded descriptions. Arbitrary
                // URL errors can include routing secrets: expose only numeric codes.
                if let error = error as? AuthenticationError { authenticationError = error.localizedDescription }
                else if let error = error as? SAPError { authenticationError = error.localizedDescription }
                else { authenticationError = "Sign-in failed (code \((error as NSError).code))." }
                code = ""
                applicationStatus = "Sign-in failed."
                print("Apple sign-in failed (code \((error as NSError).code)).")
            }
            if let preparation {
                if keepPrepared, !freshSAPForInvestigation, !Task.isCancelled, preparation.canReuse(for: email), preparedAppleLogin === preparation {
                    expireLoginPreparation(preparation)
                } else {
                    if preparedAppleLogin === preparation { preparedAppleLogin = nil }
                    await preparation.close()
                }
            }
        }
    }

    func cancelAppleLogin() {
        authenticationTask?.cancel()
        clearLoginPreparation()
        hasSent2FACode = false
        code = ""
        password = ""
        pendingAuthenticationCookies = []
        authenticationError = ""
        applicationStatus = "Not logged in!".localized
    }

    func restoreStoreAccount() {
        guard !didRestoreStoreAccount else { return }
        didRestoreStoreAccount = true
        do {
            // Legacy sessions include a password and may use a key file. Discard
            // them without decrypting/importing and require one fresh SAP login.
            try LegacyCredentials.remove()
            guard let account = try KeychainStoreAccount().load() else { return }
            try account.validate(identity: KeychainMachineIdentity.loadOrCreate())
            applyStoreAccount(account, restored: true)
        } catch {
            authenticationError = "Saved session could not be restored (code \((error as NSError).code)). Sign in again."
            // Do not overwrite or delete an inaccessible Keychain item during device lock.
        }
    }

    func logoutStoreAccount() {
        guard !isAuthenticating, storeTask == nil, !showStoreVersions else { return }
        do {
            clearLoginPreparation()
            try KeychainKBSync().clear()
            try KeychainStoreAccount().clear()
            try LegacyCredentials.remove()
            ipaTool?.close()
            ipaTool = nil
            isAuthenticated = false
            hasSent2FACode = false
            appleId = ""; password = ""; code = ""
            pendingAuthenticationCookies = []
            authenticationError = ""
            hasAppBeenServed = false
            applicationStatus = "Not logged in!".localized
            applicationIcon = "xmark.circle.fill"
            // The machine-identity Keychain item deliberately survives logout.
        } catch {
            authenticationError = "Could not remove the saved session (code \((error as NSError).code))."
            Alertinator.shared.alert(title: "Log Out".localized, body: authenticationError)
        }
    }

    func clearSignInEvidence() {
        signInTrace.clear(); signInEvidence = ""
        signInEndpointAliases.removeAll(); signInTrials = 0
    }
    func recordSignInEvidence(_ event: String) {
        guard collectSignInEvidence else { return }
        signInTrace.append(event)
        signInEvidence = signInTrace.isEmpty ? "" : signInTrace.report
    }
    private func recordSignInEndpoint(_ endpoint: URL) {
        guard collectSignInEvidence, (try? AuthenticationEndpoint.validate(endpoint)) != nil else { return }
        // Assign report-local aliases to public host/path. Queries/fragments and
        // URL strings never enter the export. Aliases survive between trials.
        let key = (endpoint.host ?? "") + endpoint.path
        if signInEndpointAliases[key] == nil { signInEndpointAliases[key] = signInEndpointAliases.count + 1 }
        recordSignInEvidence("endpoint-alias=\(signInEndpointAliases[key]!)")
    }
    func discardPreparedSignIn() { clearLoginPreparation() }

    private func expireLoginPreparation(_ prepared: PreparedAppleLogin) {
        loginPreparationExpiry?.cancel()
        loginPreparationExpiry = Task {
            let remaining = max(0, prepared.expiresAt.timeIntervalSinceNow)
            try? await Task.sleep(nanoseconds: UInt64(remaining * 1_000_000_000))
            guard !Task.isCancelled, preparedAppleLogin === prepared, !isAuthenticating else { return }
            preparedAppleLogin = nil
            await prepared.close()
        }
    }
    private func clearLoginPreparation() {
        loginPreparationExpiry?.cancel(); loginPreparationExpiry = nil
        let prepared = preparedAppleLogin
        preparedAppleLogin = nil
        Task { await prepared?.close() }
    }

    private func setAuthenticationStage(_ stage: AuthenticationStage) {
        recordSignInEvidence("stage=\(stage.rawValue)")
        applicationStatus = stage.rawValue
        print("Apple authentication stage: \(stage.rawValue)")
    }
    private func applyStoreAccount(_ account: StoreAccount, restored: Bool) {
        appleId = account.email
        password = ""; code = ""; hasSent2FACode = false
        pendingAuthenticationCookies = []
        ipaTool = IPATool(account: account)
        isAuthenticated = true
        applicationStatus = restored ? "Saved session loaded; Apple validity not checked." : "Signed in. Choose an app/version to download."
        applicationIcon = "checkmark.circle.fill"
        applicationIconColor = .primary
        print("Apple authentication: \(restored ? "saved session loaded" : "DSID/token/storefront received and saved in Keychain") [values withheld]")
    }

}

// A short-lived, same-account preparation avoids repeating the Bag/certificate/
// SAP handshake for a manual retry or 2FA. It holds no password/code, writes
// nothing to disk, signs every request freshly and expires after five minutes.
@MainActor
final class PreparedAppleLogin {
    var diagnosticID = 0
    let email: String
    let identity: MachineIdentity
    let loginTransport: AppleAuthenticationTransport
    private let sapTransport = AppleSAPTransport()
    private var signer: SAPSession?
    private var closed = false
    var endpoint: URL?
    private(set) var expiresAt = Date.distantPast
    init(email: String, cookies: [StoreCookie]) throws {
        self.email = email
        identity = try KeychainMachineIdentity.loadOrCreate()
        loginTransport = AppleAuthenticationTransport(cookies: cookies, isolatedConnections: true)
    }
    func canReuse(for email: String) -> Bool {
        !closed && self.email == email && signer != nil && expiresAt > Date()
    }
    func prepare(progress: (AuthenticationStage) -> Void, evidence: (String) -> Void) async throws -> SAPSession {
        guard !closed else { throw CancellationError() }
        if let signer { progress(.prepared); return signer }
        progress(.bag)
        let bagStart = ProcessInfo.processInfo.systemUptime
        let configuration = try await SAPProtocol(transport: sapTransport).bag(identity: identity)
        evidence("bag-ms=\(min(10_000_000, max(0, Int((ProcessInfo.processInfo.systemUptime - bagStart) * 1000))))")
        endpoint = try AuthenticationEndpoint.validate(configuration.authenticationURL)
        progress(.sap)
        let sapStart = ProcessInfo.processInfo.systemUptime
        let created = try SAPSession(guest: NativeSAPGuest(), transport: sapTransport)
        // Own the guest immediately, including cancellation during initialization.
        signer = created
        try await created.initialize(configuration: configuration, identity: identity)
        try Task.checkCancellation()
        guard !closed else { throw CancellationError() }
        evidence("sap-ms=\(min(10_000_000, max(0, Int((ProcessInfo.processInfo.systemUptime - sapStart) * 1000))))")
        expiresAt = Date().addingTimeInterval(300)
        return created
    }
    func close() async {
        guard !closed else { return }
        closed = true
        sapTransport.close(); loginTransport.close()
        if let signer { await signer.close() }
        signer = nil; endpoint = nil
    }
}

private enum LegacyCredentials {
    static func remove() throws {
        let fm = FileManager.default
        let documents = try fm.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: false)
        let library = try fm.url(for: .libraryDirectory, in: .userDomainMask, appropriateFor: nil, create: false)
        for file in [documents.appendingPathComponent("authinfo"), library.appendingPathComponent(".authkey")] {
            if fm.fileExists(atPath: file.path) { try fm.removeItem(at: file) }
        }
        let status = SecItemDelete([kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "com.nxtcoreee3.WaffleStore.key"] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw SAPError.keychain(status) }
    }
}
