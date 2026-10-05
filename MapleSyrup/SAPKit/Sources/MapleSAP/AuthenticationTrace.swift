import Foundation

// An allowlist, not redaction of arbitrary logs. No URL/header/body/account data
// is accepted. Keep a bounded, volatile report only when explicitly enabled.
public struct AuthenticationTrace {
    private var lines: [String] = []
    public init() {}
    public var report: String { (["WaffleStore sign-in report v1", "secret-values=withheld"] + lines).joined(separator: "\n") }
    public var isEmpty: Bool { lines.isEmpty }
    public mutating func clear() { lines.removeAll() }
    public mutating func append(_ event: String) {
        guard event.utf8.count <= 600 else { return }
        let pairs = event.split(separator: ";", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
        guard !pairs.isEmpty, pairs.allSatisfy(Self.allowed) else { return }
        lines.append(pairs.joined(separator: "; "))
        if lines.count > 240 { lines.removeFirst(lines.count - 240) }
    }
    private static func allowed(_ field: String) -> Bool {
        let parts = field.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2 else { return false }
        let key = String(parts[0]), value = String(parts[1])
        func number(_ maximum: Int) -> Bool {
            !value.isEmpty && value.allSatisfy { $0.isASCII && $0.isNumber } && (Int(value).map { $0 <= maximum } ?? false)
        }
        switch key {
        case "build", "trial", "preparation", "endpoint-alias", "signer-ms", "transfer-ms", "sap-ms", "bag-ms", "task-ms": return number(10_000_000)
        case "transport-code":
            let digits = value.hasPrefix("-") ? String(value.dropFirst()) : value
            return !digits.isEmpty && digits.count <= 5 && digits.allSatisfy { $0.isASCII && $0.isNumber } && (Int(digits).map { $0 <= 10_000 } ?? false)
        case "HTTP": return number(599)
        case "attempt": return number(12)
        case "signature-bytes": return number(1 << 20)
        case "cookie-jar-count", "request-cookie-count": return number(10_000)
        case "authentication-recovery-attempt":
            let parts = value.split(separator: "/")
            return parts.count == 2 && parts.allSatisfy { Int($0).map { (1...12).contains($0) } ?? false }
        case "scope": return value == "authentication"
        case "response-content": return ["absent", "html", "plist", "json", "other-withheld"].contains(value)
        case "body": return ["empty", "plist", "html", "other"].contains(value)
        case "apple-failure":
            if ["absent", "present-withheld"].contains(value) { return true }
            let digits = value.hasPrefix("-") ? String(value.dropFirst()) : value
            return !digits.isEmpty && digits.count <= 8 && digits.allSatisfy { $0.isASCII && $0.isNumber }
        case "preparation-reused", "signature-valid-base64", "connection-reused", "location-present": return ["yes", "no", "true", "false"].contains(value)
        case "mode": return ["warm", "fresh"].contains(value)
        case "route": return ["native-bag", "native-pod", "legacy-bag", "legacy-pod"].contains(value)
        case "request-profile": return ["signed-POST-plist-reference-UA", "unexpected-withheld"].contains(value)
        case "connection-metrics": return ["available", "unavailable"].contains(value)
        case "network-protocol": return ["http/1.1", "h2", "h3", "other-withheld"].contains(value)
        case "cookie-transport": return value == "fixture-or-unspecified"
        case "authentication-redirect": return value == "received"
        case "stage": return AuthenticationStage(rawValue: value) != nil
        case "outcome": return ["authenticated", "two-factor-required", "cancelled", "temporary-http", "network", "credential-or-verification", "protocol", "SAP", "other"].contains(value)
        default: return false
        }
    }
}
