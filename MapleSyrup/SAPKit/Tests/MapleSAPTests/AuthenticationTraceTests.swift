import XCTest
@testable import MapleSAP

final class AuthenticationTraceTests: XCTestCase {
    func testAllowlistRejectsCredentialsURLsCookiesAndArbitraryHeaders() {
        var trace = AuthenticationTrace()
        for event in ["password=secret", "stage=fixture@example.test", "cookie-jar-count=secret-cookie",
                      "signature=secret-signature", "URL=https://buy.itunes.apple.com/?token=secret",
                      "HTTP=404\npassword=secret", "scope=authentication; unknown=secret",
                      "request-profile=Authorization: secret", "body=<html>secret</html>",
                      "apple-failure=secret", "trial=123456789"] { trace.append(event) }
        XCTAssertTrue(trace.isEmpty)
        trace.append("scope=authentication; attempt=1; HTTP=404; body=html; apple-failure=absent")
        trace.append("request-profile=signed-POST-plist-reference-UA; route=native-pod; signer-ms=10; signature-bytes=668; signature-valid-base64=true")
        trace.append("connection-metrics=available; network-protocol=h2; connection-reused=false; task-ms=120")
        XCTAssertFalse(trace.isEmpty)
        XCTAssertTrue(trace.report.contains("HTTP=404"))
        XCTAssertFalse(trace.report.contains("secret-cookie"))
        XCTAssertFalse(trace.report.contains("https://"))
    }
    func testBoundedVolatileReportClearsAndDoesNotAcceptOversizedEvents() {
        var trace = AuthenticationTrace()
        trace.append(String(repeating: "x", count: 601))
        XCTAssertTrue(trace.isEmpty)
        for trial in 1...300 { trace.append("trial=\(trial)") }
        XCTAssertEqual(trace.report.split(separator: "\n").count, 242)
        XCTAssertFalse(trace.report.contains("\ntrial=1\n"))
        XCTAssertTrue(trace.report.contains("trial=300"))
        trace.clear()
        XCTAssertTrue(trace.isEmpty)
        XCTAssertFalse(trace.report.contains("trial=300"))
    }
    func testResponseFailureCodesMatchingSecretsAreWithheldBeforeCollection() {
        let data = Data("<plist><dict><key>failureType</key><string>123456</string><key>customerMessage</key><string>secret-password</string></dict></plist>".utf8)
        var trace = AuthenticationTrace()
        trace.append(ResponseDiagnostic.response(data, status: 403, scope: "authentication", attempt: 1, secrets: ["123456", "secret-password"]))
        XCTAssertTrue(trace.report.contains("apple-failure=present-withheld"))
        XCTAssertFalse(trace.report.contains("123456"))
        XCTAssertFalse(trace.report.contains("secret-password"))
    }
}
