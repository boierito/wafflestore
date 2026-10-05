import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public protocol AuthenticationTransport {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
    func cookies() async -> [StoreCookie]
    func transferDiagnostic() async -> String
    func cookieDiagnostic(for url: URL) async -> String
}
public extension AuthenticationTransport {
    func transferDiagnostic() async -> String { "connection-metrics=unavailable" }
    func cookieDiagnostic(for url: URL) async -> String { "cookie-transport=fixture-or-unspecified" }
}

// Each login owns an ephemeral cookie jar and connections. Never allow URLSession
// to change a redirect into GET or replay credentials to an unvalidated host.
public final class AppleAuthenticationTransport: NSObject, AuthenticationTransport, URLSessionTaskDelegate {
    private let configuration: URLSessionConfiguration = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 30
        configuration.urlCache = nil
        configuration.httpCookieAcceptPolicy = .always
        configuration.httpShouldSetCookies = true
        return configuration
    }()
    private let isolatedConnections: Bool
    private let lock = NSLock()
    private var isolatedSessions: [UUID: URLSession] = [:]
    private var closed = false
    private var connectionMetrics: [ObjectIdentifier: String] = [:]
    private var lastTransfer = "connection-metrics=unavailable"
    private lazy var session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)

    public convenience init(cookies: [StoreCookie] = [], isolatedConnections: Bool = false) {
        self.init(cookies: cookies, isolatedConnections: isolatedConnections, protocolClasses: nil)
    }
    // Test-only protocol injection never changes the production cookie policy.
    init(cookies: [StoreCookie], isolatedConnections: Bool, protocolClasses: [AnyClass]?) {
        self.isolatedConnections = isolatedConnections
        super.init()
        configuration.protocolClasses = protocolClasses
        // Carry challenge cookies into the verification request, as ipatool's
        // shared jar does. The jar remains ephemeral; no challenge is persisted.
        for cookie in cookies.compactMap({ $0.cookie() }) { configuration.httpCookieStorage?.setCookie(cookie) }
    }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        var request = request
        // Match the ephemeral jar to the destination, including domain/path/
        // Secure rules, before session creation. Do not rely on a copied
        // URLSessionConfiguration to carry restored authentication cookies.
        if let url = request.url {
            let cookies = configuration.httpCookieStorage?.cookies(for: url) ?? []
            if let header = HTTPCookie.requestHeaderFields(with: cookies)["Cookie"], !header.isEmpty {
                request.setValue(header, forHTTPHeaderField: "Cookie")
            }
        }
        // ipatool disables authentication connection pooling. HTTP/2 may ignore
        // Connection: close, so login retries own distinct sessions while sharing
        // the same ephemeral cookie jar. Store transport can still reuse sessions.
        let identifier = UUID()
        let current = try connection(identifier)
        defer { if isolatedConnections { releaseConnection(identifier, current) } }
        // Login replies contain tokens. Keep them in bounded RAM, never a
        // URLSession download file, URLCache, or a persistent cookie jar.
        #if canImport(FoundationNetworking)
        let (data, response) = try await current.data(for: request)
        guard data.count <= SAPProtocol.maximumBodySize else { throw SAPError.oversizedResponse }
        #else
        let (bytes, response) = try await current.bytes(for: request)
        var data = Data()
        for try await byte in bytes {
            guard data.count < SAPProtocol.maximumBodySize else { throw SAPError.oversizedResponse }
            data.append(byte)
        }
        #endif
        guard let response = response as? HTTPURLResponse else { throw AuthenticationError.invalidResponse(0) }
        // Retain response cookies before retiring an isolated connection. Some
        // URLSession response paths do not update the shared jar automatically.
        if let url = response.url {
            let headers = response.allHeaderFields.reduce(into: [String: String]()) { result, entry in
                if let name = entry.key as? String, let value = entry.value as? String { result[name] = value }
            }
            let cookies = HTTPCookie.cookies(withResponseHeaderFields: headers, for: url)
                .filter { StoreCookie($0).cookie() != nil }
            configuration.httpCookieStorage?.setCookies(cookies, for: url, mainDocumentURL: nil)
        }
        return (data, response)
    }
    public func transferDiagnostic() async -> String { transferSnapshot() }
    private func transferSnapshot() -> String {
        lock.lock(); defer { lock.unlock() }
        return lastTransfer
    }
    #if !canImport(FoundationNetworking)
    public func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        // Only isolated authentication sessions are attributable to one request.
        // No remote/local addresses, TLS secrets, URLs or headers are retained.
        lock.lock(); defer { lock.unlock() }
        guard isolatedSessions.values.contains(where: { $0 === session }), let transaction = metrics.transactionMetrics.last else { return }
        let raw = transaction.networkProtocolName ?? ""
        let name = ["http/1.1", "h2", "h3"].contains(raw) ? raw : "other-withheld"
        let duration = min(10_000_000, max(0, Int(metrics.taskInterval.duration * 1000)))
        connectionMetrics[ObjectIdentifier(session)] = "connection-metrics=available; network-protocol=\(name); connection-reused=\(transaction.isReusedConnection); task-ms=\(duration)"
    }
    #endif
    public func cookies() async -> [StoreCookie] {
        (configuration.httpCookieStorage?.cookies ?? []).map(StoreCookie.init).filter { $0.cookie() != nil }
    }
    public func cookieDiagnostic(for url: URL) async -> String {
        let all = configuration.httpCookieStorage?.cookies ?? []
        let matched = configuration.httpCookieStorage?.cookies(for: url) ?? []
        return "cookie-jar-count=\(all.count); request-cookie-count=\(matched.count)"
    }
    public func urlSession(_ session: URLSession, task: URLSessionTask,
                           willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                           completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    private func connection(_ id: UUID) throws -> URLSession {
        lock.lock(); defer { lock.unlock() }
        guard !closed else { throw CancellationError() }
        lastTransfer = "connection-metrics=unavailable"
        guard isolatedConnections else { return session }
        let current = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        isolatedSessions[id] = current
        return current
    }
    private func releaseConnection(_ id: UUID, _ current: URLSession) {
        lock.lock()
        lastTransfer = connectionMetrics.removeValue(forKey: ObjectIdentifier(current)) ?? "connection-metrics=unavailable"
        isolatedSessions.removeValue(forKey: id)
        lock.unlock()
        current.finishTasksAndInvalidate()
    }
    public func close() {
        lock.lock(); closed = true
        let active = Array(isolatedSessions.values); isolatedSessions.removeAll(); connectionMetrics.removeAll(); lock.unlock()
        active.forEach { $0.invalidateAndCancel() }
        if !isolatedConnections { session.invalidateAndCancel() }
    }
}
