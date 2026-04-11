//
//  TestServer.swift
//  proxymateTests
//
//  Loopback HTTP server for E2E tests. Serves canned responses
//  on 127.0.0.1 with configurable routes.
//

import Foundation
import Network

final class TestServer {
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "test.server")
    private(set) var port: UInt16 = 0
    var routes: [String: (status: String, headers: String, body: String)] = [:]

    func start() throws {
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        let l = try NWListener(using: params)
        let semaphore = DispatchSemaphore(value: 0)

        l.stateUpdateHandler = { state in
            if case .ready = state, let p = l.port?.rawValue {
                self.port = p
                semaphore.signal()
            }
        }
        l.newConnectionHandler = { [weak self] conn in
            self?.handle(conn)
        }
        l.start(queue: queue)
        listener = l
        _ = semaphore.wait(timeout: .now() + 5)
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }

    private func handle(_ conn: NWConnection) {
        conn.start(queue: queue)
        conn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, _, _ in
            guard let self, let data,
                  let req = String(data: data, encoding: .utf8) else {
                conn.cancel(); return
            }
            let firstLine = req.split(separator: "\r\n").first ?? ""
            let parts = firstLine.split(separator: " ", maxSplits: 2)
            let path = parts.count >= 2 ? String(parts[1]) : "/"

            let route = self.routes[path] ?? self.defaultRoute(path: path, request: req)
            let response = "\(route.status)\r\n\(route.headers)\r\nConnection: close\r\n\r\n\(route.body)"
            conn.send(content: Data(response.utf8), completion: .contentProcessed { _ in
                conn.cancel()
            })
        }
    }

    private func defaultRoute(path: String, request: String) -> (status: String, headers: String, body: String) {
        switch path {
        case "/echo":
            return ("HTTP/1.1 200 OK",
                    "Content-Type: text/plain",
                    request)
        case "/status/200":
            return ("HTTP/1.1 200 OK",
                    "Content-Type: text/plain",
                    "OK")
        case "/status/404":
            return ("HTTP/1.1 404 Not Found",
                    "Content-Type: text/plain",
                    "Not Found")
        case "/status/204":
            return ("HTTP/1.1 204 No Content",
                    "",
                    "")
        case "/cached":
            return ("HTTP/1.1 200 OK",
                    "Content-Type: text/plain\r\nCache-Control: max-age=300",
                    "cached-body")
        case "/no-cache":
            return ("HTTP/1.1 200 OK",
                    "Content-Type: text/plain\r\nCache-Control: no-store",
                    "no-cache-body")
        case "/server-header":
            return ("HTTP/1.1 200 OK",
                    "Content-Type: text/plain\r\nServer: Apache/2.4\r\nX-Powered-By: PHP/8.0",
                    "has-server-headers")
        case "/chunked":
            return ("HTTP/1.1 200 OK",
                    "Content-Type: text/plain\r\nTransfer-Encoding: chunked",
                    "5\r\nHello\r\n0\r\n\r\n")
        case "/large":
            return ("HTTP/1.1 200 OK",
                    "Content-Type: text/plain",
                    String(repeating: "A", count: 100_000))
        default:
            return ("HTTP/1.1 200 OK",
                    "Content-Type: text/plain",
                    "default-response")
        }
    }
}
