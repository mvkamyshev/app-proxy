import Foundation
import Network

@main
struct ProxyTests {
    static func main() async throws {
        for path in ["/Applications/Max.app", "/Applications/Max.app/Contents/Frameworks/max-service.app",
                     "/Applications/Max.app/Contents/Frameworks/max-service.app/Contents/MacOS/max-service"] {
            precondition(ApplicationRule.applicationRoot(containing: URL(fileURLWithPath: path))?.path == "/Applications/Max.app")
        }
        precondition(ApplicationRule.applicationRoot(containing: URL(fileURLWithPath: "/Applications/Maximus Monitor.app"))?.path == "/Applications/Maximus Monitor.app")
        precondition(ApplicationRule.applicationRoot(containing: URL(fileURLWithPath: "/usr/bin/curl")) == nil)
        for address in [SOCKSAddress(host: "127.0.0.1", port: 65535),
                        SOCKSAddress(host: "2001:db8::1", port: 443),
                        SOCKSAddress(host: "example.com", port: 53)] {
            let encoded = [UInt8](try address.encoded())
            var offset = 0
            let decoded = try SOCKSAddress.decode(encoded, offset: &offset)
            precondition(decoded == address && offset == encoded.count)
            for length in 0..<encoded.count {
                var cursor = 0
                do {
                    _ = try SOCKSAddress.decode(Array(encoded.prefix(length)), offset: &cursor)
                    fatalError("Accepted a truncated SOCKS address")
                } catch {}
            }
            let packet = try address.datagram(Data([0, 255, 1, 128]))
            let (source, payload) = try SOCKSAddress.decodeDatagram(packet)
            precondition(source == address && payload == Data([0, 255, 1, 128]))
        }
        for invalid in [Data(), Data([0, 0, 1, 1, 127, 0, 0, 1, 0, 53]), Data([1, 0, 0, 1])] {
            do { _ = try SOCKSAddress.decodeDatagram(invalid); fatalError("Accepted an invalid UDP packet") }
            catch {}
        }
        let rule = ApplicationRule(path: "/Applications/Test.app", name: "Test", signingIdentifiers: ["test.helper"])
        precondition(rule.matches(executablePath: "/Applications/Test.app", signingIdentifier: "test"))
        precondition(rule.matches(executablePath: "/Applications/Test.app/Contents/Frameworks/Helper", signingIdentifier: "helper"))
        precondition(!rule.matches(executablePath: "/Applications/Test.app.fake/Contents/Helper", signingIdentifier: "test.helper"))
        precondition(!rule.matches(executablePath: "/Applications/Other.app/Contents/Main", signingIdentifier: "test.helper"))
        precondition(rule.matches(executablePath: nil, signingIdentifier: "test.helper"))
        precondition(!rule.matches(executablePath: nil, signingIdentifier: "test.helper.other"))
        var configuration = ProxyConfiguration()
        configuration.applications = [rule]
        let restored = try ProxyConfiguration(dictionary: configuration.providerDictionary)
        precondition(restored.applications == [rule])
        configuration.port = -1
        do { try configuration.validate(); fatalError("Accepted invalid port") } catch {}
        print("PASS: SOCKS address boundaries, UDP framing, application matching, configuration validation")

        guard CommandLine.arguments.count == 4,
              let proxyPort = UInt16(CommandLine.arguments[1]),
              let tcpPort = UInt16(CommandLine.arguments[2]),
              let udpPort = UInt16(CommandLine.arguments[3]) else { fatalError("Expected proxy, TCP and UDP test ports") }
        let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .init(rawValue: proxyPort)!)
        let stream = ProxySocket(endpoint: endpoint)
        defer { stream.cancel() }
        _ = try await stream.negotiate(command: 1, destination: .init(host: "127.0.0.1", port: tcpPort))
        let data = Data((0..<131072).map { UInt8($0 % 251) })
        try await stream.send(data, final: true)
        var reply = Data()
        while true {
            let chunk = try await stream.receive()
            if chunk.isEmpty { break }
            reply.append(chunk)
        }
        precondition(reply == data)
        print("PASS: TCP proxy, 128 KiB payload, half-close and full response")

        let control = ProxySocket(endpoint: endpoint)
        defer { control.cancel() }
        var relay = try await control.negotiate(command: 3, destination: .init(host: "0.0.0.0", port: 0))
        if relay.host == "0.0.0.0" || relay.host == "::" { relay = .init(host: "127.0.0.1", port: relay.port) }
        let udp = ProxySocket(endpoint: relay.endpoint, udp: true)
        defer { udp.cancel() }
        try await udp.start()
        let destination = SOCKSAddress(host: "127.0.0.1", port: udpPort)
        for payload in [Data(), Data([0, 255]), Data(repeating: 71, count: 1200)] {
            try await udp.send(destination.datagram(payload))
            let (source, received) = try SOCKSAddress.decodeDatagram(await udp.receiveDatagram())
            precondition(source == destination && received == payload)
        }
        print("PASS: UDP proxy, empty datagram, binary payload, 1200-byte payload")
        let refused = ProxySocket(endpoint: endpoint)
        defer { refused.cancel() }
        do {
            _ = try await refused.negotiate(command: 1, destination: .init(host: "127.0.0.1", port: 1))
            fatalError("Accepted refused connection")
        } catch ProxyError.serverRejected { print("PASS: proxy propagates destination connection errors") }
    }
}
