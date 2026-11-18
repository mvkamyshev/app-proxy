import Foundation
import Network

struct SOCKSAddress: Equatable {
    let host: String
    let port: UInt16

    var endpoint: NWEndpoint {
        .hostPort(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!)
    }

    init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    init(endpoint: NWEndpoint) throws {
        guard case .hostPort(let host, let port) = endpoint else { throw ProxyError.unsupportedAddress }
        switch host {
        case .name(let name, _): self.host = name
        case .ipv4(let address): self.host = address.debugDescription
        case .ipv6(let address): self.host = address.debugDescription
        @unknown default: throw ProxyError.unsupportedAddress
        }
        self.port = port.rawValue
    }

    func encoded() throws -> Data {
        var data = Data()
        if let ip = IPv4Address(host) {
            data.append(1)
            data.append(ip.rawValue)
        } else if let ip = IPv6Address(host) {
            data.append(4)
            data.append(ip.rawValue)
        } else {
            let name = Data(host.utf8)
            guard !name.isEmpty, name.count <= 255, !host.contains(where: { $0.isWhitespace }) else {
                throw ProxyError.unsupportedAddress
            }
            data.append(contentsOf: [3, UInt8(name.count)])
            data.append(name)
        }
        data.append(contentsOf: [UInt8(port >> 8), UInt8(port & 255)])
        return data
    }

    static func decode(_ bytes: [UInt8], offset: inout Int) throws -> Self {
        guard offset < bytes.count else { throw ProxyError.invalidResponse }
        let type = bytes[offset]
        offset += 1
        let count: Int
        switch type {
        case 1: count = 4
        case 4: count = 16
        case 3:
            guard offset < bytes.count else { throw ProxyError.invalidResponse }
            count = Int(bytes[offset])
            offset += 1
            guard count > 0 else { throw ProxyError.invalidResponse }
        default: throw ProxyError.unsupportedAddress
        }
        guard bytes.count - offset >= count + 2 else { throw ProxyError.invalidResponse }
        let raw = Data(bytes[offset..<(offset + count)])
        let host: String
        switch type {
        case 1:
            guard let ip = IPv4Address(raw) else { throw ProxyError.invalidResponse }
            host = ip.debugDescription
        case 4:
            guard let ip = IPv6Address(raw) else { throw ProxyError.invalidResponse }
            host = ip.debugDescription
        default:
            guard let name = String(data: raw, encoding: .utf8) else { throw ProxyError.invalidResponse }
            host = name
        }
        offset += count
        let port = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
        offset += 2
        return Self(host: host, port: port)
    }

    func datagram(_ payload: Data) throws -> Data {
        var data = Data([0, 0, 0])
        data.append(try encoded())
        data.append(payload)
        return data
    }

    static func decodeDatagram(_ data: Data) throws -> (Self, Data) {
        let bytes = [UInt8](data)
        guard bytes.count >= 4, bytes[0] == 0, bytes[1] == 0 else { throw ProxyError.invalidResponse }
        guard bytes[2] == 0 else { throw ProxyError.unsupportedAddress }
        var offset = 3
        let address = try decode(bytes, offset: &offset)
        return (address, Data(bytes[offset...]))
    }
}

final class ProxySocket: @unchecked Sendable {
    let connection: NWConnection
    private let queue = DispatchQueue(label: "dev.maxkamyshev.AppProxy.socket")

    init(endpoint: NWEndpoint, udp: Bool = false) {
        let parameters: NWParameters
        if udp {
            parameters = .udp
        } else {
            let tcp = NWProtocolTCP.Options()
            tcp.connectionTimeout = 10
            parameters = NWParameters(tls: nil, tcp: tcp)
        }
        connection = NWConnection(to: endpoint, using: parameters)
    }

    func start() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                connection.stateUpdateHandler = { [self] state in
                    switch state {
                    case .ready:
                        connection.stateUpdateHandler = nil
                        continuation.resume()
                    case .failed(let error):
                        connection.stateUpdateHandler = nil
                        continuation.resume(throwing: error)
                    case .cancelled:
                        connection.stateUpdateHandler = nil
                        continuation.resume(throwing: CancellationError())
                    default: break
                    }
                }
                connection.start(queue: queue)
            }
        } onCancel: { self.cancel() }
    }

    func send(_ data: Data, final: Bool = false) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, contentContext: final ? .finalMessage : .defaultMessage,
                            isComplete: true, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            })
        }
    }

    func receive(maximum: Int = 65536) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) { data, _, _, error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: data ?? Data()) }
            }
        }
    }

    func receiveDatagram() async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            connection.receiveMessage { data, _, _, error in
                if let error { continuation.resume(throwing: error) }
                else if let data { continuation.resume(returning: data) }
                else { continuation.resume(throwing: ProxyError.connectionClosed) }
            }
        }
    }

    func readExactly(_ count: Int) async throws -> Data {
        var result = Data()
        while result.count < count {
            let next = try await receive(maximum: count - result.count)
            guard !next.isEmpty else { throw ProxyError.connectionClosed }
            result.append(next)
        }
        return result
    }

    func cancel() { connection.cancel() }

    func negotiate(command: UInt8, destination: SOCKSAddress) async throws -> SOCKSAddress {
        // Bound the entire handshake, including a proxy that accepts TCP but never replies.
        let deadline = Task {
            do { try await Task.sleep(nanoseconds: 10_000_000_000); cancel() }
            catch { }
        }
        defer { deadline.cancel() }
        try await start()
        try await send(Data([5, 1, 0]))
        let greeting = try await readExactly(2)
        guard greeting[0] == 5 else { throw ProxyError.invalidResponse }
        guard greeting[1] == 0 else { throw ProxyError.authenticationRequired }
        var request = Data([5, command, 0])
        request.append(try destination.encoded())
        try await send(request)
        let header = [UInt8](try await readExactly(4))
        guard header[0] == 5, header[2] == 0 else { throw ProxyError.invalidResponse }
        guard header[1] == 0 else { throw ProxyError.serverRejected(header[1]) }
        var address = [header[3]]
        switch header[3] {
        case 1: address += try await readExactly(6)
        case 4: address += try await readExactly(18)
        case 3:
            let length = try await readExactly(1)
            address += length
            address += try await readExactly(Int(length[0]) + 2)
        default: throw ProxyError.unsupportedAddress
        }
        var offset = 0
        return try SOCKSAddress.decode(address, offset: &offset)
    }
}
