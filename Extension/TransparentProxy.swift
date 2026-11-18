import Foundation
import Network
import NetworkExtension
import Security
import os

final class TransparentProxy: NETransparentProxyProvider, NEAppProxyUDPFlowHandling {
    private let lock = NSLock()
    private var configuration = ProxyConfiguration()
    private var relays: [UUID: FlowRelay] = [:]
    private let logger = Logger(subsystem: ProxyConfiguration.providerID, category: "proxy")

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        do {
            let configuration = try ProxyConfiguration(dictionary: (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration)
            lock.withLock { self.configuration = configuration }
            let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
            settings.includedNetworkRules = [
                NENetworkRule(remoteNetworkEndpoint: nil, remotePrefix: 0, localNetworkEndpoint: nil,
                              localPrefix: 0, protocol: .any, direction: .outbound)
            ]
            setTunnelNetworkSettings(settings, completionHandler: completionHandler)
        } catch { completionHandler(error) }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        let active = lock.withLock {
            let active = Array(relays.values)
            relays.removeAll()
            return active
        }
        active.forEach { $0.stop() }
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool { handle(flow) }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        do {
            let updated = try JSONDecoder().decode(ProxyConfiguration.self, from: messageData)
            try updated.validate()
            lock.withLock { configuration.applications = updated.applications }
            completionHandler?(Data([0]))
        } catch { completionHandler?(Data(error.localizedDescription.utf8)) }
    }

    func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteFlowEndpoint: Network.NWEndpoint) -> Bool {
        handle(flow)
    }

    private func handle(_ flow: NEAppProxyFlow) -> Bool {
        let configuration = lock.withLock { self.configuration }
        let metadata = flow.metaData
        guard metadata.sourceAppSigningIdentifier != ProxyConfiguration.providerID else { return false }
        let path = executablePath(metadata.sourceAppAuditToken)
        guard configuration.applications.contains(where: {
            $0.matches(executablePath: path, signingIdentifier: metadata.sourceAppSigningIdentifier)
        }), flow is NEAppProxyTCPFlow || flow is NEAppProxyUDPFlow else { return false }
        let id = UUID()
        let relay = FlowRelay(flow: flow, configuration: configuration) { [weak self] error in
            guard let self else { return }
            _ = lock.withLock { self.relays.removeValue(forKey: id) }
            if let error, !(error is CancellationError) {
                logger.error("Proxy flow failed: \(error.localizedDescription, privacy: .public)")
            }
        }
        lock.withLock { relays[id] = relay }
        relay.start()
        return true
    }

    private func executablePath(_ token: Data?) -> String? {
        guard let token else { return nil }
        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit: token] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var url: CFURL?
        guard SecCodeCopyPath(staticCode, [], &url) == errSecSuccess else { return nil }
        return (url as URL?)?.resolvingSymlinksInPath().path
    }
}

private final class FlowRelay: @unchecked Sendable {
    private let flow: NEAppProxyFlow
    private let configuration: ProxyConfiguration
    private let completed: (Error?) -> Void
    private let lock = NSLock()
    private var sockets: [ProxySocket] = []
    private var task: Task<Void, Never>?
    private var stopped = false

    init(flow: NEAppProxyFlow, configuration: ProxyConfiguration, completed: @escaping (Error?) -> Void) {
        self.flow = flow
        self.configuration = configuration
        self.completed = completed
    }

    func start() {
        let task = Task { [self] in
            var failure: Error?
            do {
                let proxy = ProxySocket(endpoint: .hostPort(host: NWEndpoint.Host(configuration.host),
                                                          port: NWEndpoint.Port(rawValue: UInt16(configuration.port))!))
                retain(proxy)
                if let tcp = flow as? NEAppProxyTCPFlow {
                    _ = try await proxy.negotiate(command: 1, destination: SOCKSAddress(endpoint: tcp.remoteFlowEndpoint))
                    try await open()
                    try await transferTCP(tcp, proxy: proxy)
                } else if let udp = flow as? NEAppProxyUDPFlow {
                    var bound = try await proxy.negotiate(command: 3, destination: SOCKSAddress(host: "0.0.0.0", port: 0))
                    if bound.host == "0.0.0.0" || bound.host == "::" {
                        bound = SOCKSAddress(host: configuration.host, port: bound.port)
                    }
                    guard bound.port != 0 else { throw ProxyError.invalidResponse }
                    let datagrams = ProxySocket(endpoint: bound.endpoint, udp: true)
                    retain(datagrams)
                    try await datagrams.start()
                    try await open()
                    try await transferUDP(udp, control: proxy, datagrams: datagrams)
                }
            } catch { failure = error }
            stop(error: failure)
            completed(failure)
        }
        lock.withLock {
            self.task = task
            if stopped { task.cancel() }
        }
    }

    private func retain(_ socket: ProxySocket) {
        lock.withLock {
            sockets.append(socket)
            if stopped { socket.cancel() }
        }
    }

    func stop(error: Error? = nil) {
        let active = lock.withLock { () -> ([ProxySocket], Task<Void, Never>?) in
            stopped = true
            return (sockets, task)
        }
        active.1?.cancel()
        active.0.forEach { $0.cancel() }
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
    }

    private func open() async throws {
        try Task.checkCancellation()
        try await flow.open(withLocalFlowEndpoint: nil)
    }

    private func transferTCP(_ flow: NEAppProxyTCPFlow, proxy: ProxySocket) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                while true {
                    let data: Data = try await withCheckedThrowingContinuation { continuation in
                        flow.readData { data, error in
                            if let error { continuation.resume(throwing: error) }
                            else { continuation.resume(returning: data ?? Data()) }
                        }
                    }
                    try await proxy.send(data, final: data.isEmpty)
                    if data.isEmpty { flow.closeReadWithError(nil); return }
                }
            }
            group.addTask {
                while true {
                    let data = try await proxy.receive()
                    if data.isEmpty { flow.closeWriteWithError(nil); return }
                    try await flow.write(data)
                }
            }
            do { for try await _ in group {} }
            catch { stop(error: error); group.cancelAll(); throw error }
        }
    }

    private func transferUDP(_ flow: NEAppProxyUDPFlow, control: ProxySocket, datagrams: ProxySocket) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                while true {
                    let (packets, error) = await flow.readDatagrams()
                    if let error { throw error }
                    guard let packets, !packets.isEmpty else { return }
                    for (packet, endpoint) in packets {
                        try await datagrams.send(SOCKSAddress(endpoint: endpoint).datagram(packet))
                    }
                }
            }
            group.addTask {
                while true {
                    let (source, payload) = try SOCKSAddress.decodeDatagram(await datagrams.receiveDatagram())
                    try await flow.writeDatagrams([(payload, source.endpoint)])
                }
            }
            group.addTask {
                _ = try await control.receive()
                throw ProxyError.connectionClosed
            }
            defer { stop(); group.cancelAll() }
            try await group.next()
        }
    }
}
