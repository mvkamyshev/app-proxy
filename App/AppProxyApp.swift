import AppKit
import SwiftUI
import Network
import NetworkExtension
import SystemExtensions
import Security

@main
struct AppProxyApp: App {
    @StateObject private var model = ProxyModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
                .frame(minWidth: 760, minHeight: 540)
        }
        .defaultSize(width: 880, height: 640)
        .commands { CommandGroup(replacing: .newItem) {} }
    }
}

@MainActor
final class ProxyModel: NSObject, ObservableObject, @MainActor OSSystemExtensionRequestDelegate {
    @Published var configuration = ProxyConfiguration()
    @Published var applications: [ApplicationRule] = []
    @Published var search = ""
    @Published var status = "Прокси выключен"
    @Published var error: String?
    @Published var busy = false
    @Published var connected = false
    private var manager: NETransparentProxyManager?
    private var statusObserver: NSObjectProtocol?
    private var request: OSSystemExtensionRequest?
    private let settingsKey = "proxyConfiguration"

    override init() {
        super.init()
        if let data = UserDefaults.standard.data(forKey: settingsKey),
           let saved = try? JSONDecoder().decode(ProxyConfiguration.self, from: data) {
            configuration = saved
        }
        refreshApplications()
        statusObserver = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.refreshStatus() }
        }
        Task {
            do { try await loadManager(); refreshStatus() }
            catch { self.error = error.localizedDescription }
        }
    }

    var filteredApplications: [ApplicationRule] {
        applications.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) }
    }

    func refreshApplications() {
        var selected: [ApplicationRule] = []
        for var rule in configuration.applications {
            guard let root = ApplicationRule.applicationRoot(containing: URL(fileURLWithPath: rule.path)),
                  !selected.contains(where: { $0.path == root.path }) else { continue }
            if rule.path != root.path {
                rule.path = root.path
                rule.name = root.deletingPathExtension().lastPathComponent
                rule.signingIdentifiers = signingIdentifiers(at: root)
            }
            selected.append(rule)
        }
        if selected != configuration.applications {
            configuration.applications = selected
            saveSettings()
        }
        var urls: [URL] = []
        for root in ["/Applications", "/System/Applications", NSHomeDirectory() + "/Applications"] {
            guard let enumerator = FileManager.default.enumerator(at: URL(fileURLWithPath: root),
                    includingPropertiesForKeys: nil) else { continue }
            for case let url as URL in enumerator where url.pathExtension == "app" {
                urls.append(url)
                enumerator.skipDescendants()
            }
        }
        urls += NSWorkspace.shared.runningApplications.compactMap(\.bundleURL)
        urls += configuration.applications.map { URL(fileURLWithPath: $0.path) }
        var seen = Set<String>()
        applications = urls.compactMap { url in
            guard let root = ApplicationRule.applicationRoot(containing: url) else { return nil }
            let path = root.path
            guard path != Bundle.main.bundlePath, seen.insert(path).inserted else { return nil }
            let displayName = FileManager.default.displayName(atPath: path)
            return configuration.applications.first(where: { $0.path == path }) ?? ApplicationRule(
                path: path, name: displayName.hasSuffix(".app") ? String(displayName.dropLast(4)) : displayName,
                signingIdentifiers: [])
        }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    func isSelected(_ app: ApplicationRule) -> Bool { configuration.applications.contains { $0.path == app.path } }

    func select(_ app: ApplicationRule, selected: Bool) {
        var applications = configuration.applications
        if selected {
            var rule = app
            rule.signingIdentifiers = signingIdentifiers(at: URL(fileURLWithPath: app.path))
            applications.append(rule)
        } else { applications.removeAll { $0.path == app.path } }
        applyApplications(applications)
    }

    func addApplication() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.applicationBundle]
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        if panel.runModal() == .OK {
            var applications = configuration.applications
            for selectedURL in panel.urls {
                guard let url = ApplicationRule.applicationRoot(containing: selectedURL) else { continue }
                let path = url.path
                guard !applications.contains(where: { $0.path == path }) else { continue }
                let app = ApplicationRule(path: path, name: url.deletingPathExtension().lastPathComponent,
                                          signingIdentifiers: signingIdentifiers(at: url))
                applications.append(app)
            }
            applyApplications(applications)
        }
    }

    private func applyApplications(_ applications: [ApplicationRule]) {
        var updated = configuration
        updated.applications = applications
        busy = true
        error = nil
        Task {
            defer { busy = false }
            do {
                try updated.validate()
                if connected {
                    guard let session = manager?.connection as? NETunnelProviderSession else {
                        throw ProxyError.connectionClosed
                    }
                    let message = try JSONEncoder().encode(updated)
                    let response: Data? = try await withCheckedThrowingContinuation { continuation in
                        do {
                            try session.sendProviderMessage(message) { continuation.resume(returning: $0) }
                        } catch { continuation.resume(throwing: error) }
                    }
                    guard response == Data([0]) else {
                        throw NSError(domain: "AppProxy", code: 3, userInfo: [NSLocalizedDescriptionKey:
                            response.flatMap { String(data: $0, encoding: .utf8) } ?? "Расширение не подтвердило изменение правил."])
                    }
                }
                configuration.applications = applications
                saveSettings()
                refreshApplications()
            } catch { self.error = error.localizedDescription }
        }
    }

    func saveSettings() {
        do { UserDefaults.standard.set(try JSONEncoder().encode(configuration), forKey: settingsKey) }
        catch { self.error = error.localizedDescription }
    }

    func checkProxy() {
        busy = true
        error = nil
        Task {
            defer { busy = false }
            do {
                try configuration.validate()
                try await probeProxy()
                status = "Прокси отвечает"
            } catch { self.error = error.localizedDescription }
        }
    }

    private func probeProxy() async throws {
        let endpoint = NWEndpoint.hostPort(host: .init(configuration.host), port: .init(rawValue: UInt16(configuration.port))!)
        let tcp = ProxySocket(endpoint: endpoint)
        defer { tcp.cancel() }
        _ = try await tcp.negotiate(command: 1, destination: .init(host: "example.com", port: 443))
        let udp = ProxySocket(endpoint: endpoint)
        defer { udp.cancel() }
        _ = try await udp.negotiate(command: 3, destination: .init(host: "0.0.0.0", port: 0))
    }

    func enable() {
        busy = true
        error = nil
        saveSettings()
        Task {
            do {
                try configuration.validate()
                guard !configuration.applications.isEmpty else {
                    throw NSError(domain: "AppProxy", code: 1, userInfo: [NSLocalizedDescriptionKey: "Выберите хотя бы одно приложение."])
                }
                try await probeProxy()
                status = "macOS проверяет системное расширение"
                let activation = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: ProxyConfiguration.providerID, queue: .main)
                activation.delegate = self
                request = activation
                OSSystemExtensionManager.shared.submitRequest(activation)
            } catch { self.error = error.localizedDescription; busy = false }
        }
    }

    func disable() {
        manager?.connection.stopVPNTunnel()
        status = "Прокси выключается"
    }

    private func loadManager() async throws {
        let managers: [NETransparentProxyManager] = try await withCheckedThrowingContinuation { continuation in
            NETransparentProxyManager.loadAllFromPreferences { managers, error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: managers ?? []) }
            }
        }
        manager = managers.first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == ProxyConfiguration.providerID
        }
    }

    private func startProxy() async {
        defer { busy = false }
        do {
            try await loadManager()
            let manager = manager ?? NETransparentProxyManager()
            self.manager = manager
            if manager.connection.status != .disconnected && manager.connection.status != .invalid {
                throw NSError(domain: "AppProxy", code: 2,
                              userInfo: [NSLocalizedDescriptionKey: "Выключите прокси перед изменением правил."])
            }
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = ProxyConfiguration.providerID
            proto.serverAddress = "\(configuration.host):\(configuration.port)"
            proto.providerConfiguration = try configuration.providerDictionary
            manager.protocolConfiguration = proto
            manager.localizedDescription = "App Proxy"
            manager.isEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            try manager.connection.startVPNTunnel()
            refreshStatus()
        } catch { self.error = error.localizedDescription }
    }

    private func refreshStatus() {
        let state = manager?.connection.status ?? .disconnected
        connected = state == .connected || state == .connecting || state == .reasserting
        switch state {
        case .connected: status = "Прокси работает"
        case .connecting, .reasserting: status = "Прокси подключается"
        case .disconnecting: status = "Прокси выключается"
        default: status = "Прокси выключен"
        }
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        status = "Разрешите App Proxy в настройках macOS: Основные → Объекты входа и расширения → Сетевые расширения."
        NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")!)
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        self.request = nil
        if result == .completed { Task { await startProxy() } }
        else { status = "macOS требует перезагрузку для активации расширения"; busy = false }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        self.request = nil
        self.error = "\(error.localizedDescription) [\((error as NSError).domain):\((error as NSError).code)]"
        busy = false
    }

    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }

    private func signingIdentifiers(at root: URL) -> [String] {
        var urls = [root]
        if let enumerator = FileManager.default.enumerator(at: root.appendingPathComponent("Contents"),
                includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) {
            for case let url as URL in enumerator where ["app", "xpc"].contains(url.pathExtension) { urls.append(url) }
        }
        return Array(Set(urls.compactMap { url -> String? in
            var code: SecStaticCode?
            guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code else { return nil }
            var information: CFDictionary?
            guard SecCodeCopySigningInformation(code, [], &information) == errSecSuccess else { return nil }
            return (information as? [String: Any])?[kSecCodeInfoIdentifier as String] as? String
        }))
    }
}

private struct ContentView: View {
    @ObservedObject var model: ProxyModel

    var body: some View {
        HSplitView {
            VStack(alignment: .leading, spacing: 20) {
                Label("App Proxy", systemImage: "network")
                    .font(.title2.weight(.semibold))
                Text("Выберите приложения для подключения через прокси.")
                    .foregroundStyle(.secondary)
                GroupBox("SOCKS5") {
                    VStack(alignment: .leading, spacing: 12) {
                        TextField("Адрес", text: $model.configuration.host)
                        HStack {
                            Text("Порт")
                            TextField("Порт", value: $model.configuration.port, format: .number.grouping(.never))
                        }
                        Button("Проверить прокси") { model.checkProxy() }
                    }
                    .textFieldStyle(.roundedBorder)
                    .padding(8)
                }
                .disabled(model.busy || model.connected)
                Label(model.status, systemImage: model.connected ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(model.connected ? Color.green : Color.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("proxyStatus")
                if model.busy { ProgressView().controlSize(.small) }
                if let error = model.error {
                    Text(error).foregroundStyle(.red).textSelection(.enabled)
                        .accessibilityIdentifier("proxyError")
                }
                Spacer()
                Text("Системный DNS может использовать обычное подключение.")
                    .font(.caption).foregroundStyle(.secondary)
                Button(model.connected ? "Выключить" : "Включить") {
                    if model.connected { model.disable() } else { model.enable() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.busy)
                .controlSize(.large)
                .frame(maxWidth: .infinity)
            }
            .padding(24)
            .frame(width: 280)
            VStack(spacing: 0) {
                HStack {
                    TextField("Поиск приложений", text: $model.search)
                        .textFieldStyle(.roundedBorder)
                    Button { model.refreshApplications() } label: { Image(systemName: "arrow.clockwise") }
                        .help("Обновить список")
                    Button { model.addApplication() } label: { Image(systemName: "plus") }
                        .help("Добавить приложение")
                }
                .padding()
                List(model.filteredApplications) { app in
                    HStack(alignment: .center, spacing: 12) {
                        Toggle(app.name, isOn: Binding(get: { model.isSelected(app) }, set: { model.select(app, selected: $0) }))
                            .labelsHidden()
                            .toggleStyle(.checkbox)
                            .frame(width: 20)
                            .accessibilityLabel(app.name)
                            Image(nsImage: NSWorkspace.shared.icon(forFile: app.path))
                                .resizable().frame(width: 32, height: 32)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(app.name)
                                Text(app.path).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(.vertical, 4)
                }
                .listStyle(.inset)
                HStack {
                    Text("Выбрано: \(model.configuration.applications.count)")
                    Spacer()
                    Text("Правила действуют для новых соединений")
                }
                .font(.caption).foregroundStyle(.secondary).padding()
            }
            .disabled(model.busy)
        }
        .onChange(of: model.configuration.host) { model.saveSettings() }
        .onChange(of: model.configuration.port) { model.saveSettings() }
    }
}
