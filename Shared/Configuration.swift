import Foundation

struct ApplicationRule: Codable, Identifiable, Equatable {
    var path: String
    var name: String
    var signingIdentifiers: [String]
    var id: String { path }

    static func applicationRoot(containing url: URL) -> URL? {
        var current = url.resolvingSymlinksInPath()
        var application: URL?
        while current.path != "/" {
            if current.pathExtension == "app" { application = current }
            current.deleteLastPathComponent()
        }
        return application
    }

    func matches(executablePath: String?, signingIdentifier: String) -> Bool {
        if let executablePath {
            return executablePath == path || executablePath.hasPrefix(path + "/Contents/")
        }
        return signingIdentifiers.contains(signingIdentifier)
    }
}

struct ProxyConfiguration: Codable {
    static let providerID = "dev.maxkamyshev.AppProxy.Proxy"
    var host = "127.0.0.1"
    var port = 10888
    var applications: [ApplicationRule] = []

    func validate() throws {
        guard !host.isEmpty, host == host.trimmingCharacters(in: .whitespacesAndNewlines),
              !host.contains(where: { $0.isWhitespace || $0 == "/" }),
              (1...65535).contains(port) else {
            throw ProxyError.invalidConfiguration
        }
        guard applications.allSatisfy({ $0.path.hasPrefix("/") && $0.path.hasSuffix(".app") }) else {
            throw ProxyError.invalidConfiguration
        }
    }

    var providerDictionary: [String: Any] {
        get throws { ["configuration": try JSONEncoder().encode(self)] }
    }

    init() {}

    init(dictionary: [String: Any]?) throws {
        guard let data = dictionary?["configuration"] as? Data else {
            throw ProxyError.invalidConfiguration
        }
        self = try JSONDecoder().decode(Self.self, from: data)
        try validate()
    }
}

enum ProxyError: LocalizedError {
    case invalidConfiguration, invalidResponse, unsupportedAddress, authenticationRequired, connectionClosed
    case serverRejected(UInt8)

    var errorDescription: String? {
        switch self {
        case .invalidConfiguration: return "Проверьте адрес, порт и список приложений."
        case .invalidResponse: return "Прокси вернул неверный ответ SOCKS5."
        case .unsupportedAddress: return "Прокси использует неподдерживаемый адрес или фрагментацию UDP."
        case .authenticationRequired: return "Прокси не поддерживает SOCKS5 без пароля."
        case .connectionClosed: return "Прокси закрыл соединение."
        case .serverRejected(let code): return "Прокси отклонил соединение. Код SOCKS5: \(code)."
        }
    }
}
