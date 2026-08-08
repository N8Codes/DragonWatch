import Foundation
import Network

/// Passive network status via NWPathMonitor — event-driven, costs nothing.
@MainActor
@Observable final class NetworkMonitor {
    private(set) var summary = "Checking…"
    private(set) var isUp = false

    private let monitor = NWPathMonitor()
    private var started = false

    func start() {
        guard !started else { return }
        started = true
        monitor.pathUpdateHandler = { [weak self] path in
            let up = path.status == .satisfied
            let summary: String
            if !up {
                summary = "Offline"
            } else if path.usesInterfaceType(.wifi) {
                summary = "Wi-Fi"
            } else if path.usesInterfaceType(.wiredEthernet) {
                summary = "Ethernet"
            } else if path.usesInterfaceType(.cellular) {
                summary = "Cellular"
            } else {
                summary = "Connected"
            }
            Task { @MainActor [weak self] in
                self?.isUp = up
                self?.summary = summary
            }
        }
        monitor.start(queue: DispatchQueue(label: "dragonwatch.network"))
    }
}
