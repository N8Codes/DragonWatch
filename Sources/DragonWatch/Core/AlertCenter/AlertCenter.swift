import Foundation
import UserNotifications

enum AlertKind: String, CaseIterable, Sendable {
    case newUntrustedProcess
    case invalidSignature
    case newPersistenceItem
    case knownMalware
    case binaryReplaced
    case sustainedCPU
    case networkChange

    var displayName: String {
        switch self {
        case .newUntrustedProcess: "New non-trusted process"
        case .invalidSignature: "Invalid signature"
        case .newPersistenceItem: "New persistence item"
        case .knownMalware: "Known-malware hash match"
        case .binaryReplaced: "Binary replaced in place"
        case .sustainedCPU: "Sustained CPU spike"
        case .networkChange: "Network drop / restore"
        }
    }

    var symbolName: String {
        switch self {
        case .newUntrustedProcess: "questionmark.app"
        case .invalidSignature: "xmark.seal"
        case .newPersistenceItem: "pin"
        case .knownMalware: "exclamationmark.octagon"
        case .binaryReplaced: "arrow.triangle.2.circlepath"
        case .sustainedCPU: "cpu"
        case .networkChange: "wifi.exclamationmark"
        }
    }

    /// MITRE ATT&CK technique this alert maps to, where the mapping is solid —
    /// a lookup key for further reading, not a claim of attribution.
    var attackTechnique: String? {
        switch self {
        case .newPersistenceItem: "ATT&CK T1543"  // Create/Modify System Process
        case .invalidSignature: "ATT&CK T1036.001"  // Invalid Code Signature
        case .binaryReplaced: "ATT&CK T1036"  // Masquerading
        case .newUntrustedProcess, .knownMalware, .sustainedCPU, .networkChange: nil
        }
    }
}

struct AlertEvent: Identifiable, Sendable {
    let id = UUID()
    let kind: AlertKind
    let title: String
    let detail: String
    let date: Date
}

/// Every alert rule's shared outlet: throttles, keeps the in-app history, and
/// posts user notifications. UserNotifications requires an app bundle, so a
/// bare `swift run` binary keeps the history view only.
@MainActor
@Observable final class AlertCenter {
    private(set) var history: [AlertEvent] = []
    private(set) var unreadCount = 0

    private var throttle = AlertThrottle()
    private let notificationDelegate = ForegroundBannerDelegate()
    private let canNotify = Bundle.main.bundleIdentifier != nil
    private static let historyLimit = 100

    func requestAuthorizationIfNeeded() {
        guard canNotify else { return }
        let center = UNUserNotificationCenter.current()
        // Accessory apps count as "foreground", which suppresses banners
        // unless a delegate says otherwise.
        center.delegate = notificationDelegate
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    /// Returns whether the alert actually fired (i.e. survived the throttle),
    /// so callers can mirror fired alerts into the durable event record.
    @discardableResult
    func raise(
        _ kind: AlertKind,
        key: String,
        cooldown: TimeInterval,
        title: String,
        detail: String,
        now: Date = Date()
    ) -> Bool {
        let throttleKey = "\(kind.rawValue):\(key)"
        guard throttle.shouldFire(key: throttleKey, cooldown: cooldown, now: now) else {
            return false
        }
        history.insert(
            AlertEvent(kind: kind, title: title, detail: detail, date: now), at: 0)
        if history.count > Self.historyLimit {
            history.removeLast(history.count - Self.historyLimit)
        }
        unreadCount += 1
        postNotification(title: title, detail: detail)
        return true
    }

    /// Restores past alerts (newest first) from the durable record at launch —
    /// history only, no notifications and no unread badge.
    func seedHistory(_ events: [AlertEvent]) {
        guard history.isEmpty, !events.isEmpty else { return }
        history = Array(events.prefix(Self.historyLimit))
    }

    func markAllRead() {
        unreadCount = 0
    }

    func clearHistory() {
        history = []
        unreadCount = 0
    }

    private func postNotification(title: String, detail: String) {
        guard canNotify else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = detail
        content.sound = .default
        UNUserNotificationCenter.current().add(
            UNNotificationRequest(
                identifier: UUID().uuidString, content: content, trigger: nil))
    }
}

private final class ForegroundBannerDelegate: NSObject, UNUserNotificationCenterDelegate {
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler:
            @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }
}
