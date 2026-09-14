import Foundation
import UserNotifications
import os

/// Whether macOS will actually show DragonWatch's banners. The alert pipeline
/// can be working perfectly and still be silent: notifications are gated by a
/// per-app permission in System Settings, and a refused or never-granted one
/// used to be invisible — the app never checked, so the only symptom was
/// "I didn't get a notification".
enum NotificationPermission: Equatable, Sendable {
    /// Not asked yet, or running without a bundle (no notifications possible).
    case unknown
    case allowed
    /// Turned off in System Settings > Notifications.
    case denied
    /// The permission request itself failed; the message is the system's.
    case failed(String)

    static func from(status: UNAuthorizationStatus, requestError: Error?) -> Self {
        switch status {
        case .authorized, .provisional: .allowed
        case .denied: .denied
        case .notDetermined: requestError.map { .failed($0.localizedDescription) } ?? .unknown
        @unknown default: .unknown
        }
    }
}

enum AlertKind: String, CaseIterable, Sendable {
    case newUntrustedProcess
    case invalidSignature
    case newPersistenceItem
    case binaryReplaced
    case sustainedCPU
    case networkChange

    var displayName: String {
        switch self {
        case .newUntrustedProcess: "New non-trusted process"
        case .invalidSignature: "Invalid signature"
        case .newPersistenceItem: "New persistence item"
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
        case .newUntrustedProcess, .sustainedCPU, .networkChange: nil
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
    private(set) var notificationPermission: NotificationPermission = .unknown

    nonisolated private static let log = Logger(
        subsystem: "com.dragonwatch.DragonWatch", category: "notifications")

    private var throttle = AlertThrottle()
    private let notificationDelegate = ForegroundBannerDelegate()
    private let canNotify: Bool
    private static let historyLimit = 100

    /// `canNotify` defaults to "running from a real app bundle". Tests pass
    /// false: `xctest` has a bundle identifier of its own, and
    /// `UNUserNotificationCenter.current()` crashes without an app bundle.
    init(canNotify: Bool = Bundle.main.bundleIdentifier != nil) {
        self.canNotify = canNotify
    }

    func requestAuthorizationIfNeeded() {
        guard canNotify else { return }
        let center = UNUserNotificationCenter.current()
        // Accessory apps count as "foreground", which suppresses banners
        // unless a delegate says otherwise.
        center.delegate = notificationDelegate
        center.requestAuthorization(options: [.alert, .sound]) { [weak self] granted, error in
            if let error {
                Self.log.error(
                    "Notification authorization failed: \(error.localizedDescription, privacy: .public)"
                )
            } else {
                Self.log.info("Notification authorization granted: \(granted)")
            }
            Task { @MainActor in self?.refreshNotificationPermission(requestError: error) }
        }
    }

    /// Re-reads the system's answer, so Settings can show it and reflect a
    /// change the user just made in System Settings.
    func refreshNotificationPermission(requestError: Error? = nil) {
        guard canNotify else { return }
        UNUserNotificationCenter.current().getNotificationSettings { [weak self] settings in
            let permission = NotificationPermission.from(
                status: settings.authorizationStatus, requestError: requestError)
            Self.log.info(
                "Notification settings: status \(settings.authorizationStatus.rawValue) alerts \(settings.alertSetting.rawValue)"
            )
            Task { @MainActor in self?.notificationPermission = permission }
        }
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

    /// Drops one alert from the in-app list. The caller mirrors the removal
    /// into the durable record, or the alert is back on the next launch.
    func dismiss(_ id: AlertEvent.ID) {
        history.removeAll { $0.id == id }
        if history.isEmpty { unreadCount = 0 }
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
