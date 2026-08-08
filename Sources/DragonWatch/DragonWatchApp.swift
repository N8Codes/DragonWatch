import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Menu-bar-only app: no Dock icon, no app switcher entry.
        NSApp.setActivationPolicy(.accessory)

        // Single instance: rebuilding the bundle while an old copy runs (or a
        // stray debug build) would otherwise put two shields in the menu bar.
        // Asking our own older siblings to quit is self-management — the
        // read-only rule is about everyone else's software.
        if let bundleID = Bundle.main.bundleIdentifier {
            let ownPID = ProcessInfo.processInfo.processIdentifier
            for sibling in NSRunningApplication.runningApplications(
                withBundleIdentifier: bundleID)
            where sibling.processIdentifier != ownPID {
                sibling.terminate()
            }
        }
    }
}

@main
struct DragonWatchApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            ContentView()
                .environment(model)
        } label: {
            // The label is always mounted, so monitoring starts at launch,
            // not on first click.
            StatusIconView(model: model)
                .onAppear { model.start() }
        }
        .menuBarExtraStyle(.window)
    }
}
