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

        // A window, not a popover tab. A menu bar popover closes the moment
        // focus moves — including to the file picker this window opens —
        // so results appeared only after reopening it. A window survives that
        // and can be left open while files are dragged onto it.
        Window("Inspect Files", id: DragonWatchApp.inspectWindowID) {
            InspectView()
                .environment(model)
                .frame(minWidth: 560, minHeight: 460)
        }
        .defaultSize(width: 700, height: 720)
        .windowResizability(.contentMinSize)
    }

    /// Shared so the button that opens it cannot drift from the scene.
    static let inspectWindowID = "inspect"
}

extension View {
    /// Opens the inspection window and brings it forward.
    ///
    /// An accessory app has no Dock icon and is not frontmost, so without the
    /// activate call the window opens behind whatever the user is looking at.
    func openInspectWindow(_ open: OpenWindowAction) {
        open(id: DragonWatchApp.inspectWindowID)
        // Ordering happens on the next turn of the run loop: the window does
        // not exist yet on this one, and the menu bar popover is still key.
        // Activating then ordering the window front puts it in front and lets
        // the popover dismiss behind it, rather than the window opening
        // underneath whatever was already on screen.
        DispatchQueue.main.async {
            NSApp.activate(ignoringOtherApps: true)
            let window = NSApp.windows.first {
                $0.identifier?.rawValue.contains(DragonWatchApp.inspectWindowID) == true
            }
            window?.makeKeyAndOrderFront(nil)
        }
    }
}
