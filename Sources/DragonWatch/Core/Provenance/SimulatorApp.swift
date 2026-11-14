import Foundation

/// An app running inside the iOS Simulator: a debug build (ad-hoc signed by
/// design) that Xcode copied into a simulator device's data folder and the
/// simulator's own launcher, `launchd_sim`, started.
///
/// Test runs clone a fresh device for every run
/// (`~/Library/Developer/XCTestDevices/<UUID>/…`), so the same app shows up
/// at a new path each time and a once-per-path alert fired on every
/// `xcodebuild test`. Recognising the case lets the alert say what it is and
/// throttle per build (cdhash) instead of per path.
///
/// This is context, never trust: the rating is untouched. Both halves must
/// match — the device-folder shape *and* a `launchd_sim` parent from the
/// root-owned CoreSimulator runtime or Xcode itself — so a binary that is
/// merely copied into a device folder, or one that names itself
/// `launchd_sim` somewhere writable, does not qualify.
enum SimulatorApp {
    static let launcherPrefixes = [
        "/Library/Developer/CoreSimulator/",
        "/Applications/Xcode.app/",
    ]

    static func matches(path: String, launch: LaunchContext?) -> Bool {
        guard let parent = launch?.parentPath,
            (parent as NSString).lastPathComponent == "launchd_sim",
            launcherPrefixes.contains(where: parent.hasPrefix)
        else { return false }
        return isDeviceAppPath(path)
    }

    /// `/Users/<u>/Library/Developer/XCTestDevices/<UUID>/data/Containers/Bundle/Application/…`
    /// or the same under `CoreSimulator/Devices/<UUID>/`. Matched by shape so
    /// it holds for every user.
    static func isDeviceAppPath(_ path: String) -> Bool {
        let c = (path as NSString).pathComponents
        // ["/", "Users", u, "Library", "Developer", …]
        guard c.count > 6, c[1] == "Users", c[3] == "Library", c[4] == "Developer"
        else { return false }
        let rest: ArraySlice<String>
        if c[5] == "XCTestDevices" {
            rest = c[6...]
        } else if c[5] == "CoreSimulator", c.count > 7, c[6] == "Devices" {
            rest = c[7...]
        } else {
            return false
        }
        // <UUID>, "data", "Containers", "Bundle", "Application", <UUID>, <x>.app, …
        let tail = Array(rest)
        return tail.count >= 7
            && UUID(uuidString: tail[0]) != nil
            && Array(tail[1...4]) == ["data", "Containers", "Bundle", "Application"]
    }

    /// Throttle key shared by every run of the same *build*: the cdhash,
    /// which is identical across the device clones Xcode copies one build
    /// into. Not the executable name — anything running as the user can
    /// `simctl install` an app with the same name and would share the real app's
    /// key, silencing its own alert. nil (no cdhash) means throttle per path.
    static func throttleKey(cdhash: Data?) -> String? {
        cdhash.map { "simulator:" + $0.map { String(format: "%02x", $0) }.joined() }
    }

    /// Says where it runs, not who put it there: an app installed with
    /// `simctl` looks exactly like one Xcode installed.
    static let note =
        " iOS Simulator app — installed into a simulator device and started by"
        + " the simulator. Repeat runs of the same build alert once a day, not"
        + " once per device folder."
}
