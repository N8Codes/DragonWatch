import Foundation

/// Package-manager provenance for a binary inside a Homebrew keg
/// (`…/Cellar/<formula>/<version>/…`). Homebrew bottles poured on Intel Macs
/// carry no code signature at all, so "Unsigned" alone cannot tell a brew
/// install from a dropped binary — the install receipt can. This is context,
/// never trust: a receipt says brew put *something* here, not that the file
/// is still what brew wrote.
struct HomebrewKeg: Equatable, Sendable {
    let formula: String
    let version: String
    let installedAt: Date?
    let pouredFromBottle: Bool?

    /// Where Homebrew actually lives. A receipt anywhere else — say
    /// `~/Downloads/x/Cellar/tool/1.0/` — is a file anything could write to
    /// dress up a dropped binary, so it does not count.
    static let prefixes = ["/usr/local/Cellar/", "/opt/homebrew/Cellar/"]

    /// One line for alerts and rows: "Homebrew receipt: node 25.9.0_3, poured
    /// from bottle, installed 2 May 2026". "Receipt" is deliberate — it is a
    /// claim read from a file, not a verified fact about the binary.
    var summary: String {
        var parts = ["Homebrew receipt: \(formula) \(version)"]
        switch pouredFromBottle {
        case true: parts.append("poured from bottle")
        case false: parts.append("built from source")
        case nil: break
        }
        if let installedAt {
            parts.append(
                "installed \(installedAt.formatted(date: .abbreviated, time: .omitted))")
        }
        return parts.joined(separator: ", ")
    }

    /// The keg root for a path, when the path is inside a real Homebrew
    /// Cellar. Pure string work so it is testable without a filesystem.
    static func kegRoot(of path: String) -> String? {
        guard let prefix = prefixes.first(where: { path.hasPrefix($0) }) else { return nil }
        let rest = path.dropFirst(prefix.count).split(
            separator: "/", omittingEmptySubsequences: false)
        // formula, version, then at least one file component inside the keg
        guard rest.count >= 3, !rest[0].isEmpty, !rest[1].isEmpty, !rest[2].isEmpty
        else { return nil }
        return prefix + rest[0] + "/" + rest[1]
    }

    /// Reads `INSTALL_RECEIPT.json` for the keg containing `path`. One small
    /// JSON read; nil when the path is not in a keg or the receipt is
    /// missing or unreadable.
    static func locate(path: String) -> HomebrewKeg? {
        guard let root = kegRoot(of: path) else { return nil }
        let receiptURL = URL(fileURLWithPath: root).appendingPathComponent("INSTALL_RECEIPT.json")
        guard let data = try? Data(contentsOf: receiptURL) else { return nil }
        return parse(receipt: data, kegRoot: root)
    }

    static func parse(receipt data: Data, kegRoot root: String) -> HomebrewKeg? {
        guard let object = try? JSONSerialization.jsonObject(with: data),
            let receipt = object as? [String: Any]
        else { return nil }
        let components = root.split(separator: "/")
        guard components.count >= 2 else { return nil }
        let installedAt = (receipt["time"] as? Double).map {
            Date(timeIntervalSince1970: $0)
        }
        return HomebrewKeg(
            formula: String(components[components.count - 2]),
            version: String(components[components.count - 1]),
            installedAt: installedAt,
            pouredFromBottle: receipt["poured_from_bottle"] as? Bool)
    }
}
