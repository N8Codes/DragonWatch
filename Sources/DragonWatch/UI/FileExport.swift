import AppKit

/// Saving something the user asked to export.
///
/// Written owner-only wherever they put it: a history or an inspection
/// report names files and hashes, which is an inventory of the machine. And
/// a save that was asked for must not fail silently.
@MainActor
enum FileExport {
    static func save(_ data: Data, suggestedName: String, message: String? = nil) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        if let message { panel.message = message }
        // A panel opened from a menu bar popover needs the app activated first.
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try AppSupport.writePrivately(data, to: url)
        } catch {
            reportFailure(error.localizedDescription)
        }
    }

    static func reportFailure(_ reason: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "The file was not saved"
        alert.informativeText = reason
        alert.runModal()
    }
}
