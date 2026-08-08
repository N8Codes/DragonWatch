import SwiftUI

/// The menu bar dragon eye — the app's top-level status display. Plain when
/// all is clear; a warning badge appears when something deserves a look.
struct StatusIconView: View {
    let model: AppModel

    var body: some View {
        DragonEyeIcon(badge: model.overallBadge)
    }
}
