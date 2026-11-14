import XCTest

@testable import DragonWatch

extension AppModel {
    /// A model whose ledgers and settings live in throwaway storage. A bare
    /// `AppModel()` opens the installed app's Application Support directory,
    /// so a test run wrote into — and could move aside — the real ledgers.
    @MainActor
    static func isolated(for testCase: XCTestCase) -> AppModel {
        let storage = FileManager.default.temporaryDirectory
            .appendingPathComponent("AppModel-\(UUID().uuidString)")
        let suite = "DragonWatchTests-\(UUID().uuidString)"
        testCase.addTeardownBlock {
            try? FileManager.default.removeItem(at: storage)
            UserDefaults.standard.removePersistentDomain(forName: suite)
        }
        return AppModel(storageDirectory: storage, defaults: UserDefaults(suiteName: suite)!)
    }
}
