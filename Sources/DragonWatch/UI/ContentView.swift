import SwiftUI

enum PanelTab {
    case processes
    case tree
    case alerts
    case review
    case criteria
    case settings
}

struct ContentView: View {
    @Environment(AppModel.self) private var model
    @AppStorage("hasOnboarded") private var hasOnboarded = false
    @AppStorage("list.sort") private var sortRaw = ProcessListSort.riskFirst.rawValue
    @State private var tab: PanelTab = .processes
    @State private var selection: MonitoredProcess?
    @State private var inspectedGroupID: String?
    @State private var expandedGroups: Set<String> = []
    @State private var searchText = ""
    @Environment(\.openWindow) private var openWindow

    private var sort: ProcessListSort {
        ProcessListSort(rawValue: sortRaw) ?? .riskFirst
    }

    var body: some View {
        Group {
            if hasOnboarded {
                panel
            } else {
                OnboardingView { hasOnboarded = true }
            }
        }
        .frame(width: AppText.popoverWidth, height: AppText.popoverHeight)
        .onAppear { model.popoverDidOpen() }
        .onDisappear { model.popoverDidClose() }
        .onChange(of: model.pendingReview.isEmpty) { _, empty in
            // The Review tab disappears once the queue is empty, so anyone
            // standing on it when they answer the last item would be left
            // looking at a tab that no longer has a button.
            if empty, tab == .review { tab = .processes }
        }
    }

    private var panel: some View {
        VStack(spacing: 0) {
            VitalsHeaderView(vitals: model.vitals)
            Divider()
            switch tab {
            case .processes:
                searchField
                Divider()
                if model.hasSampled {
                    processList
                } else {
                    Spacer()
                    ProgressView("Assessing running processes…")
                        .controlSize(.small)
                    Spacer()
                }
                if let selection {
                    Divider()
                    ProcessDetailView(process: selection) { self.selection = nil }
                } else if let inspectedGroupID,
                    let group = model.groups.first(where: { $0.id == inspectedGroupID })
                {
                    Divider()
                    GroupDetailView(
                        group: group, allProcesses: model.groups.flatMap(\.members),
                        select: { selection = $0 },
                        dismiss: { self.inspectedGroupID = nil })
                }
            case .tree:
                // The whole machine as launchd sees it now. On demand only —
                // the main list stays grouped and stable; this one is allowed
                // to be big.
                ProcessTreeView(
                    nodes: ProcessTree.build(model.groups.flatMap(\.members)),
                    allProcesses: model.groups.flatMap(\.members),
                    select: { selection = $0 })
                if let selection {
                    Divider()
                    ProcessDetailView(process: selection) { self.selection = nil }
                }
            case .alerts:
                AlertHistoryView(alerts: model.alerts)
            case .review:
                ReviewView()
            case .criteria:
                CriteriaView()
            case .settings:
                SettingsView()
            }
            Divider()
            footer
        }
    }

    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .font(AppText.callout)
                .foregroundStyle(.secondary)
            TextField("Search apps and processes", text: $searchText)
                .textFieldStyle(.plain)
                .font(AppText.callout)
            if !searchText.isEmpty {
                Button {
                    searchText = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(AppText.callout)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Clear search")
                .accessibilityLabel("Clear search")
            }
            Divider().frame(height: 14)
            // Beside the search field, where the eye already is, and labelled
            // rather than relying on an icon being guessed.
            Button {
                openInspectWindow(openWindow)
            } label: {
                Label("Inspect a file", systemImage: "doc.viewfinder")
                    .font(AppText.callout)
            }
            .buttonStyle(.link)
            .help("Check whether a file is what it claims to be")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private var visibleGroups: [ProcessGroup] {
        sort.apply(ProcessFilter.apply(searchText, to: model.groups))
    }

    private var processList: some View {
        ScrollView {
            LazyVStack(spacing: 1) {
                if visibleGroups.isEmpty {
                    Text("Nothing matches “\(searchText)”.")
                        .font(AppText.callout)
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 24)
                }
                ForEach(visibleGroups) { group in
                    GroupRowView(
                        group: group,
                        isExpanded: expandedGroups.contains(group.id),
                        toggleExpanded: {
                            if !expandedGroups.insert(group.id).inserted {
                                expandedGroups.remove(group.id)
                            }
                        },
                        select: {
                            inspectedGroupID = nil
                            selection = $0
                        },
                        inspect: {
                            selection = nil
                            inspectedGroupID = $0.id
                        }
                    )
                }
            }
            .padding(6)
        }
    }

    private var footer: some View {
        HStack(spacing: 10) {
            tabButton(.processes, systemImage: "list.bullet", help: "Processes")
            tabButton(
                .tree, systemImage: "list.bullet.indent",
                help: "Process tree — every process, nested under what started it")
            tabButton(
                .alerts,
                systemImage: model.alerts.unreadCount > 0 ? "bell.badge.fill" : "bell",
                help: model.alerts.unreadCount > 0
                    ? "Alerts — \(model.alerts.unreadCount) unread" : "Alerts"
            )
            .overlay(alignment: .topTrailing) {
                if model.alerts.unreadCount > 0 {
                    Circle()
                        .fill(.red)
                        .frame(width: 7, height: 7)
                        .offset(x: 3, y: -3)
                        .accessibilityHidden(true)  // the label carries the count
                }
            }
            if !model.pendingReview.isEmpty {
                // Only present when a verdict is actually waiting: permanent
                // chrome for an empty queue is the clutter the banner was.
                tabButton(
                    .review, systemImage: "questionmark.diamond.fill",
                    help: "Review — \(model.pendingReview.count) awaiting a verdict"
                )
                .overlay(alignment: .topTrailing) {
                    Circle()
                        .fill(.orange)
                        .frame(width: 7, height: 7)
                        .offset(x: 3, y: -3)
                        .accessibilityHidden(true)  // the label carries the count
                }
            }
            tabButton(
                .criteria, systemImage: "list.bullet.rectangle",
                help: "How ratings are decided")
            tabButton(.settings, systemImage: "gearshape", help: "Settings")
            if tab == .processes {
                sortMenu
            }
            Spacer()
            if tab == .processes {
                Text(
                    searchText.isEmpty
                        ? "\(model.groups.count) apps & processes"
                        : "\(visibleGroups.count) of \(model.groups.count)"
                )
                .font(AppText.callout)
                .foregroundStyle(.secondary)
            }
            Button {
                model.runFullSweep()
            } label: {
                if model.sweeping {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "arrow.clockwise")
                }
            }
            .controlSize(.regular)
            .disabled(model.sweeping)
            .help(
                model.sweeping
                    ? "Sweeping…"
                    : "Full sweep — re-check every running process now, ignoring cached results"
            )
            .accessibilityLabel(model.sweeping ? "Sweeping" : "Run a full sweep now")

            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
            .controlSize(.regular)
            .help("Quit DragonWatch")
            .accessibilityLabel("Quit DragonWatch")
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
    }

    private var sortMenu: some View {
        Menu {
            Picker("Sort", selection: $sortRaw) {
                ForEach(ProcessListSort.allCases, id: \.rawValue) { mode in
                    Text(mode.label).tag(mode.rawValue)
                }
            }
            .pickerStyle(.inline)
            .labelsHidden()
        } label: {
            Image(systemName: "arrow.up.arrow.down")
                .font(AppText.icon(15))
                .foregroundStyle(.secondary)
                .frame(width: 24, height: 22)
                .contentShape(Rectangle())
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("Sort: \(sort.label)")
        // `.help` is a mouse tooltip: it reaches neither VoiceOver nor the
        // keyboard, so an icon-only menu is announced as an unnamed button.
        .accessibilityLabel("Sort process list")
        .accessibilityValue(sort.label)
    }

    private func tabButton(_ target: PanelTab, systemImage: String, help: String) -> some View {
        Button {
            tab = target
        } label: {
            Image(systemName: systemImage)
                .font(AppText.icon(15))
                .foregroundStyle(tab == target ? Color.accentColor : Color.secondary)
                .frame(width: 24, height: 22)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(help)
        .accessibilityLabel(help)
    }
}
