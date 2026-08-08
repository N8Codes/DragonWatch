import SwiftUI

enum PanelTab {
    case processes
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
    @State private var expandedGroups: Set<String> = []
    @State private var searchText = ""

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
        .frame(width: 460, height: 640)
        .onAppear { model.popoverDidOpen() }
        .onDisappear { model.popoverDidClose() }
    }

    private var panel: some View {
        VStack(spacing: 0) {
            VitalsHeaderView(vitals: model.vitals)
            Divider()
            switch tab {
            case .processes:
                searchField
                Divider()
                if !model.pendingReview.isEmpty {
                    reviewBanner
                    Divider()
                }
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

    private var reviewBanner: some View {
        Button {
            tab = .review
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "questionmark.diamond.fill")
                    .foregroundStyle(.orange)
                Text(
                    "\(model.pendingReview.count) new item\(model.pendingReview.count == 1 ? "" : "s") awaiting review"
                )
                .font(.body)
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
    }

    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .font(.callout)
                .foregroundStyle(.secondary)
            TextField("Search apps and processes", text: $searchText)
                .textFieldStyle(.plain)
                .font(.callout)
            if !searchText.isEmpty {
                Button {
                    searchText = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Clear search")
            }
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
                        .font(.callout)
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
                        select: { selection = $0 }
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
                .font(.callout)
                .foregroundStyle(.secondary)
            }
            Button("Quit DragonWatch") {
                NSApplication.shared.terminate(nil)
            }
            .controlSize(.regular)
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
                .font(.system(size: 15))
                .foregroundStyle(.secondary)
                .frame(width: 24, height: 22)
                .contentShape(Rectangle())
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("Sort: \(sort.label)")
    }

    private func tabButton(_ target: PanelTab, systemImage: String, help: String) -> some View {
        Button {
            tab = target
        } label: {
            Image(systemName: systemImage)
                .font(.system(size: 15))
                .foregroundStyle(tab == target ? Color.accentColor : Color.secondary)
                .frame(width: 24, height: 22)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(help)
        .accessibilityLabel(help)
    }
}
