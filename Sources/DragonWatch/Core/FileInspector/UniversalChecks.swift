import Foundation

/// The checks that run on every file regardless of what it turns out to be.
///
/// Pure: everything it needs is already in the `FileProbe`. These are the
/// cheap, high-yield rules — an extension that disagrees with the bytes, a
/// filename engineered to display backwards, a payload appended to the end of
/// something harmless. The format-specific inspectors build on top.
enum UniversalChecks {

    /// Runs every universal rule. Findings come back in a fixed order so two
    /// runs over the same file render identical reports.
    /// The content checks run only when the contents were actually read.
    /// A folder or a symlink has an empty `head`, and letting the type check
    /// see that turns "we did not open this" into "we opened it and could not
    /// confirm it" — a claim about bytes nobody looked at. The name and trait
    /// checks still apply, because a name is readable either way.
    static func run(
        probe: FileProbe,
        identified: FileFormat?,
        accountedForOffsets: Set<Int64> = []
    ) -> [Finding] {
        var findings: [Finding] = []
        if probe.isReadable {
            findings.append(contentsOf: typeConsistency(probe: probe, identified: identified))
        }
        findings.append(contentsOf: filename(probe.displayName))
        if probe.isReadable {
            findings.append(
                contentsOf: embeddedSignatures(
                    probe: probe, identified: identified,
                    accountedForOffsets: accountedForOffsets))
        }
        findings.append(contentsOf: fileTraits(probe: probe))
        return findings
    }

    /// Neutral facts. Where a file came from is worth showing and argues
    /// nothing — a quarantine xattr on a downloaded file is the *normal*
    /// state, the same lesson `TrustScoring.applies` already encodes.
    static func disclosures(probe: FileProbe) -> [Disclosure] {
        var disclosures: [Disclosure] = []
        if probe.quarantine != nil {
            let agent = quarantineAgent(probe.quarantine)
            disclosures.append(
                Disclosure(
                    title: "Downloaded file",
                    detail: agent.map { "Quarantine attribute set by \($0)." }
                        ?? "Quarantine attribute present — macOS marks downloads this way."))
        }
        // Chrome records the download URL and the referrer, and for a direct
        // download they are the same string; listing it twice read as an error.
        var seen = Set<String>()
        let origins = probe.whereFrom.filter { seen.insert($0).inserted }
        let shown = 4
        for origin in origins.prefix(shown) {
            disclosures.append(
                Disclosure(title: "Came from", detail: displaySafe(origin, limit: 180)))
        }
        // Dropping the rest silently would understate how much provenance the
        // file actually carries.
        let hidden = probe.whereFrom.count - shown
        if hidden > 0 {
            disclosures.append(
                Disclosure(
                    title: "Additional origins",
                    detail: "\(hidden) more recorded origin\(hidden == 1 ? "" : "s") "
                        + "not shown here."))
        }
        return disclosures
    }

    // MARK: - Does the extension agree with the bytes?

    static func typeConsistency(probe: FileProbe, identified: FileFormat?) -> [Finding] {
        let ext = probe.declaredExtension
        let expected = MagicBytes.formats(forExtension: ext)

        switch (identified, expected.isEmpty) {
        case (let found?, false):
            guard !expected.contains(found) else { return [] }
            // An image under another image's name is the commonest mislabel
            // there is — sites serve one format as another, browsers save
            // WebP as .jpg — and nothing in it can run. Reporting it in red
            // taught users that red means nothing. Same family, nothing
            // runnable on either side: Caution, and it says why.
            if isBenignMislabel(found: found, expected: expected, ext: ext) {
                return [
                    Finding(
                        rule: "magic.mislabelled",
                        severity: .caution,
                        title: "Mislabelled \(found.family.rawValue): contents are \(found.name)",
                        detail:
                            "Named .\(displaySafe(ext, limit: 24)), which would be \(list(expected)), "
                            + "but the contents are \(found.name). Both are \(found.family.rawValue) "
                            + "formats, so nothing here can run; this is common when a site "
                            + "serves one format under another's name or a file is renamed. "
                            + "The name is still wrong.")
                ]
            }
            // The strongest signal this whole feature produces: the file says
            // one thing and its first bytes say another.
            return [
                Finding(
                    rule: "magic.mismatch",
                    severity: .inconsistent,
                    title: "Extension does not match contents",
                    detail:
                        "Named .\(displaySafe(ext, limit: 24)), which would be \(list(expected)), "
                        + "but the contents are "
                        + "\(found.name).")
            ]

        case (nil, false):
            return [
                Finding(
                    rule: "magic.unconfirmed",
                    severity: .caution,
                    title: "Contents could not be confirmed",
                    detail:
                        "Named .\(displaySafe(ext, limit: 24)), which would be \(list(expected)), "
                        + "but the first bytes "
                        + "match no format DragonWatch recognises. The file may be corrupt, "
                        + "truncated, or a variant not in the table.")
            ]

        case (_?, true):
            // Bytes recognised, extension unknown or absent. Informational:
            // extensionless files are normal on a Mac.
            return []

        case (nil, true):
            // Text has no signature by nature. A source or text extension with
            // unrecognised bytes is the normal case, and `SourceInspector`
            // examines the contents; calling it "not recognised" was noise.
            guard !SourceInspector.sourceExtensions.contains(ext) else { return [] }
            return [
                Finding(
                    rule: "magic.unclassified",
                    severity: .info,
                    title: "Format not recognised",
                    detail:
                        "No signature matched, and .\(ext.isEmpty ? "(none)" : displaySafe(ext, limit: 24)) "
                        + "maps to no "
                        + "known format. First bytes: \(hexPreview(probe.head)).")
            ]
        }
    }

    /// A mismatch that stays within one family with nothing runnable on
    /// either side. Runnable means the executable family, a format whose
    /// canonical extension macOS would launch — a disk image under a .zip
    /// name is still a disk image — or a declared extension that would be
    /// launched, which is the name the user double-clicks.
    static func isBenignMislabel(found: FileFormat, expected: [FileFormat], ext: String) -> Bool {
        let foundRunnable =
            found.family == .executable
            || MagicBytes.executableExtensions.contains(found.extensions.first ?? "")
        guard !foundRunnable, !MagicBytes.executableExtensions.contains(ext) else { return false }
        return expected.contains { $0.family == found.family }
    }

    // MARK: - Is the filename itself deceptive?

    static func filename(_ name: String) -> [Finding] {
        var findings: [Finding] = []

        // Right-to-left override and friends: the classic way to make
        // "report<RLO>fdp.exe" render as "reportexe.pdf" in Finder.
        let bidi: Set<Unicode.Scalar> = [
            "\u{202A}", "\u{202B}", "\u{202C}", "\u{202D}", "\u{202E}",
            "\u{2066}", "\u{2067}", "\u{2068}", "\u{2069}",
            "\u{200E}", "\u{200F}",
        ]
        let foundBidi = name.unicodeScalars.filter { bidi.contains($0) }
        if !foundBidi.isEmpty {
            findings.append(
                Finding(
                    rule: "name.bidi",
                    severity: .inconsistent,
                    title: "Filename contains text-direction overrides",
                    detail:
                        "The name carries \(foundBidi.count) bidirectional control character"
                        + "\(foundBidi.count == 1 ? "" : "s") "
                        + "(\(foundBidi.map(codePoint).joined(separator: ", "))), which make it "
                        + "display differently from what it is. Legitimate files effectively "
                        + "never need these."))
        }

        let invisible: Set<Unicode.Scalar> = [
            "\u{200B}", "\u{200C}", "\u{200D}", "\u{2060}", "\u{FEFF}",
        ]
        let foundInvisible = name.unicodeScalars.filter { invisible.contains($0) }
        if !foundInvisible.isEmpty {
            findings.append(
                Finding(
                    rule: "name.invisible",
                    severity: .caution,
                    title: "Filename contains invisible characters",
                    detail:
                        "The name carries \(foundInvisible.count) zero-width character"
                        + "\(foundInvisible.count == 1 ? "" : "s") "
                        + "(\(foundInvisible.map(codePoint).joined(separator: ", "))), so it may "
                        + "not be the name it appears to be."))
        }

        if let double = doubleExtension(name) {
            findings.append(
                Finding(
                    rule: "name.doubleExtension",
                    severity: .caution,
                    title: "Runnable file wearing a document extension",
                    detail:
                        "The name ends .\(displaySafe(double.masking, limit: 24))"
                        + ".\(displaySafe(double.actual, limit: 24)) — it reads as a "
                        + "\(displaySafe(double.masking, limit: 24)) file but macOS would treat "
                        + "it as \(displaySafe(double.actual, limit: 24))."))
        }

        return findings
    }

    /// Flags `photo.jpg.exe` but not `archive.tar.gz` or `deploy.test.sh`.
    ///
    /// The rule needs *both* halves to be meaningful: the last extension must
    /// be something macOS would run, and the one before it must be a format
    /// people recognise as inert. Requiring only the first half flags every
    /// shell script with a dot in its name.
    static func doubleExtension(_ name: String) -> (masking: String, actual: String)? {
        let parts = name.lowercased().split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 3 else { return nil }
        let actual = String(parts[parts.count - 1])
        let masking = String(parts[parts.count - 2])
        guard MagicBytes.executableExtensions.contains(actual) else { return nil }
        let inert = MagicBytes.formats(forExtension: masking)
        guard !inert.isEmpty else { return nil }
        guard !MagicBytes.executableExtensions.contains(masking) else { return nil }
        return (masking, actual)
    }

    // MARK: - Is something else hiding inside?

    /// Looks for other formats' signatures at non-zero offsets.
    ///
    /// Deliberately narrow. Two-byte markers like `MZ` occur by chance roughly
    /// twice per 128 KiB of compressed data, so only signatures of four bytes
    /// or more are searched, and archives are skipped entirely — containing
    /// other files is what an archive is *for*.
    ///
    /// This scans the head and tail windows, so on a large file it is a
    /// sample, not a proof. The format-aware "data past the logical end" check
    /// in each inspector is the reliable one; this catches the rest.
    static func embeddedSignatures(
        probe: FileProbe,
        identified: FileFormat?,
        accountedForOffsets: Set<Int64> = []
    ) -> [Finding] {
        guard identified?.family != .archive else { return [] }
        guard probe.isReadable, probe.size > 0 else { return [] }

        let hunted: [(name: String, bytes: [UInt8])] = [
            ("ZIP archive", [0x50, 0x4B, 0x03, 0x04]),
            ("Mach-O executable", [0xCF, 0xFA, 0xED, 0xFE]),
            ("Mach-O executable", [0xCE, 0xFA, 0xED, 0xFE]),
            ("Mach-O universal binary", [0xCA, 0xFE, 0xBA, 0xBE]),
            ("ELF executable", [0x7F, 0x45, 0x4C, 0x46]),
            ("PDF document", Array("%PDF-".utf8)),
            ("7-Zip archive", [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
            ("RAR archive", Array("Rar!".utf8)),
        ]

        var findings: [Finding] = []
        for hunt in hunted {
            // Offset 0 is the file's own identity; the accounted-for set is
            // the structure it legitimately declares, such as the slices of a
            // universal binary listed in its own architecture table.
            let offsets = probe.offsets(of: hunt.bytes)
                .filter { $0 > 0 && !accountedForOffsets.contains($0) }
            guard let first = offsets.first else { continue }
            findings.append(
                Finding(
                    rule: "embedded.signature",
                    severity: .caution,
                    title: "\(hunt.name) signature inside this file",
                    detail:
                        "Found at byte \(first)\(offsets.count > 1 ? " and \(offsets.count - 1) other place\(offsets.count == 2 ? "" : "s")" : "")"
                        + ". Some formats legitimately embed others; combined with anything else "
                        + "here, it is worth opening in something that shows structure."
                        + (probe.isFullyWindowed
                            ? "" : " Only the first and last 64 KB were searched.")))
        }
        return findings
    }

    // MARK: - Traits of the file itself

    static func fileTraits(probe: FileProbe) -> [Finding] {
        var findings: [Finding] = []

        if probe.isDirectory && !probe.isBundle {
            findings.append(
                Finding(
                    rule: "file.directory",
                    severity: .info,
                    title: "Folder",
                    detail:
                        "Folders are expanded into the files they hold before inspection. "
                        + "Nothing was read from the folder itself."))
        }

        if probe.isSymbolicLink {
            let target = (try? FileManager.default.destinationOfSymbolicLink(atPath: probe.path))
            findings.append(
                Finding(
                    rule: "file.symlink",
                    severity: .info,
                    title: "Symbolic link",
                    detail:
                        "Points at \(target.map { displaySafe($0, limit: 180) } ?? "an unreadable target"). "
                        + "DragonWatch inspected the "
                        + "link, not its destination."))
        }

        if let error = probe.readError {
            findings.append(
                Finding(
                    rule: "file.unreadable",
                    severity: .info,
                    title: "Could not be read",
                    detail: error))
        }

        // The end of the file is where appended payloads live, so not having
        // reached it is a gap in the answer, not a detail.
        if probe.partialRead {
            findings.append(
                Finding(
                    rule: "file.partialRead",
                    severity: .caution,
                    title: "Only part of this file could be read",
                    detail:
                        "The start was read but the end was not, so checks for data appended "
                        + "past the end of the file did not run."))
        }

        if probe.isReadable && probe.size == 0 {
            findings.append(
                Finding(
                    rule: "file.empty",
                    severity: .info,
                    title: "Empty file",
                    detail: "Zero bytes, so there is nothing to verify."))
        }

        // Anyone on the machine can replace a world-writable file, which
        // makes every other check here a statement about a moment in time.
        if probe.posixPermissions & 0o002 != 0 {
            findings.append(
                Finding(
                    rule: "perm.worldWritable",
                    severity: .caution,
                    title: "Writable by any user",
                    detail:
                        "Mode \(String(probe.posixPermissions, radix: 8)) — any account on this "
                        + "Mac can change the contents, so what was verified here may not be "
                        + "what opens later."))
        }

        return findings
    }

    // MARK: - Helpers

    /// The quarantine value is semicolon-separated — flags, timestamp, agent,
    /// UUID — and the *third* field is the agent that downloaded the file,
    /// which is the only part worth showing.
    static func quarantineAgent(_ raw: String?) -> String? {
        guard let fields = raw?.split(separator: ";", omittingEmptySubsequences: false),
            fields.count >= 3
        else { return nil }
        let agent = fields[2].trimmingCharacters(in: .whitespaces)
        return agent.isEmpty ? nil : displaySafe(agent, limit: 48)
    }

    /// Makes an attacker-controlled string safe to place in report prose.
    ///
    /// Filenames, extensions, symlink targets and download URLs all come from
    /// the file under inspection, and all end up interpolated into a `detail`
    /// string. Left raw, a name can carry newlines that forge extra report
    /// lines, control characters that corrupt a terminal, direction overrides
    /// that reverse the surrounding sentence, or thousands of characters that
    /// bury every other finding.
    ///
    /// This strips and bounds. It does **not** escape: escaping is per-format
    /// and belongs to whichever renderer is writing (Markdown pipes and
    /// backticks, HTML angle brackets). A renderer must still escape its own
    /// metacharacters — this only guarantees the string is one short, printable
    /// line.
    static func displaySafe(_ text: String, limit: Int = 64) -> String {
        let stripped = String(
            String.UnicodeScalarView(
                text.unicodeScalars.filter { scalar in
                    !CharacterSet.controlCharacters.contains(scalar)
                        && !bidiAndInvisible.contains(scalar)
                }))
        guard stripped.count > limit else {
            return stripped.isEmpty ? "(empty)" : stripped
        }
        return stripped.prefix(limit) + "… (\(stripped.count) characters)"
    }

    /// `displaySafe` without the length cap, for paths in reports: control
    /// characters and direction overrides are removed, nothing is shortened.
    /// A filename can legally contain a newline, and one did split a report
    /// into lines that read as extra verdict entries.
    static func lineSafe(_ text: String) -> String {
        String(
            String.UnicodeScalarView(
                text.unicodeScalars.filter { scalar in
                    !CharacterSet.controlCharacters.contains(scalar)
                        && !bidiAndInvisible.contains(scalar)
                }))
    }

    /// Direction overrides and zero-width characters, shared by the filename
    /// rules and the sanitiser so the two cannot drift apart.
    static let bidiAndInvisible: Set<Unicode.Scalar> =
        directionControls.union([
            "\u{200E}", "\u{200F}",
            "\u{200B}", "\u{200C}", "\u{200D}", "\u{2060}", "\u{FEFF}",
        ])

    /// The embeddings, overrides and isolates that reorder displayed text —
    /// the Trojan Source set. Subset of `bidiAndInvisible`, for content
    /// where zero-width characters are legitimate.
    static let directionControls: Set<Unicode.Scalar> = [
        "\u{202A}", "\u{202B}", "\u{202C}", "\u{202D}", "\u{202E}",
        "\u{2066}", "\u{2067}", "\u{2068}", "\u{2069}",
    ]

    static func hexPreview(_ data: Data, limit: Int = 8) -> String {
        guard !data.isEmpty else { return "(empty)" }
        return data.prefix(limit).map { String(format: "%02x", $0) }.joined(separator: " ")
    }

    private static func codePoint(_ scalar: Unicode.Scalar) -> String {
        String(format: "U+%04X", scalar.value)
    }

    private static func list(_ formats: [FileFormat]) -> String {
        let names = formats.map(\.name)
        switch names.count {
        case 0: return "an unknown format"
        case 1: return names[0]
        default: return names.dropLast().joined(separator: ", ") + " or " + names[names.count - 1]
        }
    }
}
