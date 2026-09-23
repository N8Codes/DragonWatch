import Foundation

/// Every rule the File Inspector can report, with what it means and why it
/// exists.
///
/// The app's own design rule is that the whole rulebook ships inside the app —
/// a rating the user cannot interrogate is a rating they have to take on
/// faith. `CriteriaView` renders this, and a test asserts that every rule the
/// inspectors actually emit appears here, so the documentation cannot drift
/// away from the code.
enum InspectionRulebook {

    struct Rule: Sendable, Hashable, Identifiable {
        let id: String
        let severity: FindingSeverity
        let title: String
        /// Why this is worth reporting — the part a user needs to judge it.
        let rationale: String
    }

    struct Group: Sendable, Identifiable {
        let id: String
        let summary: String
        let rules: [Rule]
    }

    static let groups: [Group] = [
        Group(
            id: "What the file claims to be",
            summary:
                "The extension is a claim; the first bytes are evidence. Where they disagree, "
                + "the bytes win.",
            rules: [
                Rule(
                    id: "magic.mismatch", severity: .inconsistent,
                    title: "Extension does not match contents",
                    rationale:
                        "The strongest signal here. A Mach-O named .png is not a mislabelled "
                        + "image; renaming is how a runnable file is made to look inert. Any "
                        + "runnable format under another name, or a different kind of file "
                        + "altogether, lands here."),
                Rule(
                    id: "magic.mislabelled", severity: .caution,
                    title: "Mislabelled, but the same kind of file",
                    rationale:
                        "A GIF named .png, a WebP named .jpg: the name is wrong, but both are "
                        + "images and nothing in them can run. Common on the web, where sites "
                        + "serve one format under another's name. Still worth knowing."),
                Rule(
                    id: "magic.unconfirmed", severity: .caution,
                    title: "Contents could not be confirmed",
                    rationale:
                        "The extension names a format DragonWatch knows, but the bytes match "
                        + "no signature. Usually truncation or a variant not in the table."),
                Rule(
                    id: "magic.unclassified", severity: .info,
                    title: "Format not recognised",
                    rationale:
                        "Neither the bytes nor the extension are known. Informational, because "
                        + "plenty of legitimate formats are not in the table — the bytes are "
                        + "recorded so a recurring unknown can be recognised next time."),
            ]),

        Group(
            id: "The name itself",
            summary: "A filename is displayed to you before you open anything.",
            rules: [
                Rule(
                    id: "name.bidi", severity: .inconsistent,
                    title: "Filename contains text-direction overrides",
                    rationale:
                        "Unicode direction controls make a name render differently from what it "
                        + "is — \"report\\u{202E}fdp.exe\" shows as \"reportexe.pdf\". "
                        + "Legitimate filenames effectively never need them."),
                Rule(
                    id: "name.invisible", severity: .caution,
                    title: "Filename contains invisible characters",
                    rationale:
                        "Zero-width characters make two different names look identical."),
                Rule(
                    id: "name.doubleExtension", severity: .caution,
                    title: "Runnable file wearing a document extension",
                    rationale:
                        "Reported only when the final extension is something macOS would run "
                        + "and the one before it is a known inert format, so \"archive.tar.gz\" "
                        + "and \"deploy.test.sh\" do not trip it."),
            ]),

        Group(
            id: "Where the file ends",
            summary:
                "Most formats declare their own length. Anything past that point is carried, "
                + "not part of the file.",
            rules: [
                Rule(
                    id: "container.trailingData", severity: .caution,
                    title: "Data after the end of the file",
                    rationale:
                        "An exact count, from the format's own end marker or declared size. "
                        + "This is how a second file rides inside an innocuous one — and also "
                        + "what some signing and watermarking tools leave behind."),
                Rule(
                    id: "embedded.signature", severity: .caution,
                    title: "Another format's signature inside this file",
                    rationale:
                        "A sampled check over the first and last 64 KB, so it can corroborate "
                        + "the exact check above but cannot replace it. Archives are exempt: "
                        + "containing other files is what an archive is for."),
                Rule(
                    id: "container.malformed", severity: .caution,
                    title: "Structure does not parse cleanly",
                    rationale:
                        "The chunk, segment or box chain breaks. Every other structural claim "
                        + "about the file rests on that chain, so a break is worth saying."),
                Rule(
                    id: "container.shortFile", severity: .caution,
                    title: "File is shorter than its header declares",
                    rationale: "Truncated: the header describes more than the file holds."),
                Rule(
                    id: "jpeg.noEndMarker", severity: .caution,
                    title: "JPEG has no end-of-image marker",
                    rationale:
                        "Either truncated, or enough is appended to push the marker outside the "
                        + "sampled window."),
                Rule(
                    id: "png.noEndChunk", severity: .caution,
                    title: "PNG has no IEND chunk",
                    rationale: "Every complete PNG ends with one."),
                Rule(
                    id: "gif.noTrailer", severity: .caution,
                    title: "GIF does not end with a trailer byte",
                    rationale: "Truncated, or something follows the image."),
                Rule(
                    id: "pdf.noEndMarker", severity: .caution,
                    title: "PDF has no %%EOF marker",
                    rationale: "Every complete PDF ends with one."),
                Rule(
                    id: "ogg.noTrailingPage", severity: .caution,
                    title: "No Ogg page near the end of the file",
                    rationale: "An Ogg stream runs to the end; something follows the audio."),
            ]),

        Group(
            id: "Things that run",
            summary:
                "A document that executes something is a program as well as a document. Saying "
                + "so is not a malware verdict.",
            rules: [
                Rule(
                    id: "pdf.launchAction", severity: .inconsistent,
                    title: "PDF can launch another program",
                    rationale:
                        "A launch action asks the reader to start a separate program. Nothing "
                        + "that only displays content needs it."),
                Rule(
                    id: "pdf.activeContent", severity: .caution,
                    title: "PDF contains active content",
                    rationale:
                        "JavaScript or embedded rich media. Forms use JavaScript for "
                        + "validation, so it is common in anything fillable. An open action on "
                        + "its own is not flagged: nearly every PDF has one, and it usually just "
                        + "picks the page and zoom to show first. It is only mentioned when "
                        + "there is JavaScript for it to run."),
                Rule(
                    id: "ooxml.macros", severity: .caution,
                    title: "Office document contains a macro project",
                    rationale:
                        "A vbaProject.bin means the document carries code. Office will ask "
                        + "before running it."),
                Rule(
                    id: "svg.activeContent", severity: .caution,
                    title: "SVG contains active content",
                    rationale:
                        "SVG is XML, and a browser runs script inside it where an image viewer "
                        + "does not. Safe to view locally; not safe to serve to other people."),
                Rule(
                    id: "svg.externalEntity", severity: .caution,
                    title: "SVG declares an XML entity",
                    rationale:
                        "Entity declarations are how an XML parser is made to read other files "
                        + "off the machine that opens it."),
                Rule(
                    id: "source.decodeAndExecute", severity: .caution,
                    title: "Source decodes a string and runs it",
                    rationale:
                        "Code that assembles itself at runtime cannot be read by looking at it, "
                        + "which is the reason for writing it that way."),
            ]),

        Group(
            id: "Archives",
            summary: "Read from the index only. Nothing is ever extracted.",
            rules: [
                Rule(
                    id: "zip.pathTraversal", severity: .inconsistent,
                    title: "Entry escapes the extraction folder",
                    rationale:
                        "An absolute or parent path would write outside the folder you chose. "
                        + "Caught from the index, without creating a single file."),
                Rule(
                    id: "zip.expansionRatio", severity: .caution,
                    title: "Expands far more than its size suggests",
                    rationale:
                        "Reported only when the archive is both large and lopsided, so ordinary "
                        + "compression does not trip it."),
                Rule(
                    id: "zip.prependedData", severity: .caution,
                    title: "Data before the start of the archive",
                    rationale:
                        "Self-extracting archives look like this; so does a ZIP hidden inside "
                        + "another file."),
                Rule(
                    id: "zip.indexTruncated", severity: .caution,
                    title: "Archive index is incomplete",
                    rationale: "Fewer entries could be read than the record claims."),
            ]),

        Group(
            id: "Executables and bundles",
            summary:
                "Signature checking is shared with the process monitor; only the structure is "
                + "read here.",
            rules: [
                Rule(
                    id: "macho.sliceOutOfBounds", severity: .inconsistent,
                    title: "Architecture slice extends past the end of the file",
                    rationale: "The header does not describe this file."),
                Rule(
                    id: "bundle.signatureInvalid", severity: .inconsistent,
                    title: "Bundle signature does not match its contents",
                    rationale:
                        "Something inside changed after signing, or the certificate was revoked. "
                        + "This is the same question the rest of the inspector asks: the bundle "
                        + "is not what its signer sealed."),
                Rule(
                    id: "bundle.unsigned", severity: .caution,
                    title: "Bundle has no code signature",
                    rationale: "Nothing identifies who built it or proves it is unaltered."),
                Rule(
                    id: "bundle.adHoc", severity: .caution,
                    title: "Bundle is ad-hoc signed",
                    rationale:
                        "The signature proves the contents are intact but says nothing about "
                        + "who produced them."),
            ]),

        Group(
            id: "Source and text",
            summary:
                "\"Is this code malicious\" is not a question a parser answers, and none of "
                + "these claim to. They report text that does not read the way it renders.",
            rules: [
                Rule(
                    id: "source.bidiText", severity: .inconsistent,
                    title: "Source contains direction-override characters",
                    rationale:
                        "Trojan Source (CVE-2021-42574): these change how code displays without "
                        + "changing what the compiler reads, so the code reviewed is not the "
                        + "code that runs. Zero-width joiners are not counted — emoji and many "
                        + "scripts need them."),
                Rule(
                    id: "source.veryLongLine", severity: .caution,
                    title: "Contains an extremely long line",
                    rationale:
                        "Packed or generated rather than written. Bundled JavaScript and CSS "
                        + "are exempt, because minification there is normal."),
                Rule(
                    id: "source.encodedBlob", severity: .caution,
                    title: "Contains a long encoded run",
                    rationale:
                        "An unbroken base64-style run well past what a key, hash or data URI "
                        + "needs is carrying data."),
                Rule(
                    id: "source.notText", severity: .caution,
                    title: "Not readable as text",
                    rationale:
                        "The extension says source or text and the contents are not valid UTF-8."),
            ]),

        Group(
            id: "The file on disk",
            summary: "Properties of the file itself rather than its contents.",
            rules: [
                Rule(
                    id: "perm.worldWritable", severity: .caution,
                    title: "Writable by any user",
                    rationale:
                        "Any account on this Mac can change the contents, so what was verified "
                        + "may not be what opens later."),
                Rule(
                    id: "file.partialRead", severity: .caution,
                    title: "Only part of the file could be read",
                    rationale:
                        "The end was not reached, so the checks for appended data did not run. "
                        + "Said out loud rather than left to look like a clean result."),
                Rule(
                    id: "file.unreadable", severity: .info,
                    title: "Could not be read",
                    rationale:
                        "Reported rather than skipped. \"We could not look\" must never read as "
                        + "\"we looked and it was fine\"."),
                Rule(
                    id: "file.symlink", severity: .info,
                    title: "Symbolic link",
                    rationale:
                        "The link is inspected, never followed — following one would take the "
                        + "scan outside what you selected."),
                Rule(
                    id: "file.directory", severity: .info,
                    title: "Folder",
                    rationale: "Folders are expanded into their files before inspection."),
                Rule(
                    id: "file.empty", severity: .info,
                    title: "Empty file",
                    rationale: "Zero bytes, so there is nothing to verify."),
                Rule(
                    id: "id3.oversizedTag", severity: .caution,
                    title: "Audio tag is larger than the file",
                    rationale: "The header does not describe this file."),
                Rule(
                    id: "id3.dominantTag", severity: .caution,
                    title: "Metadata tag is most of the file",
                    rationale:
                        "Cover art explains some of this; not usually most of it."),
            ]),
    ]

    /// Every rule id the app can report. The drift test compares this against
    /// what the inspectors actually emit.
    static let allRuleIDs: Set<String> = Set(groups.flatMap { $0.rules.map(\.id) })

    /// What the app will not conclude, stated where the rules are.
    static let limits: [String] = [
        "This is not a malware scan. There is no malware corpus, no signature feed and no "
            + "cloud lookup; XProtect and Gatekeeper remain your antivirus.",
        "A clean result means the contents match what the file claims to be — not that the "
            + "file is safe to open.",
        "Nothing inspected is ever executed, decoded by a system media framework, or extracted.",
        "Structural checks on a large file are sampled: the first and last 64 KB, plus "
            + "whatever the format's own structure declares. Hashing is the exception — a "
            + "file is streamed end to end to produce its SHA-256, up to a 2 GB ceiling.",
        "Content Credentials are read, not verified. DragonWatch does not check their signature, "
            + "and they can be stripped by resaving a file.",
    ]
}
