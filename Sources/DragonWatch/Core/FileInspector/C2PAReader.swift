import Foundation

/// Reads C2PA Content Credentials — the provenance manifest that generative
/// tools and some cameras embed — by walking the manifest, not by searching
/// the file for keywords.
///
/// **The claim is read, not verified.** Real verification means decoding COSE,
/// walking an X.509 chain to a trust list, and re-hashing every asserted
/// region. None of that happens here, so the manifest is what the file *says
/// about itself*: useful context, never evidence. An absent manifest proves
/// nothing either — it is stripped by resaving the image — so "no credentials"
/// is not "not AI-generated" and is not reported as a finding.
///
/// Everything it produces is a `Disclosure`. Provenance argues nothing about
/// whether a file is what it claims to be, and counting it as a finding would
/// inflate the number the user is meant to read.
enum C2PAReader {

    /// Assertion labels are versioned and suffixed (`c2pa.actions.v2`,
    /// `c2pa.ingredient.v3__4`), so lookups match on the stem.
    static func assertion(_ stem: String, in boxes: [String: Data]) -> Data? {
        if let exact = boxes[stem] { return exact }
        let matches = boxes.keys.filter { $0 == stem || $0.hasPrefix(stem + ".v") }
        // Sorted so the choice does not depend on dictionary order.
        guard let key = matches.sorted().last else { return nil }
        return boxes[key]
    }

    static func disclosures(probe: FileProbe, format: FileFormat?) -> [Disclosure] {
        guard let payload = JUMBF.payload(probe: probe, format: format) else { return [] }
        let boxes = JUMBF.labelledCBOR(in: payload)
        guard !boxes.isEmpty else {
            // A JUMBF container that yields no assertions is either truncated
            // by the head window or malformed; either way, saying nothing
            // would be the wrong answer.
            return [
                Disclosure(
                    title: "Content Credentials present but unreadable",
                    detail:
                        "The file carries a C2PA container that could not be parsed — it may be "
                        + "larger than the portion DragonWatch reads, or malformed.")
            ]
        }

        var disclosures: [Disclosure] = []
        let claim = assertion("c2pa.claim", in: boxes).flatMap(CBOR.decode)
        let actions = assertion("c2pa.actions", in: boxes).flatMap(CBOR.decode)

        let generator = claim?["claim_generator_info"]?["name"]?.textValue
        let steps = declaredActions(actions)
        let sourceType = steps.compactMap(\.digitalSourceType).first

        var summary = "This file carries C2PA Content Credentials"
        if let generator {
            summary += ", written by \(UniversalChecks.displaySafe(generator, limit: 64))"
        }
        summary += "."
        if let meaning = sourceTypeMeaning(sourceType) {
            summary += " It states it was \(meaning)."
        }
        disclosures.append(Disclosure(title: "Content Credentials", detail: summary))

        for step in steps.prefix(6) {
            guard let text = step.description ?? step.action else { continue }
            disclosures.append(
                Disclosure(
                    title: "Declared step",
                    detail: UniversalChecks.displaySafe(text, limit: 160)))
        }

        // Without this line the section reads as verification, which is the
        // one thing it is not.
        disclosures.append(
            Disclosure(
                title: "Claim not verified",
                detail:
                    "DragonWatch read this manifest without checking its signature, and "
                    + "credentials can be removed by resaving the file. Treat it as what the "
                    + "file says about itself."))
        return disclosures
    }

    // MARK: - The actions assertion

    struct DeclaredAction: Sendable {
        let action: String?
        let description: String?
        let digitalSourceType: String?
    }

    /// Reads `actions` out of the actions assertion.
    ///
    /// Each entry is a map, and the fields are read from *that* map — which
    /// is the whole reason for decoding rather than scanning. An ingredient's
    /// own `description` lives in a different assertion entirely and can no
    /// longer be mistaken for a step the file declares.
    static func declaredActions(_ assertion: CBORValue?) -> [DeclaredAction] {
        guard let items = assertion?["actions"]?.arrayValue else { return [] }
        return items.prefix(32).map { entry in
            DeclaredAction(
                action: entry["action"]?.textValue,
                description: entry["description"]?.textValue,
                digitalSourceType: entry["digitalSourceType"]?.textValue)
        }
    }

    // MARK: - IPTC digital source type

    /// The vocabulary term is the last path component of an IPTC newscode URL.
    static func sourceTypeMeaning(_ value: String?) -> String? {
        guard let term = value?.split(separator: "/").last.map(String.init) else { return nil }
        switch term {
        case "trainedAlgorithmicMedia": return "created by a generative AI model"
        case "compositeWithTrainedAlgorithmicMedia":
            return "a composite that includes AI-generated material"
        case "algorithmicMedia": return "generated by software rather than captured"
        case "digitalCapture": return "captured by a camera"
        case "digitalArt": return "created as digital art"
        case "composite", "compositeCapture": return "composited from more than one source"
        case "minorHumanEdits", "humanEdits": return "edited by a person after capture"
        default: return nil
        }
    }
}
