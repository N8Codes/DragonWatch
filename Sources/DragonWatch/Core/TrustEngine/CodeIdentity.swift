import CryptoKit
import Foundation
import Security

/// A content-bound fingerprint of an executable.
///
/// Vouching used to identify a binary by `(path, mtime, size)`. Both halves of
/// that tuple are attacker-controlled: `utimensat` sets any mtime, and a
/// payload is trivially padded to a target size. Anyone who could write the
/// file could therefore keep its vouch — which is the whole protection the
/// vouch is supposed to provide.
///
/// This binds to the bytes instead. The code directory hash is preferred: it
/// is what the kernel and `codesign` themselves compare. Unsigned files have
/// no cdhash and fall back to SHA-256 of the whole file.
enum CodeIdentity {
    /// nil when the file cannot be read at all — an unreadable file is never
    /// treated as matching anything.
    ///
    /// The cdhash is read from the signature blob, so on its own it says
    /// nothing about the code pages: a binary patched in place keeps its
    /// cdhash. It counts as the fingerprint only while the signature still
    /// validates against the executable; otherwise the file's own SHA-256
    /// does, which no recorded cdhash can equal.
    static func fingerprint(path: String) -> Data? {
        if let cdhash = codeDirectoryHash(path: path, requiringValidSignature: true) {
            return cdhash
        }
        return FileHasher.sha256Data(path: path)
    }

    /// `kSecCodeInfoUnique` — the cdhash. Present for signed and ad-hoc-signed
    /// code, absent for unsigned files.
    static func codeDirectoryHash(
        path: String, requiringValidSignature: Bool = false
    ) -> Data? {
        var codeOpt: SecStaticCode?
        guard
            SecStaticCodeCreateWithPath(
                URL(fileURLWithPath: path) as CFURL, SecCSFlags(), &codeOpt)
                == errSecSuccess,
            let code = codeOpt
        else { return nil }
        if requiringValidSignature,
            SecStaticCodeCheckValidity(code, SignatureInspector.validateExecutableOnly, nil)
                != errSecSuccess
        {
            return nil
        }

        var infoOpt: CFDictionary?
        guard
            SecCodeCopySigningInformation(code, SecCSFlags(rawValue: 2), &infoOpt)
                == errSecSuccess,
            let info = infoOpt as? [String: Any]
        else { return nil }
        return info[kSecCodeInfoUnique as String] as? Data
    }
}
