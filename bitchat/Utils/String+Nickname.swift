//
// String+Nickname.swift
// bitchat
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unlicense.org>
//

import Foundation

extension String {
    /// Canonical form for nickname storage and comparison (Unicode NFC).
    /// "café" typed with a combining accent and "café" typed precomposed
    /// must resolve to the same user wherever nicknames are stored or
    /// matched (mentions, DM resolution, autocomplete, geo presence).
    var normalizedNickname: String {
        precomposedStringWithCanonicalMapping
    }

    /// Strips ONLY a trailing `#abcd` collision suffix, leaving everything
    /// else alone.
    ///
    /// Deliberately not `splitSuffix()`: that also removes every `@` in the
    /// string, which is right for parsing a mention but wrong for comparing a
    /// nickname — nothing in `validateNickname` forbids `@`, so `ravi@hq`
    /// would compare unequal to itself.
    var withoutCollisionSuffix: String {
        guard count >= 5 else { return self }
        let tail = suffix(5)
        guard tail.first == "#",
              tail.dropFirst().allSatisfy({ $0.isHexDigit }) else { return self }
        return String(dropLast(5))
    }

    /// Split a nickname into base and a '#abcd' suffix if present
    func splitSuffix() -> (String, String) {
        let name = self.replacingOccurrences(of: "@", with: "")
        guard name.count >= 5 else { return (name, "") }
        let suffix = String(name.suffix(5))
        if suffix.first == "#", suffix.dropFirst().allSatisfy({ c in
            ("0"..."9").contains(String(c)) || ("a"..."f").contains(String(c)) || ("A"..."F").contains(String(c))
        }) {
            let base = String(name.dropLast(5))
            return (base, suffix)
        }
        return (name, "")
    }
}
