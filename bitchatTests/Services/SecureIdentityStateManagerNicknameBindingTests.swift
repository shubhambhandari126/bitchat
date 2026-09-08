import Foundation
import Testing

@testable import bitchat

/// Binds a trust badge to the nickname it was earned under.
///
/// `VouchAttestation` signs `voucheeFingerprint | voucheeSigningKey |
/// timestampMs` and deliberately says nothing about a name — a name-free
/// attestation is the right wire format. But the badge is *rendered* beside a
/// self-claimed nickname, so the binding has to live on the receiver, which is
/// the only party that knows what name the key was presenting when it decided
/// to trust it. These tests pin that rule.
///
/// `@MainActor` for the same reason as `SecureIdentityStateManagerVouchTests`:
/// the manager's blocking `queue.sync` reads must stay off the Swift
/// Concurrency cooperative pool, or CI's few-core runners deadlock.
@MainActor
struct SecureIdentityStateManagerNicknameBindingTests {
    private let voucher = String(repeating: "0a", count: 32)
    private let secondVoucher = String(repeating: "0c", count: 32)
    private let vouchee = String(repeating: "0b", count: 32)

    private func makeManager() -> SecureIdentityStateManager {
        SecureIdentityStateManager(MockKeychain())
    }

    /// Mirrors the announce path: the peer tells us what it calls itself.
    private func announce(_ manager: SecureIdentityStateManager,
                          _ fingerprint: String,
                          as nickname: String) {
        manager.upsertCryptographicIdentity(
            fingerprint: fingerprint,
            noisePublicKey: Data(repeating: 0x01, count: 32),
            signingPublicKey: nil,
            claimedNickname: nickname
        )
    }

    // MARK: - The attack this closes

    @Test
    func vouch_pinsTheNicknameItWasEarnedUnder() {
        let manager = makeManager()
        announce(manager, vouchee, as: "ravi")
        manager.setVerified(fingerprint: voucher, verified: true)

        #expect(manager.recordVouch(voucheeFingerprint: vouchee, voucherFingerprint: voucher, timestamp: Date()))
        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "ravi"))
        #expect(manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "medic"),
                "the baseline is pinned: any other name is a mismatch")
    }

    @Test
    func renamingOntoATrustedNameAfterEarningAVouchIsAMismatch() {
        let manager = makeManager()
        announce(manager, vouchee, as: "ravi")
        manager.setVerified(fingerprint: voucher, verified: true)
        manager.recordVouch(voucheeFingerprint: vouchee, voucherFingerprint: voucher, timestamp: Date())

        // Same key, new self-chosen name — the badge must not follow it.
        announce(manager, vouchee, as: "medic")

        #expect(manager.isVouched(fingerprint: vouchee),
                "the vouch itself is still valid; only its binding to a name broke")
        #expect(manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "medic"))
        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "ravi"),
                "the baseline stayed on the name the vouch was earned under")
    }

    @Test
    func aLaterVoucherCannotReanchorTheBaselineToTheNewName() {
        let manager = makeManager()
        announce(manager, vouchee, as: "ravi")
        manager.setVerified(fingerprint: voucher, verified: true)
        manager.recordVouch(voucheeFingerprint: vouchee, voucherFingerprint: voucher, timestamp: Date())
        announce(manager, vouchee, as: "medic")

        // A second vouch arriving after the rename must not launder it.
        manager.setVerified(fingerprint: secondVoucher, verified: true)
        manager.recordVouch(voucheeFingerprint: vouchee, voucherFingerprint: secondVoucher, timestamp: Date())

        #expect(manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "medic"))
        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "ravi"),
                "the second vouch did not launder the rename")
    }

    // MARK: - Vouches for peers we have not seen yet

    @Test
    func aVouchForAnUnseenPeerBindsOnTheirFirstAnnounce() {
        // The usual case: the vouch arrives over Noise from someone else and
        // the vouchee is not in our announce set yet, so there is no name to
        // bind to at record time.
        let manager = makeManager()
        manager.setVerified(fingerprint: voucher, verified: true)
        manager.recordVouch(voucheeFingerprint: vouchee, voucherFingerprint: voucher, timestamp: Date())
        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "ravi"),
                "nothing is bound yet, so nothing can mismatch")

        announce(manager, vouchee, as: "ravi")
        announce(manager, vouchee, as: "medic")

        #expect(manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "medic"))
        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "ravi"),
                "the first name seen while the vouch stood is the binding")
    }

    @Test
    func theAnnouncePathDoesNotBindBeforeTrustExists() {
        // Otherwise a peer who renamed BEFORE being vouched would be bound to
        // the name we happened to see first, and lose a legitimate badge.
        let manager = makeManager()
        announce(manager, vouchee, as: "rav")
        announce(manager, vouchee, as: "ravi")

        manager.setVerified(fingerprint: voucher, verified: true)
        manager.recordVouch(voucheeFingerprint: vouchee, voucherFingerprint: voucher, timestamp: Date())

        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "ravi"),
                "bound to the name it was vouched under, not the name seen first")
        #expect(manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "rav"))
    }

    @Test
    func aFirstAnnounceThatIsAlreadyTheImpersonatingNameIsNotCaught() {
        // The documented limit of receiver-side binding: if we never saw this
        // key under its real name, the impersonating name IS the baseline.
        // Only signing the nickname into the attestation closes this, which is
        // a wire change and deliberately not attempted here.
        let manager = makeManager()
        manager.setVerified(fingerprint: voucher, verified: true)
        manager.recordVouch(voucheeFingerprint: vouchee, voucherFingerprint: voucher, timestamp: Date())

        announce(manager, vouchee, as: "medic")

        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "medic"),
                "known gap, pinned here so it is explicit rather than a surprise")
    }

    // MARK: - Rebinding and clearing

    @Test
    func verifyingInPersonRebindsToTheCurrentName() {
        let manager = makeManager()
        announce(manager, vouchee, as: "ravi")
        manager.setVerified(fingerprint: voucher, verified: true)
        manager.recordVouch(voucheeFingerprint: vouchee, voucherFingerprint: voucher, timestamp: Date())
        announce(manager, vouchee, as: "medic")

        // The user scanned this key themselves, under the name it shows now.
        manager.setVerified(fingerprint: vouchee, verified: true)

        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "medic"))
        #expect(manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "ravi"),
                "the baseline moved to the name just checked in person")
    }

    @Test
    func unverifyingClearsTheBaselineOnlyWhenNoVouchRemains() {
        let manager = makeManager()
        announce(manager, vouchee, as: "ravi")

        manager.setVerified(fingerprint: vouchee, verified: true)
        #expect(manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "medic"))
        manager.setVerified(fingerprint: vouchee, verified: false)
        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "medic"),
                "with no trust left there is no baseline, so nothing to mismatch")

        // With a vouch still standing, the baseline has to survive: it is what
        // that vouch's badge is bound to.
        manager.setVerified(fingerprint: voucher, verified: true)
        manager.recordVouch(voucheeFingerprint: vouchee, voucherFingerprint: voucher, timestamp: Date())
        manager.setVerified(fingerprint: vouchee, verified: true)
        manager.setVerified(fingerprint: vouchee, verified: false)
        #expect(manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "medic"),
                "the vouch's badge still needs the name it was bound to")
    }

    // MARK: - Names as rendered in a message row

    @Test
    func aDisambiguationSuffixIsNotMistakenForARename() {
        // Message senders render as "ravi#a1b2" when nicknames collide; the
        // announced nickname never carries the suffix.
        let manager = makeManager()
        announce(manager, vouchee, as: "ravi")
        manager.setVerified(fingerprint: vouchee, verified: true)

        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, displayedSender: "ravi#a1b2"))
        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, displayedSender: "@ravi#a1b2"))
        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, displayedSender: "ravi"))
    }

    @Test
    func aRenameIsStillCaughtThroughTheSuffix() {
        let manager = makeManager()
        announce(manager, vouchee, as: "ravi")
        manager.setVerified(fingerprint: vouchee, verified: true)

        #expect(manager.trustedNicknameMismatch(fingerprint: vouchee, displayedSender: "medic#a1b2"))
        #expect(manager.trustedNicknameMismatch(fingerprint: vouchee, displayedSender: "medic"))
    }

    @Test
    func aNameEndingInSomethingSuffixLikeIsNotTruncated() {
        // "#abcd" only counts as a suffix when those four characters are hex;
        // a nickname that merely contains '#' must still compare whole.
        let manager = makeManager()
        announce(manager, vouchee, as: "ravi#zzzz")
        manager.setVerified(fingerprint: vouchee, verified: true)

        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, displayedSender: "ravi#zzzz"))
        #expect(manager.trustedNicknameMismatch(fingerprint: vouchee, displayedSender: "ravi"))
    }

    // MARK: - Failing open

    @Test
    func aMissingBaselineNeverSuppressesABadge() {
        // Verified before the peer ever announced a name — there is nothing to
        // bind to, and pinning "" would read as a mismatch against every later
        // announce. Peers trusted by builds before this shipped land here too,
        // so an upgrade must not silently drop their badges.
        let manager = makeManager()
        manager.setVerified(fingerprint: vouchee, verified: true)

        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "medic"))
        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: "ravi"))
    }

    @Test
    func anEmptyClaimedNicknameIsNotAMismatch() {
        let manager = makeManager()
        announce(manager, vouchee, as: "ravi")
        manager.setVerified(fingerprint: vouchee, verified: true)

        #expect(!manager.trustedNicknameMismatch(fingerprint: vouchee, claimedNickname: ""))
    }

    // MARK: - Persistence compatibility

    @Test
    func aCacheWrittenBeforeThisFieldExistedStillLoads() throws {
        let legacyJSON = Data("""
        {"socialIdentities":{},"nicknameIndex":{},"verifiedFingerprints":["\(vouchee)"],\
        "lastInteractions":{},"blockedNostrPubkeys":[],"cryptographicIdentities":{},"version":1}
        """.utf8)

        let decoded = try JSONDecoder().decode(IdentityCache.self, from: legacyJSON)

        #expect(decoded.trustedNicknames == nil)
        #expect(decoded.verifiedFingerprints.contains(vouchee))
    }

    @Test
    func theBaselineSurvivesAnEncodeDecodeRoundTrip() throws {
        var cache = IdentityCache()
        cache.trustedNicknames = [vouchee: "ravi"]

        let decoded = try JSONDecoder().decode(IdentityCache.self, from: JSONEncoder().encode(cache))

        #expect(decoded.trustedNicknames?[vouchee] == "ravi")
    }
}
