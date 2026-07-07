# Defenses — Mixed-Script Tricks & Bidi Attacks (with mandatory known bypass per defense)

Ground rule (mission §3): a defense with an unaddressed bypass is *not* SOTA. Each entry
below lists mechanism **then** its known bypass. URLs defanged.

---

## D1. UTS #39 mixed-script / single-script confinement + confusable skeleton

**Mechanism.** Compute each string's **resolved script set** (intersection of
`Script_Extensions`). Reject/flag *mixed-script* strings (empty intersection), enforce a
**Restriction Level** (e.g., "Highly Restrictive" or "Moderately Restrictive," which
already bans Latin+Cyrillic and Latin+Greek), and compute `skeleton(X)` to test whether a
token is confusable with a protected brand/allowlist term. This is the canonical Unicode
defense and underpins Chrome's IDN gauntlet (UTS #46 → identifier status → script-mixing →
invisible-char → whole-script-confusable → skeleton match vs top domains). [UTS39, 2025][ChromiumIDN]

**KNOWN BYPASS.**
1. **Whole-script confusables evade mixed-script detection.** An all-Cyrillic (or
   all-Greek) label is *single-script*, so mixed-script confinement passes it. The
   `аррӏе[.]com` / `xn--80ak6aa92e[.]com` attack is exactly this: single-script,
   glyph-for-glyph identical to `apple`. Requires a *separate* whole-script-confusable
   check plus a skeleton-vs-known-brands comparison — and that comparison needs the
   target brand list to be complete. [Zheng2017][MozBug1332714]
2. **Single-script (intra-Latin) confusables** — `ǉeto`/`ljeto`, `rn`→`m`, `0`/`O`,
   Latin-only ligatures — share a script, so mixed-script logic never fires. [UTS39, 2025]
3. **Codepoints shared across scripts / Script_Extensions overlap.** Some characters
   belong to multiple scripts (e.g., common punctuation, or characters with broad
   `Script_Extensions`), so a genuinely mixed token can retain a non-empty resolved set
   and read as single-script. [UTS39, 2025]
4. **False positives on legitimate multilingual mail (the operational bypass).** UTS #39
   itself warns the mixed-script algorithm "is likely to flag a large number of legitimate
   strings." Genuinely bilingual senders — a Greek company name beside a Latin product,
   Cyrillic personal names in a Latin sentence, CJK+Latin brands — trip the detector,
   forcing operators to loosen thresholds, which reopens the attack surface. [UTS39, 2025][NameSilo]

---

## D2. Bidi control-character detection / stripping / balanced-override enforcement

**Mechanism.** The Trojan Source mitigations: (a) **detect** any of U+202A–U+202E,
U+2066–U+2069 and warn/reject; (b) **compilers/interpreters** error on *unterminated*
bidi controls in comments/string literals (Rust 1.56.1 added `text_direction_codepoint_in_
{comment,literal}` lints); (c) **editors/repos** render the controls with visible glyphs
(GitHub, VS Code, Atlassian/Bitbucket added highlighting/tooltips); (d) for an email
gateway: **strip or neutralise** bidi controls in headers, display names, filenames, and
anchor text, or require **balanced** override/isolate pairs. [TrojanSource2021][RedHatRHSB2021-007][SoteriBitbucket]

**KNOWN BYPASS.**
1. **Unbalanced-but-valid / legitimate bidi.** Real Arabic/Hebrew mail legitimately uses
   RLE/RLI and sometimes leaves runs unterminated at line end (the UBA resets per
   paragraph). A strict "reject unbalanced override" rule produces false positives on
   legitimate RTL correspondence; a lenient rule lets a crafted unbalanced sequence
   through. The balance check is a heuristic, not a proof of benign intent. [TrojanSource2021]
2. **Stripping ≠ canonical parse.** Removing bidi controls changes the *rendered* string
   but not necessarily how a *downstream* renderer (mail client, OS file browser) will
   display the original if the raw bytes survive elsewhere (e.g., inside an attachment the
   gateway forwards intact). Defense must act on every rendering surface, not just the
   scanned copy.
3. **No-bidi attacks remain.** Homoglyph and invisible-character variants (CVE-2021-42694;
   Bad Characters' homoglyph/deletion injections) carry **no** bidi control at all, so a
   bidi-only filter misses them entirely. [TrojanSource2021][BadChars2021]

---

## D3. Anchor-text-vs-href mismatch detection (email HTML)

**Mechanism.** Parse HTML `<a>` elements; extract the visible **anchor text** and the
`href` target; flag when the anchor text *looks like a URL/brand* but resolves to a
different registrable domain. Combine with confusable-skeleton normalisation of both text
and href host so a Cyrillic-spoofed anchor is compared on its skeleton. Widely deployed in
"adaptive AI" email security and a classic phishing signal. [KnowBe4][Intezer]

**KNOWN BYPASS.**
1. **Non-URL anchor text.** If the visible text is a word ("Click here", "View invoice")
   rather than a URL, there is *no* string to compare against `href` — the mismatch check
   has nothing to fire on. Most modern phishing uses exactly this.
2. **Benign redirectors / URL wrappers.** Legitimate mail routes links through trackers,
   SafeLinks, marketing redirectors, and shorteners, so href ≠ visible domain is *normal*;
   attackers hide a single malicious SafeLinks-wrapped URL among legitimate ones to defeat
   the heuristic. [Ironscales]
3. **Text-in-image / QR.** If the "link" is rendered as an image or QR code, there is no
   `<a>` element to inspect at all (out of this class's scope but a full bypass of D3).

---

## D4. Attachment filename RLO / mixed-script detection

**Mechanism.** Scan attachment (and archive-member) filenames for U+202E/U+202D and other
bidi/invisible codepoints; flag or rename; also flag double-extension patterns and
mixed-script filenames. Endpoint/EDR rules (e.g., Elastic, MITRE T1036.002 detections)
look for `‮`, `[U+202E]`, `‮`. [MITRE_T1036_002][Hornetsecurity]

**KNOWN BYPASS.**
1. **Archive nesting / evasion of the scanner.** Attackers `.zip` (often nested/encrypted)
   the RLO-named file so gateways that don't recurse into archives never see the filename;
   VirusTotal data showed only ~2/58 engines caught such samples. [Hornetsecurity]
2. **The real payload isn't the filename.** RLO only disguises the *extension*; blocking it
   doesn't address the executable content, and non-RLO masquerades (double extension,
   icon spoofing, LNK, HTML-smuggling) achieve the same deception without any bidi char.
3. **Legitimate RTL filenames.** Users in Arabic/Hebrew locales produce filenames with
   genuine RTL characters; a blunt "any bidi char in filename = malicious" rule
   false-positives on their normal attachments.

---

## Cross-cutting: the false-positive ceiling
Every defense above shares one adversary — **legitimate multilingual/RTL email**. UTS #39
explicitly warns mixed-script detection over-flags; RTL locales legitimately use bidi
controls; multilingual brands legitimately mix scripts. This forces a threshold that no
single rule can set safely, which is why the recommended posture is **canonicalise +
score, not hard-block**: normalise (skeleton, strip/neutralise controls) for the
*classifier's* view while preserving the original for delivery, and feed
mixed-script/bidi/whole-script/anchor-mismatch as **weighted features** into an ensemble
alongside sender reputation, SPF/DKIM/DMARC, and URL/domain intelligence — not as
standalone verdicts.

---

## Bibliography (this file)

- **[TrojanSource2021]** Trojan Source: Invisible Vulnerabilities — N. Boucher, R. Anderson (2021). arXiv:2111.00169.
- **[BadChars2021]** Bad Characters: Imperceptible NLP Attacks — N. Boucher, I. Shumailov, R. Anderson, N. Papernot (2021). arXiv:2106.09898.
- **[UTS39]** UTS #39 Unicode Security Mechanisms, v17.0.0 (2025). https://www.unicode.org/reports/tr39/
- **[ChromiumIDN]** Internationalized Domain Names (IDN) in Google Chrome — Chromium docs. https://chromium.googlesource.com/chromium/src/+/main/docs/idn.md
- **[Zheng2017]** Phishing with Unicode Domains — Xudong Zheng (2017). hxxps://www[.]xudongz[.]com/blog/2017/idn-phishing/
- **[MozBug1332714]** IDN Phishing using whole-script confusables — Mozilla Bugzilla #1332714 (2017).
- **[RedHatRHSB2021-007]** Trojan Source (CVE-2021-42574 / -42694) — Red Hat. https://access.redhat.com/security/vulnerabilities/RHSB-2021-007
- **[SoteriBitbucket]** Mitigating Trojan Source Attacks — Soteri (2021). https://soteri.io/blog/2021-11-08-mitigating-trojan-source-attacks-with-security-for-bitbucket
- **[MITRE_T1036_002]** Masquerading: Right-to-Left Override, T1036.002 — MITRE ATT&CK. https://attack.mitre.org/techniques/T1036/002/
- **[Hornetsecurity]** 20-Year-Old RLO Technique scamming M365 Users — Hornetsecurity. https://www.hornetsecurity.com/en/blog/right-to-left-override-spoofing/
- **[NameSilo]** Confusable Detection 101: Unicode Skeletons and Mixed-Script Checks — NameSilo. https://www.namesilo.com/blog/en/brand-protection/confusable-detection-101-unicode-skeletons-and-mixed-script-checks-for-your-brands
- **[KnowBe4]** Bad Guys Spoof Phishing Link Hover Texts — KnowBe4.
- **[Intezer]** URL Analysis 101: phishing URLs — Intezer.
- **[Ironscales]** Malicious SafeLinks-Wrapped URL Hidden Among Legitimate SharePoint Anchors — Ironscales. https://ironscales.com/threat-intelligence/safelinks-malicious-url-sharepoint-trust-anchors
