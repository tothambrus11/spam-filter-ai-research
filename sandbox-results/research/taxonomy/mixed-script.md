# Taxonomy — Mixed-Script Tricks & Bidirectional (Bidi) Attacks

Scope: mixing Latin/Cyrillic/Greek within a single token (confusables); the UTS #39
single-/mixed-/whole-script confusable distinction; and Unicode bidirectional control
characters used to reorder *displayed* text away from *logical* byte order (the
"Trojan Source" family, RLO filename spoofing). Focus on the email-gateway surfaces.

All live/attack URLs defanged (`http`→`hxxp`, `.`→`[.]`).

---

## 1. Confusables and the UTS #39 script vocabulary

Unicode security work classifies visual look-alikes ("confusables") with a **skeleton**
function: two strings X and Y are *confusable* iff `skeleton(X) = skeleton(Y)`, where
`skeleton()` applies bidi reordering in isolation, moves combining marks, replaces
mirrored glyphs, and maps each codepoint to a canonical "prototype" (NFD-normalised,
Default_Ignorable characters removed). [UTS39, v17.0.0, 2025]

Each string also has a **resolved script set**: the intersection, across all its
characters, of their `Script_Extensions` (augmented with Jpan/Hanb/Kore). A string is
**single-script** if that intersection is non-empty, **mixed-script** if it is empty.
[UTS39, 2025]

Three confusable classes (UTS #39 §4; also UTR #36): [UTS39, 2025][UTR36]

- **Single-script confusable** — X and Y are confusable *and* share ≥1 resolved script.
  Example: `ǉeto` vs `ljeto` (Croatian "summer"): U+01C9 LATIN SMALL LETTER LJ vs the
  two-letter `lj`. Both are Latin, so mixed-script detectors *do not* catch this.
- **Mixed-script confusable** — confusable but resolved script sets have *no* element
  in common. Canonical example: `paypal` vs `pаypаl`, where each `а` is U+0430 CYRILLIC
  SMALL LETTER A. The token mixes Latin + Cyrillic.
- **Whole-script confusable** — a *sub-class of mixed-script* where **each** string is
  itself single-script. Example: an all-Cyrillic label that is glyph-for-glyph identical
  to a Latin word. These are the dangerous ones: each string in isolation looks
  "clean/single-script," so naive script-mixing checks pass (see whole-script example
  below).

**Restriction levels** (UTS #39 §5.2) rank identifiers from safest to loosest:
ASCII-Only → Single Script → Highly Restrictive (single script, or Latin+Han+Hiragana+
Katakana i.e. Latn+Jpan) → Moderately Restrictive (adds Latin + one other Recommended
script *except Cyrillic/Greek*) → Minimally Restrictive → Unrestricted. Note that the
"Moderately Restrictive" level **specifically excludes Latin+Cyrillic and Latin+Greek**
combinations — precisely the combos used in homograph attacks. [UTS39, 2025]

### Real example — whole-script IDN homograph (2017)
Security researcher **Xudong Zheng** registered `xn--80ak6aa92e[.]com`, which Punycode-
decodes to an **all-Cyrillic** string that renders as `аррӏе[.]com` — visually identical
to `apple[.]com`. Because every letter was Cyrillic, the label was *single-script* and
sailed past the mixed-script heuristic browsers had used since ~2005; Chrome, Firefox,
and Opera all displayed the spoof at the time. [Zheng2017][MozBug1332714]

---

## 2. Bidirectional (Bidi) control characters & Trojan Source

Unicode's Bidirectional Algorithm (UBA) supports scripts written right-to-left (Arabic,
Hebrew). A set of invisible **control characters** can override or isolate the direction
of a run, so the order in which glyphs are *displayed* can differ from the order in which
codepoints are *stored/parsed*: [TrojanSource2021][UTR36]

- **Overrides:** U+202D LEFT-TO-RIGHT OVERRIDE (LRO), U+202E RIGHT-TO-LEFT OVERRIDE (RLO)
- **Embeddings:** U+202A LRE, U+202B RLE; terminated by U+202C POP DIRECTIONAL FORMATTING (PDF)
- **Isolates (Unicode 6.3+):** U+2066 LRI, U+2067 RLI, U+2068 FIRST STRONG ISOLATE (FSI),
  terminated by U+2069 POP DIRECTIONAL ISOLATE (PDI)

### Trojan Source (Boucher & Anderson, 2021)
The **Trojan Source** attack embeds bidi overrides/isolates inside comments and string
literals so that source code is *"logically encoded in a different order from the one in
which it is displayed."* A reviewer sees benign code; the compiler parses something else
(e.g., an early `return`, a comment that is actually live code, or a swapped operand).
Demonstrated across C, C++, C#, JavaScript, Java, Rust, Go, Python, SQL, Bash, Assembly,
Solidity. [TrojanSource2021]

Attack variants described in the paper:
- **Reordering (Bidi):** bidi control chars reorder tokens visually.
- **Homoglyph:** near-identical glyphs create two functions/identifiers that look the same.
- **Invisible characters / deletions:** zero-width or backspace-style manipulation.

Two CVEs were assigned: **CVE-2021-42574** (the bidi-override rendering issue, the core
Trojan Source) and **CVE-2021-42694** (homoglyph identifiers). [TrojanSource2021][RedHatRHSB2021-007][NVD]

### The same trick weaponised against ML text filters — Bad Characters (2021)
Boucher, Shumailov, Anderson & Papernot show that a **single imperceptible injection** —
one invisible character, homoglyph, **reordering (bidi)**, or deletion — significantly
degrades NLP models (MT, toxic-content, search) in a **black-box** setting, and three
injections can functionally break most models, including deployed Microsoft/Google
systems. This is the direct email-security concern: bidi/confusable perturbations that a
human reads normally can flip a spam/phishing classifier's decision. [BadChars2021]

---

## 3. Email-pipeline surfaces (where these land)

These are the parts of an email a gateway must canonicalise/inspect:

- **Display name / From header:** RLO or mixed-script confusables can spoof a sender name
  (e.g., a Cyrillic-`а` "PayPal", or an RLO that visually reverses the display name).
- **Subject line:** bidi controls / confusables to evade keyword and ML spam classifiers
  (Bad Characters style). [BadChars2021]
- **Attachment filenames:** the classic **RLO extension spoof** — a file stored as
  `resume‮fdp.exe` (i.e. `resume` + RLO + `fdp.exe`) *renders* as `resumeexe.pdf`,
  but executes as `.exe`. MITRE ATT&CK **T1036.002** (Masquerading: Right-to-Left
  Override); first noted publicly ~2008 (Mozilla, later CVE-2009-3376); attackers wrap
  the file in a `.zip` to survive transport. Reports note only ~2/58 AV engines flagged
  such samples on VirusTotal. [MITRE_T1036_002][Hornetsecurity][CVE-2009-3376]
- **Anchor text vs. href:** HTML `<a href="hxxp://evil[.]tld">hxxp://paypal[.]com</a>` —
  the visible text names a trusted URL while `href` points elsewhere. Bidi controls or
  confusables in the *anchor text* further disguise the mismatch. Widely documented as a
  core phishing indicator. [KnowBe4][Intezer]
- **Body links / IDN homographs:** mixed- or whole-script confusable domains in link
  hostnames (the `аррӏе[.]com` class). [Zheng2017]

A recent broad taxonomy of email deception techniques (Veit et al., 2026) catalogues
these visual-spoofing/manipulation families across ~50 sub-techniques. [Veit2026]
(Flagged: I could not fully extract its PDF text to confirm the exact RLO/bidi entry
names — cited as a taxonomy pointer, not for a specific claim.)

---

## Bibliography (this file)

- **[TrojanSource2021]** Trojan Source: Invisible Vulnerabilities — Nicholas Boucher, Ross Anderson (2021). arXiv:2111.00169. CVE-2021-42574, CVE-2021-42694.
- **[BadChars2021]** Bad Characters: Imperceptible NLP Attacks — N. Boucher, I. Shumailov, R. Anderson, N. Papernot (2021). arXiv:2106.09898.
- **[UTS39]** UTS #39: Unicode Security Mechanisms, v17.0.0, rev.32 — M. Davis, M. Suignard (2025). https://www.unicode.org/reports/tr39/
- **[UTR36]** UTR #36: Unicode Security Considerations — Unicode Consortium. https://unicode.org/reports/tr36/
- **[Zheng2017]** Phishing with Unicode Domains (аррӏе.com / xn--80ak6aa92e.com whole-script confusable) — Xudong Zheng (2017). hxxps://www[.]xudongz[.]com/blog/2017/idn-phishing/
- **[MozBug1332714]** IDN Phishing using whole-script confusables on Windows and Linux — Mozilla Bugzilla #1332714 (2017). https://bugzilla.mozilla.org/show_bug.cgi?id=1332714
- **[MITRE_T1036_002]** Masquerading: Right-to-Left Override, T1036.002 — MITRE ATT&CK. https://attack.mitre.org/techniques/T1036/002/
- **[Hornetsecurity]** Hackers Using 20-Year-Old RLO Technique to scam M365 Users — Hornetsecurity (blog). https://www.hornetsecurity.com/en/blog/right-to-left-override-spoofing/
- **[CVE-2009-3376]** Mozilla RLO filename-display spoofing (2009). NVD.
- **[RedHatRHSB2021-007]** Trojan Source attacks (CVE-2021-42574, CVE-2021-42694) — Red Hat Security Bulletin. https://access.redhat.com/security/vulnerabilities/RHSB-2021-007
- **[NVD]** CVE-2021-42574 Detail — NIST NVD. https://nvd.nist.gov/vuln/detail/cve-2021-42574
- **[KnowBe4]** Bad Guys Spoof Phishing Link Hover Texts — KnowBe4 (blog). https://blog.knowbe4.com/all-con-all-the-way-down-bad-guys-spoof-phishing-link-hover-texts
- **[Intezer]** URL Analysis 101: phishing URLs — Intezer. https://intezer.com/blog/url-analysis-phishing-part-1/
- **[Veit2026]** Comprehensive List of User Deception Techniques in Emails — M. Veit, M. Mossano, T. Länge, M. Volkamer (2026). arXiv:2604.04926.
