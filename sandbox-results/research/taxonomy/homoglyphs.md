# Taxonomy — Homoglyph / Unicode Confusable Attacks

**Attack class:** Latin/Cyrillic/Greek (and math/fullwidth) lookalike substitution in display
text, sender names, subjects, body anchor text, brand names, and domains/IDNs.
**Scope of this note:** email-gateway pipeline. Live URLs are DEFANGED (`http`->`hxxp`, `.`->`[.]`).
**Date compiled:** 2026-07-02.

---

## 1. Definitions (precise, and often conflated)

- **Homoglyph** — a *glyph* (rendered shape) that is visually identical or near-identical to
  another glyph, typically from a different script. Classic example: Latin small `a` (U+0061)
  vs Cyrillic small `а` (U+0430); Latin `c` (U+0063) vs Cyrillic `с` (U+0441). "Homoglyph" is
  a *rendering* property and is font-dependent. [Suzuki 2019, arXiv:1909.07539; unicode.org/reports/tr39]

- **Confusable (UTS #39 term)** — the Unicode Consortium's formal, data-driven notion. Two
  strings are *confusable* if they map to the same **skeleton** under the `skeleton()` transform,
  which replaces each character with a "prototype" from the `confusables.txt` data file (e.g.
  `0441 ; 0063 ; MA` maps Cyrillic `с` -> Latin `c`). Confusables are classed as
  **single-script**, **mixed-script**, and **whole-script** confusables. This is the standardized,
  citable definition; "homoglyph" is the informal visual notion. [UTS #39, unicode.org/reports/tr39, current 2024 rev.]

- **IDN homograph attack** — a *specific application* of confusables to **Internationalized
  Domain Names**. Since IDNA lets Unicode appear in domain labels (Punycode-encoded on the wire
  as `xn--...`), an attacker registers a name whose glyphs match a target brand's ASCII domain.
  The term "homograph" (same-looking word) is the security-community name for this; technically
  these are whole-script or mixed-script confusables at the DNS-label level. [Suzuki 2019, arXiv:1909.07539; Zheng 2017]

**Distinction to hold onto:** *homoglyph* = visual fact (font-dependent); *confusable* =
UTS #39's formal, table-backed relation used to *operationalize* it; *IDN homograph attack* =
the confusable trick applied to domain names. A pair can be visually confusable to a human yet
*absent from* `confusables.txt` (the table is incomplete — see Deng 2020, which predicted 8,000+
previously-unknown homoglyphs). [Deng 2020, arXiv:2010.04382]

---

## 2. Concrete, real examples (defanged)

### 2.1 The canonical IDN homograph: "apple.com" (Xudong Zheng, 2017)
- Zheng registered `xn--80ak6aa92e[.]com`, which **rendered as `apple[.]com`** in Chrome ≤58,
  Firefox ≤53, and Opera. Every letter of "apple" was **Cyrillic** (e.g. Cyrillic `а` U+0430,
  `р` U+0440, `е` U+0435, `с`...), so the label was **entirely single-script** and thus sailed
  past the browsers' *mixed-script* heuristic (which had been the main defense since ~2005).
  This is a **whole-script confusable**. [Zheng 2017, https://www.xudongz.com/blog/2017/idn-phishing/ ; Mozilla bug 1463219]
- Fix path: Chrome/Firefox tightened IDN display policy so a label rendered as Unicode only if it
  passes stricter script/whole-script-confusable checks; otherwise the raw `xn--` Punycode is shown.

### 2.2 Brand-name substitution in text (display name / subject / body)
- `pаypal` where the first `a` is Cyrillic `а` (U+0430) — looks like "paypal" but fails an exact
  string match against the brand allow-list. [UTS #39 examples; NameSilo blog 2024]
- UTS #39's own worked example: `skeleton("paypal")` equals the skeleton of a string that mixes
  **Greek, Cyrillic, and Hebrew** glyphs (`ρ⍺у𝓅𝒂ן`) — all collapse to the same skeleton.
  [unicode.org/reports/tr39]

### 2.3 Non-cross-script confusables (no foreign script needed)
- `rn` -> `m` (Latin `r`+`n` visually approximates `m`): `paypa1[.]com` uses digit `1` for `l`;
  `rnicrosoft[.]com` for "microsoft". These are **single-script (all-ASCII)** and therefore evade
  *any* script-mixing detector entirely. dnstwist enumerates these as first-class permutations.
  [elceef/dnstwist, github.com/elceef/dnstwist]

### 2.4 Math / styled / fullwidth Unicode (spam-filter evasion in body text)
- **Mathematical Alphanumeric Symbols** block (U+1D400–U+1D7FF), e.g. bold `𝐏𝐚𝐲𝐏𝐚𝐥`, italic,
  script, double-struck. Widely seen in spam subject lines to defeat keyword matching while
  staying human-legible. Unicode explicitly warns these are semantically distinct and should not
  substitute for markup. [Wikipedia "Mathematical Alphanumeric Symbols"; unicode.org charts]
- **Fullwidth forms** (U+FF01–U+FF5E), e.g. `ｐａｙｐａｌ`. Unlike Cyrillic homoglyphs, most of
  these **do** have NFKC compatibility mappings back to ASCII — a defensively useful asymmetry
  (see defenses note).

### 2.5 Where each lands in the EMAIL pipeline
| Pipeline field | How the attack shows up | Notes |
|---|---|---|
| `From:` display name | `Аpple Support` (Cyrillic А) | Seen by user in client; not authenticated by SPF/DKIM/DMARC. |
| `From:`/`Return-Path` domain | IDN homograph `xn--...` or ASCII typo | DMARC checks the *actual* domain, but users read the rendered glyphs. |
| `Subject:` | Math-bold / styled letters, mixed-script brand | Evades keyword/regex spam rules. |
| Body anchor text (`<a>...text...</a>`) | Shows `paypal[.]com`, `href` points elsewhere | Anchor text is prime homoglyph real estate. |
| Body URL host (in `href`) | Homograph IDN, Punycode | Feeds link-reputation and must be normalized before lookup. |
| Brand names in body | Confusable substitution to dodge brand-impersonation rules | Combine with invisible chars (see adversarial-ML note). |

---

## 3. Why this is hard (structural facts to carry into defenses)
1. **Whole-script confusables** defeat mixed-script detection (the apple.com case). [Zheng 2017]
2. **NFKC does NOT collapse Cyrillic/Greek->Latin**: those are *canonical*, not *compatibility*
   equivalents, so `NFKC("pаypal")` still contains U+0430. Cheap normalization catches fullwidth
   and math-alphanumerics but **not** the classic cross-script homoglyphs. [UAX #15; UTS #39; paultendo 2024]
3. **`confusables.txt` is incomplete and font-dependent**: UTS #39 itself states "shapes of
   characters vary greatly among fonts," so no table is complete; Deng 2020 found 8,000+ unlisted
   homoglyphs via a vision model. [UTS #39; Deng 2020, arXiv:2010.04382]
4. **All-ASCII confusables** (`rn`->`m`, `1`->`l`, `0`->`o`) need no Unicode at all and evade every
   script-based defense. [dnstwist]

---

## 4. Flagged / unverified
- Exact browser version cutoffs (Chrome 58, Firefox 53) are from Zheng's blog and the Mozilla bug
  tracker (secondary but authoritative); not independently re-derived here.
- The specific "8,000+ predicted homoglyphs" figure is the authors' claim (Deng 2020) with early
  manual spot-checks, not an exhaustively validated set — flagged by the authors themselves.

## Sources used (see research/sources.md for full bibliography)
Suzuki 2019 (arXiv:1909.07539) · Zheng 2017 (xudongz.com blog) · Mozilla bug 1463219 · UTS #39
(unicode.org/reports/tr39) · UAX #15 (unicode.org/reports/tr15) · Deng 2020 (arXiv:2010.04382) ·
Boucher 2021 (arXiv:2106.09898) · dnstwist (github.com/elceef/dnstwist) · Mathematical Alphanumeric
Symbols (Wikipedia/unicode charts) · paultendo 2024 (confusables-vs-NFKC).
