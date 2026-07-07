# Taxonomy — Zero-Width & Invisible Characters

Attack class: insertion of Unicode codepoints that render to **zero advancing width /
no glyph** (or are silently dropped by renderers) so that text looks identical to a
human while its byte/codepoint sequence differs. Used to (a) break keyword/URL/brand
matching, (b) spoof identity, and (c) — the 2024+ frontier — **smuggle instructions or
data past humans and into LLM-based email assistants/classifiers**.

All claims carry a citation. Live URLs defanged (hxxp, [.]).

---

## 1. Inventory of exploited codepoints

| Codepoint(s) | Name | Unicode category | Notes / abuse |
|---|---|---|---|
| U+200B | ZERO WIDTH SPACE (ZWSP) | Cf | invisible word-break; splits keywords/URLs [avanan2019zwasp] |
| U+200C | ZERO WIDTH NON-JOINER (ZWNJ) | Cf | legit in Persian/Arabic/Indic; used as "1" bit in ZW-binary [reversecaptcha2026] |
| U+200D | ZERO WIDTH JOINER (ZWJ) | Cf | **legit**: emoji sequences (👨‍👩‍👧), Indic conjuncts — big false-positive source |
| U+2060 | WORD JOINER (WJ) | Cf | non-breaking, invisible; replaces deprecated BOM-as-joiner |
| U+FEFF | ZERO WIDTH NO-BREAK SPACE / BOM | Cf | invisible when mid-stream; also byte-order mark |
| U+00AD | SOFT HYPHEN (SHY) | Cf | invisible in-line in most clients; classic spam splitter since 2010 [threatpost2010shy][sans2025shy] |
| U+2062, U+2063, U+2064 | INVISIBLE TIMES / SEPARATOR / PLUS | Cf | math-invisible operators; no glyph |
| U+2061 | FUNCTION APPLICATION | Cf | invisible |
| U+180E | MONGOLIAN VOWEL SEPARATOR | Cf | historically zero-width; renderer-dependent |
| U+034F | COMBINING GRAPHEME JOINER | Mn | no visible mark |
| U+FE00–U+FE0F | VARIATION SELECTORS VS-1..16 | Mn | steganography carrier (1 byte each) [butler2025] |
| U+E0100–U+E01EF | VARIATION SELECTORS VS-17..256 | Mn | 240 more; full-byte steganography [butler2025] |
| U+E0000–U+E007F | **TAGS block** (U+E0001 LANGUAGE TAG, U+E0020–E007E ASCII tag chars) | Cf | "ASCII smuggling": mirrors full ASCII set, invisible in most UIs [rehberger2024][cisco2024tag] |
| U+2028 / U+2029 | LINE / PARAGRAPH SEPARATOR | Zl/Zp | invisible structural chars, can hide content in some parsers |
| U+115F, U+1160, U+3164, U+FFA0 | Hangul filler / "blank" fillers | — | render as blank; used as invisible usernames/spacing |

Most invisibles are Unicode general category **Cf (Format)** or **Cc (Control)**; the
variation-selector carriers are **Mn (Nonspacing Mark)** — important because a naive
"strip all Cf" filter misses the VS steganography channel (verified in defenses file).

---

## 2. Real examples (with years)

### 2.1 Keyword / brand-name evasion ("hidden text salting")
- Cisco Talos reported wide adoption of **hidden text salting** in **H2 2024**: ZWSP/ZWNJ
  inserted *between letters of brand names* so brand-extraction fails, e.g. a Wells Fargo
  lure whose HTML reads `WE<junk>LLS FA<junk>RGO` while rendering `WELLS FARGO`; Norton
  LifeLock impersonations used invisible Unicode; a phishing mail was mis-classified as
  French by Exchange Online Protection because hidden French text was salted in
  [talos2024salting]. Microsoft's 2021 "trend-spotting" writeup documented the same
  human/machine perception gap earlier [microsoft2021].

### 2.2 URL / link cloaking to bypass Office 365 ("Z-WASP")
- **Avanan, disclosed Nov 2018, Microsoft fix 2019-01-09**: the **Z-WASP** attack
  fragmented malicious URLs in email HTML with **zero-width non-joiner (`&#8204;`)** so
  Office 365 URL-reputation / Safe Links did not recognize the domain, while the rendered
  link looked legitimate (credential-harvest page mimicking Chase) [avanan2019zwasp]. A
  related variant, **"Shy Z-WASP,"** combines ZWJ + soft-hyphen HTML entities [gbhackers/talos2024salting].

### 2.3 Soft-hyphen URL/subject splitting (oldest, still live)
- **Threatpost, 2010**: spammers larded promoted URLs with **U+00AD SHY**, which many
  browsers ignore, to defeat signature rules [threatpost2010shy].
- **SANS ISC, 2025-10-28**: phishing that hides **U+00AD** *in the Subject line* via
  **RFC 2047 MIME encoded-words** (`=?UTF-8?B?…?=`), fragmenting keywords before they
  reach the subject-line filter — noted as still relatively uncommon [sans2025shy].

### 2.4 Homograph of spaces / invisible spacing
- Full-width and blank fillers (e.g. U+FFA0, U+3164) and no-break/zero-width spaces are
  used to fake whitespace or hide tokens; enumerated among the five "ZWSP entities"
  abused in email HTML [avanan2019zwasp].

### 2.5 Unicode Tags "ASCII smuggling" into LLMs (2024)
- **Riley Goodside, 2024-01-11**: demonstrated encoding ASCII into the **Tags block**
  (`'R' U+0052 → U+E0052`), invisible to humans but the LLM tokenizer re-expands it, so
  ChatGPT executed hidden instructions (invoked DALL·E) [cisco2024tag].
- **Johann Rehberger (Embrace The Red), 2024-02**: coined operational **"ASCII Smuggling"**;
  Tags mirror the whole ASCII set and are invisible in most UI; LLMs both *read* and can
  *emit* such hidden text (data-exfil channel in Copilot-style assistants) [rehberger2024].

### 2.6 Variation-selector steganography (2025)
- **Paul Butler, 2025**: any byte string can be hidden by appending **variation selectors**
  (VS-1..256) after a carrier emoji/char — 1 byte per selector, unbounded length, invisible,
  and *spec-mandated to survive copy/paste and transforms*. Explicit uses cited: content-filter
  evasion and per-recipient watermarking [butler2025]. Predates it: high-capacity ZWSP/ZWNJ
  text steganography is a decade-old academic subfield [naeini2020][textstegreview2021].

### 2.7 Reverse-CAPTCHA / invisible instruction injection (2026 measurement)
- **arXiv:2603.00164 (2026)** measured LLM susceptibility to invisible instructions via
  two channels: **zero-width binary** (U+200B=0, U+200C=1) and **Unicode Tags**. Compliance
  was model- and encoding-specific and **exploded when tools were enabled** (≤17% → 98–100%),
  with Anthropic models preferring Tags and OpenAI models preferring zero-width binary
  [reversecaptcha2026].

---

## 3. Where it hits an EMAIL pipeline

1. **Subject/body keyword & brand evasion** — invisibles inserted between letters defeat
   substring/regex/brand-extraction and Bayesian tokenization (§2.1, §2.3) [talos2024salting][sans2025shy].
2. **URL / link cloaking** — ZWNJ/SHY inside the href fragment the domain so
   reputation/Safe-Links lookups miss it (§2.2) [avanan2019zwasp].
3. **Sender / display-name spoofing** — invisible or blank-filler codepoints in From/display
   names and lookalike whitespace to imitate trusted senders.
4. **Language/route confusion** — salted foreign-language text flips language detection and
   routing (§2.1) [talos2024salting].
5. **NEW — LLM-assistant smuggling** — as gateways add LLM triage/summarization/auto-reply,
   Tags/zero-width-binary payloads hidden in body or subject become *indirect prompt
   injection*: invisible to the human reviewer but executed by the model, especially with
   tool access (§2.5, §2.7) [rehberger2024][reversecaptcha2026]. This is the highest-severity
   modern variant because the "human-in-the-loop" mitigation is defeated by design.

## 4. Bibliography (this file)
See consolidated block in the return message / research/sources.md. Keys:
avanan2019zwasp, threatpost2010shy, sans2025shy, talos2024salting, microsoft2021,
cisco2024tag, rehberger2024, butler2025, reversecaptcha2026, naeini2020, textstegreview2021,
boucher2021, gbhackers.
