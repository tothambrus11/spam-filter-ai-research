# Taxonomy — HTML/CSS Obfuscation & Hidden Text in Email Bodies

Attack class scope: text/markup hidden or transformed via HTML and CSS so that what a
**human sees** in a mail client diverges from what a **content scanner / classifier
parses**. This "perceptual asymmetry" is the core primitive; every technique below is a
way to widen the gap between the *recipient view* and the *filter view*.

All URLs defanged (hxxp, [.]). Years noted; field moves fast — most techniques below were
confirmed active in real campaigns in 2024–2025.

---

## 0. Three intents (do not conflate them)

Content concealment is not one thing. Separate by *who is being fooled*:

| Intent | Who is fooled | Goal | Typical technique |
|---|---|---|---|
| **A. Fool the CLASSIFIER (ham injection / "good words")** | ML/keyword filter | Dilute spam signal with invisible legit-looking text so the message scores as ham | `display:none` paragraphs of neutral/marketing prose; hidden common English words appended in bulk (Lowd–Meek "good word attack") [LowdMeek05] |
| **B. Fool the CLASSIFIER (keyword/brand disruption)** | ML/keyword/regex filter, brand-impersonation and language detectors | Break the tokens a filter keys on — split "PayPal" so no `PayPal` token exists; confuse language ID | zero-width chars / HTML comments / zero-width spans **inside** flagged words; hidden foreign-language paragraphs to flip language detection [TalosSeasoning25] |
| **C. Fool the HUMAN (parser blind)** | Recipient | Show benign-looking content to a scanner but a different message (or nothing) to the human, OR hide attacker content from the human while it still reaches a machine reader (LLM) | Outlook conditional comments showing a clean link to analysts; invisible prompt-injection text aimed at an LLM judge [Koide26] |

"Hidden text salting" (Cisco Talos' term, 2025) is mostly **A + B**: invisible "salt"
(random chars, foreign words, HTML comments) sprinkled into preheader/header/body/attachment
to poison the filter's view while the human sees a clean phish. [TalosSeasoning25,
TalosTooSalty25]

The academic term is **content concealment**; Betts et al. (2024) split it into three
sub-types on a 984-email sample: **Add Paragraph** (57.8% of concealment cases — bulk hidden
text, intent A), **Disrupt Word** (50.3% — invisible chars inside a word, intent B), and
**Insert Word** (6.2%, mostly pre-2011). [Betts24]

---

## 1. CSS visibility / display hiding (the core inventory)

Confirmed properties observed in real spam/phish (Talos 2024–2025 corpus [TalosSeasoning25,
TalosTooSalty25, TalosAbusingStyle25]; Betts24; Sublime docs [SublimeKeywords]):

- `display:none` — removed from layout entirely. Most-cited.
- `visibility:hidden` — occupies space but invisible.
- `opacity:0` — fully transparent, still in DOM and clickable.
- `font-size:0` (or `1px`/`3px`) — text collapses to nothing/near-nothing. Betts24 found
  `font-size` reduced to ≤3px in 218 occurrences.
- `color:` == background color (or `color:transparent`) — low/zero contrast. Betts24's
  single most common trick: **Font Colour, 264 occurrences**, exploiting CSS inheritance so
  the hidden `color` need only be set on a parent.
- `width:0` / `height:0` / `max-width:0` / `max-height:0` combined with `overflow:hidden` —
  container clips content to nothing.
- `display:inline-block; width:0; overflow:hidden` — used to hide junk chars *between brand
  letters* (Wells Fargo sample, Talos). [TalosSeasoning25]
- `text-indent:-9999px` and absolute positioning off-screen (`position:absolute; left:-9999px`)
  — moves text out of the viewport. [TalosAbusingStyle25]
- deprecated `clip:rect(0,0,0,0)` and modern `clip-path` — clips the rendered box away.
- `line-height:0` manipulation. [TalosTooSalty25]
- **Table manipulation** — zero-size/overlapping table cells, rows, columns hide content
  structurally (Betts24: 63 occurrences).
- **Combination** is the norm: real salt often stacks
  `color:transparent;visibility:hidden;display:none;opacity:0;height:0;width:0;font-size:0;`
  in a single `style` attribute (this exact stack appears in Sublime's own doc example).
  [SublimeKeywords] Betts24: font-colour + font-size was the most common pairing.

### 1a. Client-specific rendering divergence (renders differently for human vs parser)
- **MSO / Outlook conditional comments**: `<!--[if mso]> … <![endif]-->` renders **only** in
  Microsoft Outlook (Word rendering engine); `<!--[if !mso]><!--> … <!--<![endif]-->` renders
  everywhere **except** Outlook. Attackers show a clean/benign link to analysts (who use
  Outlook in corporate SOCs) and the real payload to everyone else — or vice versa.
  Documented since ~2019, still exploited 2024. [gbhackersOutlook, TalosTooSalty25]
- `mso-hide:all` — Outlook-specific "hide this element" property; content is invisible in
  Outlook but visible in webmail (or the reverse of the above). [SO-mso-hide, TalosTooSalty25]
- `@media` queries: serve different content/URLs by screen width, color-scheme, resolution.
  A scanner rendering at one viewport sees different content than the human's device.
  [TalosAbusingStyle25]
- `@font-face` OS-fingerprinting (checking for "Segoe UI" ⇒ Windows, "Helvetica Neue" ⇒ macOS)
  to conditionally deliver content. [TalosAbusingStyle25]

---

## 2. Injection *between* letters (word/token disruption — intent B)

Goal: destroy the exact byte sequence a keyword/regex/brand detector matches, while the
letters still render adjacent to the human eye.

- **Zero-width characters**: ZWSP (U+200B), ZWNJ (U+200C), ZWJ (U+200D), word-joiner (U+2060),
  soft hyphen (U+00AD) inserted between letters: `N‌o‌r‌t‌o‌n` reads normally but no `Norton`
  token exists. (Norton LifeLock sample, Talos.) [TalosSeasoning25]  *(Overlaps the
  zero-width/invisible-char attack class — cross-reference that taxonomy file.)*
- **HTML comments between letters**: `Pay<!--x-->Pal` — comment is invisible on render,
  breaks the token for any parser that doesn't strip comments before tokenizing.
- **Zero-width styled spans between letters**: `P<span style="font-size:0">junk</span>ayPal`.
- **Language-detection poisoning**: inject a hidden foreign-language paragraph (French, German,
  Finnish, Estonian observed) so Microsoft **Exchange Online Protection (EOP)** misclassifies
  an English phish as another language, degrading downstream English-tuned models.
  [TalosSeasoning25, TalosTooSalty25]

---

## 3. Encoding / entity obfuscation

- **Numeric & hex HTML entities**: `&#112;&#97;&#121;&#112;&#97;&#108;` or
  `&#x70;&#x61;…` renders as "paypal" but a naive substring/regex over raw HTML misses it.
  Attacker can partially entity-encode (`p&#97;ypal`) to defeat entity-agnostic matching.
- **base64 `data:` URIs**: entire HTML/JS/image payloads as `data:text/html;base64,…` or
  `data:image/png;base64,…` — content never appears as readable markup to a text scanner.
  Also used in HTML-smuggling attachments.
- **HTML comments padding base64**: irrelevant comments inserted *between* base64 characters
  in an attachment so an attachment parser cannot reconstruct/decode the payload
  (`PD<!--a-->94b…`). Confirmed in Talos HTML-smuggling samples. [TalosSeasoning25]
- **JS/CSS-driven reveal**: content assembled at runtime (`document.write`, `innerHTML`,
  `atob()` decode, CSS `::before{content:…}` pseudo-element text) so it exists nowhere in the
  static DOM the scanner parses. A non-executing scanner never sees the final text.
- **Percent/URL-encoding and mixed encodings** in hrefs to cloak the destination.

---

## 4. "Salad" / hashbusting / preheader abuse

- **Hidden random-text salad ("hashbusting")**: unique random invisible strings per message
  so every copy has a different body hash / different bag-of-words, defeating hash-based and
  bulk/fuzzy-signature detection while the visible content is identical. (Long-standing spam
  tactic; the modern CSS form is Talos' "salt".) [TalosSeasoning25]
- **Salt location matters**: Talos found salt in the **preheader** (rarest), **headers**,
  **attachments**, and **body** (most common). Preheader/header salt specifically targets the
  snippet/summary text clients and filters extract. [TalosTooSalty25]
- **Hidden tracking pixels / beacons**: remote 1×1 images hidden via CSS to log opens; also
  used to fingerprint client via `@media`/`@font-face`. Note: also common in *legitimate*
  marketing mail, so presence alone is a weak signal. [TalosAbusingStyle25]

---

## 5. Real examples (defanged, dated)

- **Wells Fargo phish** — junk characters between brand letters hidden with
  `display:inline-block; width:0; overflow:hidden`. (Talos, reported Jan 2025.) [TalosSeasoning25]
- **Norton LifeLock phish** — ZWSP/ZWNJ inserted between letters of the brand name.
  (Talos, Jan 2025.) [TalosSeasoning25]
- **Harbor Freight phish** — hidden French-language `<div>` (via `display:none`) to poison EOP
  language detection. (Talos, Jan 2025.) [TalosSeasoning25]
- **HTML-smuggling attachment** — base64 payload padded with HTML comments to defeat the
  attachment decoder/URL extractor. (Talos, Jan 2025.) [TalosSeasoning25]
- **CSS-tracking campaigns** — `@media`/`@font-face`/remote-resource fingerprinting embedded in
  otherwise ordinary marketing-style mail. (Talos, Mar 2025.) [TalosAbusingStyle25]
- **Outlook conditional-comment phish** — analysts on Outlook shown a benign link; real victims
  on webmail shown the phishing link (or reverse). (reported 2024–2025.) [gbhackersOutlook]
- **Historical corpus** — Betts et al. rendered the University of… Spam Archive
  (8.4M emails, 1998–2024); 37.6% of a stratified sample carried concealed content, with
  Font-Colour and Font-Size tricks *stable across all years* (i.e., still effective).
  [Betts24]

---

## 6. Email-surface specifics (what clients render vs strip)

- **No JavaScript in mail**: Gmail, Outlook.com, Apple Mail, and virtually all modern clients
  strip `<script>` and JS event handlers. ⇒ JS-gated reveal (§3) does **not** render for the
  human either — so it's a weak *human*-targeting vector but a strong *scanner-desync* vector
  if the scanner *does* execute JS in a sandbox (it renders something the recipient never sees).
- **CSS support is uneven**: Gmail strips `<style>` in `<head>` in some contexts and rewrites
  CSS; it historically did **not** support `@media`/embedded styles the same way Apple Mail
  does; Outlook desktop uses the **Word** engine (poor CSS, but honors MSO conditionals and
  `mso-hide`). This divergence is itself the attack surface (§1a): no single "render" reproduces
  every client.
- **Remote content**: many clients proxy or block remote images by default (Gmail image proxy),
  and remote `@import`/external CSS is widely stripped — so remote-CSS reveal is unreliable for
  hitting the human but can still desync a scanner that fetches remote CSS vs one that doesn't.
- **`display:none` is honored by essentially all rendering clients** — which is exactly why it's
  the workhorse: reliably invisible to the human, reliably present for a naive text parser.
- **Preheader** text is pulled by clients for the inbox snippet; hidden preheader salt can shape
  that snippet or hide from it.

---

## 7. Cross-references
- Zero-width / invisible characters and homoglyphs: see Unicode confusables taxonomy file.
- base64 `data:` image payloads and screenshot-only phish: see text-in-image taxonomy file.
- LLM-judge prompt injection via hidden text: see §Intent-C above and defenses/html-css.md
  (Koide et al. 2026) — this is the newest and most dangerous convergence.

## Unverified / flagged
- Exact per-client CSS support matrices shift constantly; the client-behavior claims above are
  synthesized from vendor blogs and general email-dev knowledge, not a controlled 2025 test.
  Flag for a fresh render-matrix experiment before relying on any single "canonical render."
- Betts24's honeypot/dataset skews pre-2018 for some sub-types; post-2018 evolution is
  under-measured in that paper (their own stated limitation).
