# Defenses — HTML/CSS Obfuscation & Hidden Text (with mandatory known bypasses)

Rule: a defense with an unaddressed bypass is not SOTA. Each entry: mechanism → known bypass.
Citations: arXiv id / DOI / URL + year. Vendor-blog-only claims are marked **[vendor-blog]**.
Defang: hxxp, [.].

---

## D1. Naive DOM text extraction (strip tags, tokenize) — **BASELINE, INSUFFICIENT**
**Mechanism.** Parse HTML, drop tags, feed the concatenated text to the classifier
(BeautifulSoup `get_text()`, or Sublime's `body.html.inner_text`). Cheap, fast, universal.

**Known bypass — this is the core failure of the whole class.** Tag-stripping does **not**
evaluate CSS, so it *includes* text that is `display:none`/`visibility:hidden`/`opacity:0`.
Confirmed: Sublime's parsed `inner_text` field still contains a span styled
`display:none;opacity:0;height:0;width:0;font-size:0;` — the hidden content "appears in the
parsed output." [SublimeKeywords, vendor-docs] So:
- **Ham injection (good-word attack)** poisons this view directly — the invisible legit
  paragraph is fed to the classifier as if visible. [LowdMeek05]
- **Word-disruption** (zero-width chars / comments between letters) survives unless the
  tokenizer also normalizes those. [TalosSeasoning25]
⇒ Any pipeline that classifies raw-parsed text is trivially evaded. This motivates D2–D5.

---

## D2. Rendered-visibility extraction (headless render → visible text only) — **STRONGEST TEXT-TIER**
**Mechanism.** Actually render the email (headless Chromium via Playwright/Puppeteer),
compute the CSS cascade, and extract only text that is *actually visible* — either via
DOM computed-style filtering (drop nodes with `display:none`, `visibility:hidden`,
`opacity≈0`, zero box size, off-screen position, fg≈bg contrast) or via screenshot+OCR.
Betts et al. (2024) operationalize the two-view comparison: BeautifulSoup "filter view" vs
Playwright+OCR "recipient view", Jaccard distance between the word sets flags concealment
(mean Jaccard 0.22 with concealment vs 0.07 without). [Betts24, arXiv:2410.11169]
This is the right *canonicalization* idea: classify what the human sees, and separately flag
the *delta* as a hidden-content signal.

**Known bypasses.**
1. **Client-rendering divergence.** "The render" isn't unique. Outlook (Word engine) honors
   `mso-hide:all` and `<!--[if mso]>` conditionals that Chromium ignores, and vice-versa
   [TalosTooSalty25, gbhackersOutlook]. A single Chromium render reproduces *one* client;
   attacker targets the gap between the scanner's render and the victim's client. Defeating
   this needs a *multi-client* render matrix (Chromium + Word engine + webmail CSS rules),
   which few gateways run.
2. **`@media`/`@font-face`/viewport conditioning.** Content keyed on screen width, color-scheme,
   or OS-font presence renders differently at the scanner's viewport than on the victim device.
   [TalosAbusingStyle25]
3. **JS-gated / dynamically-loaded content.** Scanners that render but don't fully execute JS
   (most, for safety/cost) miss `document.write`/`atob`/`innerHTML`-assembled text; a scanner
   that *does* execute sees content the JS-less victim client never will (false desync). Mail
   clients strip JS, so this is a scanner-vs-scanner problem, not scanner-vs-human.
4. **Render-cost DoS.** Headless render + OCR is expensive (seconds/CPU per message). Betts24
   explicitly states "the OCR process may not be suitable for real-time analysis in practical
   mail filtering." [Betts24] Attackers can send huge/deeply-nested DOMs, CSS animation loops,
   or many messages to exhaust the render farm, forcing fail-open to the cheap D1 path.
5. **OCR fidelity.** Homoglyph/low-contrast-but-technically-visible text, tiny-but-nonzero
   fonts, and image-rendered text stress OCR; mis-reads create their own evasion (ties to the
   text-in-image class).

---

## D3. Hidden-text heuristics as spam FEATURES (detect the concealment, don't just remove it)
**Mechanism.** Instead of (or alongside) extracting visible text, treat the *presence* of
concealment as a strong malicious signal: flag `display:none`/`visibility:hidden`/`font-size:0`/
`color==background`/`opacity:0`/zero-size/off-screen elements, excessive inline styles, HTML
comments inside words, zero-width chars between letters, base64-comment padding, MSO conditionals.
Talos and Sublime both recommend this; Sublime ships open detection rules keying on these CSS
properties and on the visible-vs-raw text delta. [TalosSeasoning25, TalosTooSalty25,
SublimeKeywords, SublimeRules] Betts24's visible/hidden Jaccard delta is the same idea quantified.
Rationale: concealment is far more common in spam/phish than ham, so it's discriminative.
[TalosTooSalty25]

**Known bypasses.**
1. **Static-heuristic evasion via computed styles.** Heuristics that scan the raw `style=`
   attribute miss hiding achieved through *inheritance* (parent sets `color`, child inherits —
   Betts24's dominant Font-Colour trick), external/`<style>`-block/`@import` rules, CSS variables,
   or class names resolved only by the cascade. You must compute styles, not string-match — which
   collapses D3 back into the cost of D2.
2. **Legitimate-use false positives.** `display:none` preheaders, `mso-hide`, and hidden
   tracking pixels are *rampant in legitimate marketing mail* [TalosAbusingStyle25]. Naive
   "has display:none ⇒ spam" over-blocks; attackers deliberately mimic marketing structure to
   ride under the FP-tolerance threshold.
3. **Novel/`Other` tricks.** Betts24 bucketed 33 occurrences as unclassifiable
   (first-letter selectors, bespoke combinations) — heuristic lists are enumerable and always
   trail attacker creativity.
4. **Sub-threshold hiding.** `font-size:3px`, `opacity:0.02`, contrast just above a hard cutoff:
   technically "visible," dodging boolean heuristics while ~invisible to humans. [Betts24]

---

## D4. Entity/encoding decode + canonicalization before classification
**Mechanism.** Before matching/classifying: decode HTML entities (`&#xNN;`, numeric refs),
strip comments, normalize Unicode (NFKC), remove zero-width/soft-hyphen chars, decode `data:`
base64, collapse the token-splitting tricks — producing a canonical string the classifier scores.
Directly counters intent-B word disruption and entity obfuscation (§3 taxonomy).

**Known bypasses.**
1. **Aggressive normalization is itself an attack surface.** Stripping zero-width chars and
   collapsing whitespace can *merge* attacker-intended separators, and NFKC can map distinct
   strings together — creating false matches or erasing signal. Over-canonicalization also
   destroys legitimately-meaningful characters.
2. **Decode-order / parser-differential.** If the canonicalizer's HTML/entity parser differs
   from the victim client's, the attacker crafts input that decodes one way for the scanner and
   another for the human (classic "parser differential"). Partial entity encoding and malformed
   markup exploit this.
3. **Doesn't touch CSS visibility.** Decoding entities does nothing about `display:none` ham
   injection — D4 is necessary but must be paired with D2/D3.
4. **JS/CSS runtime reveal** (`::before{content}`, `atob`) is invisible to a static decoder.

---

## D5. Full browser render → screenshot → OCR / vision-LLM
**Mechanism.** Render in a real browser, screenshot the rendered email, and run OCR or a
vision-LLM over the pixels — classify *exactly the pixels the human sees*, sidestepping all
markup tricks by construction. Betts24 uses this as ground-truth "recipient view";
Sublime uses browser-emulation + computer vision (logo/login-form/CAPTCHA detection) on
followed links. [Betts24, SublimeCredPhish (vendor-blog)] Strong against text-markup evasion
and ties into the text-in-image defense tier.

**Known bypasses.**
1. **Cost / latency / DoS** — same as D2.4; heaviest tier, most DoS-exposed, most likely to
   fail-open under load. [Betts24]
2. **Rendering divergence** — the screenshot is of *the scanner's* client; §D2.1 applies. Vision
   can't see what a *different* client would show (MSO conditionals, `@media`).
3. **Prompt injection against the vision/LLM judge (critical, 2026).** Koide, Nakano & Chiba
   (2026) show CSS-*concealed* text is a prompt-injection **surface**: invisible-to-human
   instructions embedded in the HTML are still parsed by an LLM-based detector, flipping its
   verdict. Even GPT-5-class multimodal detectors remain vulnerable. Their InjectDefuser
   (prompt hardening + allowlist RAG + output validation) reduces but does not eliminate ASR.
   [Koide26, arXiv:2602.05484] ⇒ Moving to an LLM/vision judge *reopens* the hidden-text
   channel in a new form: hidden text now *commands* the classifier instead of merely diluting it.
4. **Screenshot-only phish / image text** stresses OCR; adversarial perturbations on rendered
   images can fool vision models (cross-ref adversarial-ML and image-text classes).

---

## D6. Structural / DOM ML features (classify HTML structure, not just text)
**Mechanism.** Features from HTML/CSS structure — tag/style distributions, count of hidden
elements, inline-style density, comment density, entity ratio, DOM depth, visible/hidden token
ratio — fed to ML (or end-to-end models over raw HTML like WebPhish). [Opara20,
arXiv:2011.04412] Robust to *content* wording; keys on the *obfuscation footprint* itself.

**Known bypasses.**
1. **Structure mimicry.** Attackers template phish off real newsletters/marketing HTML so the
   structural fingerprint matches ham (legit mail is full of hidden pixels, inline styles,
   `mso-hide`). [TalosAbusingStyle25]
2. **Adversarial feature manipulation / good-word at the structure level.** Add benign
   structural features to shift the vector across the boundary — the Lowd–Meek attack
   generalizes from words to any additive feature space; linear/NB models especially fragile.
   [LowdMeek05] Text-preprocessing-robust pipelines still fall to TextAttack-style perturbations
   in evaluation. [Kulal25, arXiv:2510.11915]
3. **Concept drift** — structural signatures age; the model needs constant retraining, and
   Betts24 shows some tricks are stable-but-evolving over 25 years.

---

## Synthesis of the defense stack (what actually holds)
- **No single tier is sufficient.** D1 alone is broken (D1 bypass). The defensible design is a
  **canonicalization + delta** pattern: (a) canonicalize (D4) then (b) extract *rendered-visible*
  text (D2) to classify what the human sees, while (c) treating the *hidden/visible delta* and
  concealment footprint (D3/D6) as an independent strong feature — you both neutralize the
  poison *and* score the fact that poison was present.
- **Every rendering tier inherits the client-divergence bypass** (D2.1): there is no single
  canonical render; robustness needs a small multi-client render matrix, not one Chromium.
- **The newest, least-addressed bypass** is prompt injection of the LLM/vision judge via hidden
  text (D5.3, [Koide26 2026]) — the "smart" defenses reopen the hidden-text channel.
- **Cost/DoS (D2.4/D5.1)** is the practical ceiling: heavy render/OCR/LLM tiers cannot run on
  100% of mail volume, so pipelines must gate them and resist fail-open.

## Unverified / flagged
- Sublime's browser-emulation + computer-vision link analysis is **vendor-blog** described,
  not independently benchmarked here. [SublimeCredPhish]
- Microsoft's "LLM BEC detection, 99.995% accuracy, ~140k/day blocked" is a **vendor** figure,
  unverified and not an apples-to-apples hidden-text metric. [MS-BEC vendor]
- Betts24 does not benchmark evasion against named commercial filters (their stated limitation);
  its evasion claims are structural, not measured kill-rates.
- InjectDefuser efficacy [Koide26] is authors' own eval; residual ASR remains — flag for
  independent replication.

---

## Bibliography (this file + taxonomy)
- **[Betts24]** Exploring Content Concealment in Email — L. Betts, R. Biddle, D. Lottridge,
  G. Russello (2024). arXiv:2410.11169.
- **[Koide26]** Clouding the Mirror: Stealthy Prompt Injection Attacks Targeting LLM-based
  Phishing Detection — T. Koide, H. Nakano, D. Chiba (2026). arXiv:2602.05484.
- **[Opara20]** Look Before You Leap: Detecting Phishing Web Pages by Exploiting Raw URL and
  HTML Characteristics (WebPhish) — C. Opara, Y. Chen, B. Wei (2020). arXiv:2011.04412.
- **[Kulal25]** Robust ML-based Detection of Conventional, LLM-Generated, and Adversarial
  Phishing Emails Using Advanced Text Preprocessing — D. H. Kulal et al. (2025). arXiv:2510.11915.
- **[LowdMeek05]** Good Word Attacks on Statistical Spam Filters — D. Lowd, C. Meek (2005).
  CEAS 2005. https://www2.cs.uh.edu/~rmverma/good.pdf (also Semantic Scholar 16358a75).
- **[TalosSeasoning25]** Seasoning email threats with hidden text salting — Cisco Talos,
  2025-01-24. hxxps://blog.talosintelligence[.]com/seasoning-email-threats-with-hidden-text-salting/ **[vendor-blog]**
- **[TalosAbusingStyle25]** Abusing with style: Leveraging CSS for evasion and tracking — Cisco
  Talos, 2025-03-13. hxxps://blog.talosintelligence[.]com/css-abuse-for-evasion-and-tracking/ **[vendor-blog]**
- **[TalosTooSalty25]** Too salty to handle: Exposing cases of CSS abuse for hidden text salting
  — Cisco Talos, 2025-10-07. hxxps://blog.talosintelligence[.]com/too-salty-to-handle-exposing-cases-of-css-abuse-for-hidden-text-salting/ **[vendor-blog]**
- **[SublimeKeywords]** How to detect keywords or phrases in the body (body.html.inner_text vs
  raw) — Sublime Security docs. hxxps://docs.sublime[.]security/docs/how-to-detect-keywords-or-phrases-in-the-body **[vendor-docs]**
- **[SublimeRules]** sublime-security/sublime-rules — open detection rules repo. github[.]com/sublime-security/sublime-rules **[vendor]**
- **[SublimeCredPhish]** Email Credential Phishing (browser-emulation + computer vision) —
  Sublime Security. hxxps://sublime[.]security/attack-types/credential-phishing/ **[vendor-blog]**
- **[gbhackersOutlook]** Outlook Users Targeted by New HTML-Based Phishing Scheme (MSO
  conditional comments). gbhackers[.]com/outlook-html-based-phishing/ **[vendor-blog]**
- **[SO-mso-hide]** mso-hide:all usage note. gist.github[.]com/jamesmacwhite/18e97b06f2c04661a757 **[ref]**
- **[MS-BEC vendor]** Microsoft 2024 LLM-based BEC detection figure (via secondary reporting) **[vendor, unverified]**.
