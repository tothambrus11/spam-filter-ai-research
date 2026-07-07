# Defenses — Homoglyph / Unicode Confusable Attacks (with known bypasses)

For each defense: **mechanism -> citation -> KNOWN BYPASS**. A defense whose bypass is unaddressed
is *not* SOTA. Email-gateway framing throughout. Live URLs DEFANGED. Compiled 2026-07-02.

---

## D1. Unicode normalization (NFKC/NFC) as a first-pass canonicalizer
**Mechanism.** Apply Unicode Normalization Form KC (compatibility decomposition + canonical
composition, UAX #15) to sender/subject/body/URL before any matching. This collapses fullwidth
forms (U+FF41 `ａ` -> `a`), ligatures, math-alphanumerics (U+1D400+ styled letters -> base
ASCII), and many compatibility variants to a canonical ASCII-ish form, defeating the "styled
spam subject" and fullwidth tricks. [UAX #15, unicode.org/reports/tr15]

**KNOWN BYPASS (unaddressed by NFKC alone).** NFKC only collapses *compatibility* equivalents.
The classic cross-script homoglyphs — Cyrillic `а` U+0430, Greek `ο` U+03BF, etc. — are treated
as **distinct canonical characters with no mapping to Latin**, so `NFKC("pаypal")` still contains
Cyrillic `а`. Cross-script homoglyph attacks pass straight through. confusables.txt and NFKC even
*disagree* on ~31 characters. [UTS #39; paultendo 2024 "confusables.txt and NFKC disagree on 31
characters"; multiple 2025 confirmations] => NFKC is necessary but **insufficient**; it must be
paired with UTS #39 confusable folding (D2).

---

## D2. UTS #39 confusables `skeleton()` mapping / confusable detection
**Mechanism.** Compute `skeleton(s)`: NFD-normalize, strip default-ignorable chars, replace each
char with its prototype from `confusables.txt`, re-NFD. Two strings with equal skeletons are
confusable. For a brand allow-list, precompute `skeleton(brand)` and flag any incoming
token/domain whose skeleton collides but whose raw code points differ (i.e. a lookalike, not the
real brand). Handles the cross-script cases NFKC misses (Cyrillic/Greek/Hebrew -> Latin).
[UTS #39, unicode.org/reports/tr39]

**KNOWN BYPASSES.**
- **Table incompleteness.** `confusables.txt` is curated and font-dependent; UTS #39 concedes
  "shapes vary greatly among fonts." Deng 2020 trained a vision model that found **8,000+
  homoglyph pairs not in the table** — any of these evades skeleton folding. [Deng 2020,
  arXiv:2010.04382; UTS #39]
- **Partial / sub-glyph confusables.** `rn`->`m`, `vv`->`w`, `cl`->`d` are multi-char visual
  merges the per-character skeleton map does not capture. [dnstwist permutation set]
- **Needs a reference brand list.** skeleton() only tells you *two strings collide*; to raise an
  alarm you must already know the brand you're protecting (a maintained allow-list). Novel/rare
  brands and free-text impersonation get no coverage.
- **Real-world demonstration:** Unicode confusables were shown to bypass exec-policy string
  matching in a deployed system (openai/codex issue #13095, 2025) precisely because normalization
  did not fold the confusables before comparison. [github.com/openai/codex issue 13095]

---

## D3. Script-mixing detection / single-script enforcement + IDN Punycode display policy
**Mechanism.** Flag strings whose UTS #39 **resolved script set is empty** (chars from
incompatible scripts, e.g. Latin + Cyrillic in one word). Apply UTS #39 **restriction levels**
(ASCII-Only, Single-Script, Highly/Moderately Restrictive). Browsers/registries adopt this: render
an IDN label as Unicode only if it passes the policy, else show raw `xn--` Punycode. Registries
also bundle-block confusable variants. [UTS #39; browser IDN policies post-2017]

**KNOWN BYPASS (this is exactly the apple.com break).** **Whole-script confusables** use a *single
foreign script for the entire label*, so the string is single-script and the mixed-script test
returns clean. `xn--80ak6aa92e[.]com` was 100% Cyrillic and rendered as `apple[.]com` in Chrome
≤58 / Firefox ≤53. [Zheng 2017; Mozilla bug 1463219] Mitigations (whole-script-confusable check
against a target script like Latin) help for major scripts but (a) depend on a "top domains /
Latin" reference set, (b) don't cover all-ASCII confusables like `rn`->`m` at all, and (c) some
mobile/third-party mail clients still auto-render IDNs. So single-script enforcement is a partial
patch, not a solution.

---

## D4. Visual / rendering-based similarity (render glyph -> CNN / embedding compare)
**Mechanism.** Render the string (or domain) to an image and compare against legitimate brands in
a learned visual space — sidestepping the incomplete confusables *table* by measuring pixels.
Representative work:
- **Woodbridge et al. 2018**, Siamese CNN on rendered strings; 13–45% ROC-AUC lift over
  Levenshtein-style baselines; feature vectors indexed with KD-trees for lookup.
  [arXiv:1805.09738]
- **Deng et al. 2020**, embedding/transfer learning with weak labels; avg precision 0.97 pairwise;
  clusters glyphs into equivalence classes; predicts thousands of *unlisted* homoglyphs.
  [arXiv:2010.04382]
- **GlyphNet (Gupta et al. 2023)**, attention-CNN on a 4M real/homoglyph *domain-image* dataset,
  works on **unpaired** data (attacker only sends the fake), 0.93 AUC. [arXiv:2306.10392]
- Broader reference-based *website* visual detectors (VisualPhishNet-style, on-device CV) extend
  the idea to full page/logo rendering. [Petrukha 2024, arXiv:2405.18236]

**KNOWN BYPASSES.**
- **Adversarial examples against the detector.** These are ML models and inherit ML fragility;
  cross-script homoglyph substitution "routinely fools classifiers while remaining readable to
  LLMs" (58.7% avg attack success, up to 92% per model in one 2025 study), and characters outside
  the training distribution / confusables table can be chosen to sit just under the visual-distance
  threshold. [Special-Character Adversarial Attacks, arXiv:2508.14070, 2025]
- **Font dependence.** Visual similarity is font-relative; a pair confusable in the gateway's
  render font may differ in the victim's client font (and vice-versa), producing both misses and
  false positives. [UTS #39 font-variability caveat]
- **Cost / coverage.** Rendering + CNN per token is expensive at gateway scale, and reference-based
  methods still need a brand/logo gallery — novel targets are uncovered.

---

## D5. Domain-level permutation & brand-squatting detection (dnstwist / ShamFinder)
**Mechanism.**
- **dnstwist** generates thousands of permutations of a protected domain (homoglyph, bitsquat,
  omission, transposition, `rn`->`m`, vowel-swap, TLD-swap...) and checks which are *registered*
  (DNS A/MX), plus page similarity via ssdeep fuzzy hash and pHash. Proactive: find lookalikes
  before they're used. [github.com/elceef/dnstwist]
- **ShamFinder (Suzuki 2019)** auto-builds a homoglyph DB and scans registered IDNs at scale to
  surface homographs in the wild. [arXiv:1909.07539]

**KNOWN BYPASSES.**
- **Generation ≠ recall of the wild.** Permutation engines only catch variants they *generate*;
  attacker glyph choices outside the seed set (esp. unlisted homoglyphs from D2/D4) are missed.
  [Deng 2020]
- **Enumeration blow-up.** With full Unicode confusables the permutation space is astronomically
  large; dnstwist prunes to stay tractable, so coverage is a tradeoff, not complete.
- **Reactive to registration.** These find *registered* lookalikes; a domain registered minutes
  before a campaign (or never resolving until send-time) evades pre-scan. [ShamFinder measurement caveats]
- **Requires a protected-brand seed** — same allow-list dependency as D2/D3.

---

## D6. LLM / embedding-based canonicalization & restoration
**Mechanism.** Instead of table lookup, use a model to *restore* perturbed text to its canonical
form, or judge intent despite obfuscation. LLMs "read code points, not glyphs" but can be trained
to normalize: BitAbuse (Lee 2025) is a 325k-sentence dataset of **real-world** visually-perturbed
phishing text with clean ground-truth; models trained on it reach ~96% restoration accuracy and
beat synthetic-only baselines. LLM-judge / multi-agent pipelines (PhishDebate 2025) can reason over
brand-impersonation context rather than exact strings. [Lee 2025, arXiv:2502.05225; Li 2025,
arXiv:2506.15656]

**KNOWN BYPASSES.**
- **The model itself is the target.** Bad Characters (Boucher 2021) shows a *single* imperceptible
  homoglyph/invisible/reorder injection significantly degrades, and three injections functionally
  break, deployed NLP systems from Microsoft/Google/Facebook/IBM/HuggingFace — the same encoding
  tricks that fool spam filters fool the LLM canonicalizer. [arXiv:2106.09898]
- **Distribution shift.** BitAbuse's own finding: a large gap between synthetic and real
  perturbations — a restorer trained on one perturbation style underperforms on novel styles.
  [Lee 2025]
- **Cost & latency.** Per-message LLM inference is far too expensive to run on 100% of gateway
  traffic; only viable as a top tier on already-suspicious mail.
- **Prompt-injection surface.** Homoglyph/invisible-char text fed to an LLM judge is itself an
  injection vector, so the canonicalizer needs sanitizing *before* the model — recursive problem.
  [Boucher 2021; paultendo 2025 "LLM reads codepoints not glyphs"]

---

## Cross-cutting bypass themes (carry to synthesis)
1. **Whole-script confusables** beat script-mixing (D3). [Zheng 2017]
2. **Incomplete/table-bound** methods (D2, D5) miss unlisted + partial homoglyphs. [Deng 2020]
3. **All-ASCII confusables** (`rn`->`m`, `1`->`l`) beat *every* Unicode-script defense. [dnstwist]
4. **ML detectors/canonicalizers are themselves attackable** (D4, D6). [Boucher 2021; arXiv:2508.14070]
5. **Everything table/reference-based needs a maintained brand allow-list** — zero coverage for
   unknown brands / free-text impersonation.

## Flagged / unverified
- 58.7% / 92% attack-success figures are from arXiv:2508.14070 (2025 preprint, not yet peer-reviewed
  at time of writing) — directional, treat as indicative.
- Vendor/registry IDN display policies evolve; exact current browser behavior not re-tested here.

## Sources used (full list in research/sources.md)
UAX #15 · UTS #39 · Woodbridge 2018 (arXiv:1805.09738) · Deng 2020 (arXiv:2010.04382) · GlyphNet
2023 (arXiv:2306.10392) · Suzuki/ShamFinder 2019 (arXiv:1909.07539) · dnstwist · Zheng 2017 ·
Mozilla bug 1463219 · Boucher 2021 (arXiv:2106.09898) · Lee/BitAbuse 2025 (arXiv:2502.05225) ·
Li/PhishDebate 2025 (arXiv:2506.15656) · Petrukha 2024 (arXiv:2405.18236) · arXiv:2508.14070 (2025)
· paultendo 2024/2025 · openai/codex issue 13095.
