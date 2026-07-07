# Defenses — Zero-Width & Invisible Characters (with known bypasses)

Rule of this file: **no defense is listed without its known bypass.** A defense whose
bypass is unaddressed is not SOTA — it is a filter tier that raises attacker cost.
Live URLs defanged. Citations map to the bibliography block returned to the orchestrator.

This is one of the **cheapest** defensive tiers (deterministic string ops, no ML), so it
belongs early in the gateway pipeline — but see the false-positive analysis at the end.

---

## D1. Strip / normalize invisible codepoints (blocklist or Cf/Cc category filter)

**Mechanism.** Remove or flag codepoints by Unicode general category — drop **Cf (Format)**
and **Cc (Control)** and explicit blocklist entries (ZWSP U+200B, ZWNJ U+200C, ZWJ U+200D,
WJ U+2060, SHY U+00AD, BOM U+FEFF, Tags U+E0000–E007F). For LLM pipelines vendors recommend
the explicit one-liner `''.join(c for c in s if not 0xE0000<=ord(c)<=0xE007F)` plus YARA
rules on Tag runs [cisco2024tag], and "remove Unicode Tags Block on the way in **and out**"
of the model [rehberger2024]. The canonical academic call for aggressive input sanitization
is Boucher et al., *Bad Characters* [boucher2021].

**KNOWN BYPASSES.**
1. **Incomplete blocklist / novel carriers.** A blocklist tuned to ZWSP/ZWNJ/Tags misses
   **variation selectors** (U+FE00–FE0F, U+E0100–E01EF), which are category **Mn, not Cf**,
   so both a "strip Cf" filter *and* a Tags-only filter pass them — yet they carry a full
   steganographic byte channel [butler2025]. Also missed by narrow lists: invisible math
   operators (U+2062–2064), Hangul/blank fillers (U+3164, U+FFA0), U+034F, U+180E.
2. **Over-broad stripping breaks legitimate text (false positives → the filter gets
   relaxed).** ZWJ is semantically required for **emoji ZWJ sequences** (👨‍👩‍👧 collapses to
   three separate glyphs) and for **Indic/Arabic/Persian** rendering (ZWNJ controls
   Persian plural forms and Indic conjuncts). Blindly deleting Cf corrupts real
   multilingual mail, so operators whitelist ZWJ/ZWNJ — reopening the salting channel
   [talos2024salting][boucher2021]. This is the core tension: *correctness vs. coverage.*
3. **Semantic equivalents outside the invisibles set.** Attackers pivot to *visible*
   confusables/homoglyphs, reorderings (bidi), or HTML/CSS hiding (`display:none`,
   zero-font ZeroFont) — none of which an invisible-char stripper touches [boucher2021][talos2024salting].
4. **Encoding-layer hiding.** In email the payload can sit in **RFC 2047 MIME
   encoded-words** or HTML entities (`&#8204;`, `&shy;`); a filter that runs *before*
   MIME/HTML decoding never sees the codepoint — decode-then-normalize ordering is required
   [sans2025shy][avanan2019zwasp].

**Verdict.** Necessary and cheap, but must (a) normalize *after* full MIME/HTML/entity
decode, (b) blocklist by *behavior* (all default-ignorable + all variation selectors +
Tags + fillers) not a short list, and (c) **flag-don't-silently-delete** so the density
signal survives to later tiers.

---

## D2. NFKC (compatibility) normalization

**Mechanism.** Unicode NFKC folds compatibility variants (full-width→ASCII, ligatures,
some invisibles) to a canonical form; widely assumed to "clean" obfuscation.

**KNOWN BYPASS — verified in this sandbox.** NFKC does **not** remove the zero-width /
invisible codepoints at all. Empirical test (`unicodedata.normalize('NFKC', 'A'+c+'B')`):
ZWSP U+200B, ZWNJ U+200C, ZWJ U+200D, WJ U+2060, SHY U+00AD, BOM U+FEFF, invisible-times
U+2062, variation selector U+FE0F, and Tag char U+E0041 are **all preserved unchanged**
(each stays a 3-codepoint string A·c·B). So NFKC gives a false sense of safety against this
attack class — it is a *homoglyph/full-width* defense, **not** an invisible-character
defense. (This is consistent with Unicode treating these as default-ignorable rather than
compatibility-decomposable.) Even where a normalization *does* delete a char (e.g. some
pipelines use NFKD + "remove default-ignorable"), bypasses D1.1/D1.3/D1.4 still apply.
[verified locally; corroborated by boucher2021's finding that deployed NLP stacks did not
sanitize these]

**Verdict.** NFKC is orthogonal to zero-width evasion. Do not rely on it here; pair it with
explicit invisible-char removal.

---

## D3. Entropy / statistical anomaly detection on invisible-char density

**Mechanism.** Flag messages where the ratio of invisible/format codepoints to visible
glyphs, or the *positional* pattern (invisibles wedged *inside* words rather than at word
boundaries), exceeds a threshold — legitimate text almost never puts a ZWSP between every
letter. Related: entropy of the codepoint distribution, or ML on hidden-char features. A
2026 study trains **XGBoost on zero-width-character features to detect obfuscated phishing
URLs** [xgboost2026]; Boucher et al. also note density as a tell [boucher2021].

**KNOWN BYPASSES.**
1. **Low-and-slow / single injection.** Boucher et al. show **one** imperceptible
   injection already degrades many NLP models and **three** can functionally break them —
   a density threshold set to avoid false positives sits far above 1–3 chars, so sparse
   attacks pass under it [boucher2021].
2. **Steganographic payloads mimic "legit" placement.** Variation-selector data rides
   *after a genuine emoji* (VS is literally designed to follow a base char), so its
   position looks legitimate and per-message counts can stay low while still exfiltrating
   bytes [butler2025].
3. **False positives from real heavy-ZWJ content.** Emoji-rich marketing mail, Indic/Arabic
   newsletters, and RTL content have naturally high Cf density → threshold must be loosened,
   widening the evasion band [talos2024salting].

**Verdict.** Good as a *risk-scoring* signal feeding an ensemble, weak as a standalone gate.

---

## D4. Tags / ASCII-smuggling detection & sanitization for LLM tiers

**Mechanism.** Before any text reaches an LLM triage/summarize/auto-reply component:
(a) strip the **Tags block U+E0000–E007F** and zero-width-binary carriers, (b) YARA/regex
alert on Tag runs (≥N chars) [cisco2024tag], (c) strip on **input and output** so the model
can't emit an exfil channel either [rehberger2024], (d) **tokenizer-level filtering** —
argued in [reversecaptcha2026] as the most robust point because the attack is a
tokenizer-reexpansion phenomenon, and (e) "spotlighting" / provenance-tagging so the model
distinguishes data from instructions [spotlighting2024]. Broad reviews now catalogue these
as standard indirect-prompt-injection mitigations [promptreview2026].

**KNOWN BYPASSES.**
1. **Wrong channel covered.** A Tags-only sanitizer misses **zero-width binary** (U+200B/
   U+200C) and **variation-selector** encodings; [reversecaptcha2026] shows OpenAI models
   *preferentially decode zero-width binary*, i.e. exactly the channel a Tags filter ignores.
2. **Tool access dominates risk regardless of filter tuning.** [reversecaptcha2026] finds
   tool availability raised compliance from ≤17% to 98–100%; so a leaky sanitizer against
   a tool-enabled agent is near-total compromise, not a graceful degradation.
3. **Model can reconstruct from partial/visible fragments.** Because the LLM re-expands
   sub-token pieces, defenses that only delete *contiguous* Tag runs can be evaded by
   interleaving visible chars or splitting the payload; and stripping input does nothing if
   the injection arrives via a rendered attachment/OCR path the sanitizer didn't cover.
4. **Sanitization ≠ instruction/data separation.** Even perfectly stripped text leaves the
   *semantic* indirect-prompt-injection problem; spotlighting reduces but does not eliminate
   it (no complete defense exists per the 2026 review) [spotlighting2024][promptreview2026].

**Verdict.** Mandatory for any LLM-in-the-loop gateway, but must cover **all three**
invisible channels (Tags + zero-width-binary + variation selectors), run at the tokenizer
boundary, and be paired with tool-use guardrails — stripping alone is insufficient.

---

## D5. Render-and-read (OCR / vision) as a cross-check (defense-in-depth)

**Mechanism.** Since the attack exploits the *human-visible vs. byte* gap, render the
message like a client would and OCR/vision-classify the pixels; invisible chars contribute
no pixels, so the visible brand/keyword re-emerges. Recommended by Talos and implemented as
**visual-based spam filtering** for obfuscated email [talos2024salting][vbsf2512].

**KNOWN BYPASSES.**
1. **Asymmetric — misses the LLM-smuggling threat entirely.** OCR sees what the human sees,
   which is *exactly* what the ASCII-smuggling attacker wants: the hidden instruction has no
   pixels, so a vision tier cannot detect Tags/zero-width payloads aimed at the model
   [rehberger2024][butler2025].
2. **Cost/latency and its own adversarial surface** (CSS/ZeroFont hiding, image-based text,
   adversarial perturbation of the rendered image) — a separate attack class.

**Verdict.** Strong complement for the *human-facing* keyword/brand-evasion half; blind to
the *machine-facing* smuggling half. The two halves need different tiers.

---

## Consolidated recommendation (ordering)
1. **Decode fully first** (MIME encoded-words, HTML entities, quoted-printable) — else D1–D4
   never see the codepoint [sans2025shy][avanan2019zwasp].
2. **D1 behavioral strip+flag** of *all* default-ignorables **+ all variation selectors +
   Tags + fillers**, whitelisting ZWJ/ZWNJ only where script/emoji context justifies it.
3. **D3 density score** into the ensemble (don't gate on it).
4. **D4 tokenizer-boundary sanitization + tool guardrails** for any LLM tier, covering all
   three channels; strip on input **and** output.
5. **D5 render/OCR** cross-check for brand/keyword evasion.
6. Do **not** rely on **D2 NFKC** for this class — verified ineffective.
