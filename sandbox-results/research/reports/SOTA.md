# SOTA — Obfuscation-Resilient Spam/Phishing Detection for an Email Gateway

**A ranked, cited architecture recommendation + evaluation plan**
Compiled 2026-07-02. Target: inbound email gateway (full MIME, HTML bodies, attachments, URLs).
Optimization priority (per stakeholder): **evasion robustness against an adaptive attacker**,
subject to a real per-message compute budget.

Citation keys `[key]` resolve in [`../sources.md`](../sources.md). Per-attack detail lives in
[`../taxonomy/`](../taxonomy/) and [`../defenses/`](../defenses/). Live URLs are defanged.

---

## 0. The problem this report is built around

The stakeholder's operational failure: *a low-latency ML text classifier scores a
99%-legit-looking email as clean and therefore never fetches/OCRs the embedded image that
carries the actual scam.*

The core finding of this survey is that **this is not a model-tuning bug; it is the generic,
provable failure mode of a confidence-gated cascade.** The attacker's objective is simply
"make the cheap tier confidently benign," and the literature shows that objective is reliably
achievable:

- High confidence ≠ correctness — neural nets emit high-confidence outputs on meaningless
  inputs [nguyen].
- Softmax confidence is uncalibrated and gameable [msp][guo], and calibration *degrades
  precisely on the novel/shifted inputs you most need to escalate* [ovadia].
- An **image-only email defeats this without any adversarial ML at all**: the text tier is
  *genuinely correct* that the (bland or GenAI-written) visible text is benign, so it is not
  even uncertain — there is no low-confidence signal to route on [vbsf][image-text defenses].

**Therefore the central architectural commitment of this report is: escalate on message
*structure and provenance*, never on the text classifier's confidence.** Confidence is kept
only as a late, cost-saving input on traffic that is *already structurally benign*.

Everything else follows from two supporting findings:

1. **Canonicalize before you classify.** Most Unicode/HTML obfuscation is defeated cheaply and
   deterministically *if* normalization runs in the right order (after MIME/entity decode) and
   you keep the *obfuscation itself* as a feature. What you must not do is feed raw or
   naively-parsed text to any classifier.
2. **The text classifier is one weak voter.** Every text-only ML/LLM defense has a documented
   adaptive-attack bypass. Robustness comes from signals the attacker *cannot forge by
   rewriting the body*: SPF/DKIM/DMARC authentication, URL/domain reputation, sender history,
   and structural anomaly — plus click-time and post-delivery controls for the threats that no
   receive-time scan can close.

---

## 1. Recommended architecture (ranked, layered)

A five-stage pipeline. Stages 0–2 run on **100% of mail** and are cheap/deterministic.
Stage 3 (expensive analysis) runs only on a **structurally-selected minority**. Stage 4 is
**post-delivery**, because some attacks are unclosable at receive time.

```
            ┌─────────────────────────────────────────────────────────────────┐
 inbound →  │ S0  PARSE & DECODE   MIME, RFC2047 encoded-words, HTML entities,  │
            │                      base64 data: URIs, quoted-printable           │
            ├─────────────────────────────────────────────────────────────────┤
            │ S1  CANONICALIZE     NFKC → UTS#39 skeleton → strip/flag invisible │  cheap,
            │     (+ keep deltas)  chars → bidi neutralize → rendered-visible    │  100% of
            │                      text extraction. EMIT obfuscation features.    │  mail
            ├─────────────────────────────────────────────────────────────────┤
            │ S2  CHEAP MULTI-     auth (SPF/DKIM/DMARC), URL/domain reputation, │
            │     SIGNAL SCORE     sender history, text classifier (1 voter),    │
            │                      + STRUCTURAL/PROVENANCE ESCALATION GATE        │
            └───────────────┬───────────────────────────┬─────────────────────┘
                            │ benign & low-risk          │ escalate (structural/anomaly/random)
                            ▼                             ▼
                        deliver                   ┌───────────────────────────┐
                                                  │ S3  DEEP ANALYSIS (tiered)│  expensive,
                                                  │  3a OCR + QR-decode + pHash│  small % of
                                                  │  3b rendered screenshot    │  mail
                                                  │  3c vision-LLM / brand ref │
                                                  │  3d URL sandbox detonation │
                                                  └───────────────────────────┘
                            ┌─────────────────────────────────────────────────┐
                            │ S4  POST-DELIVERY   click-time URL re-scan,       │  continuous
                            │                     retro-hunt/clawback, FIDO2    │
                            └─────────────────────────────────────────────────┘
```

### Stage 0 — Parse & decode (mandatory precondition)

Ordering is load-bearing. Attackers hide `U+00AD`/`U+200C` inside `=?UTF-8?B?…?=` encoded
words or as `&shy;`/`&#8204;` entities; a normalizer that runs *before* full MIME/HTML/entity
decode never sees the codepoint [sans2025shy][avanan2019zwasp]. Decode MIME, RFC 2047
encoded-words, quoted-printable, HTML entities, and `data:` base64 URIs **first**, then
canonicalize.

### Stage 1 — Canonicalize, and keep the obfuscation as a feature (cheap, 100%)

Build the classifier's *view* of the message; never mutate the bytes delivered to the user.
Run, in order:

1. **NFKC normalization** — folds fullwidth forms and Mathematical-Alphanumeric styled letters
   (the "styled subject" spam trick) back to ASCII [uax15]. **Known limits (do not over-trust):**
   NFKC does **not** strip zero-width/invisible characters — *verified in-sandbox*: ZWSP, ZWNJ,
   ZWJ, WJ, SHY, BOM, VS16, and Tag chars survive NFKC unchanged [zero-width defenses][badchars];
   and it does **not** fold cross-script homoglyphs (Cyrillic а / Greek ο are canonical, not
   compatibility, equivalents) [uts39][paultendo].
2. **UTS #39 confusable `skeleton()`** against a maintained brand/domain allow-list — catches
   the cross-script and whole-script homoglyphs NFKC misses, and intra-Latin `rn`→`m`, `1`→`l`,
   `0`→`o` confusables that *no* Unicode/script check catches [uts39][dnstwist].
3. **Invisible-character handling** — blocklist by *behavior* (all default-ignorables + all
   variation selectors `U+FE00–FE0F`/`U+E0100–E01EF` + Tags `U+E0000–E007F` + zero-width/joiners
   + SHY/BOM), **flag rather than silently delete** so density survives as a signal. Context-aware
   whitelist ZWJ/ZWNJ only adjacent to emoji or inside identified Indic/Arabic runs to bound
   false positives [zero-width defenses][butler2025].
4. **Bidi neutralization** — detect/strip unbalanced RLO/LRO/PDI (Trojan Source), flag RLO in
   attachment/archive-member filenames [TrojanSource2021][MITRE_T1036_002].
5. **Rendered-visible-text extraction** — compute the CSS cascade (headless render) and classify
   what a human actually sees, defeating `display:none`/`opacity:0`/`font-size:0`/fg==bg hidden
   "ham salad" that poisons tag-stripping extractors like BeautifulSoup `get_text` [Betts24].

   **Keep the hidden-vs-visible delta as a strong malicious feature** (Betts24 reports Jaccard
   delta ~0.22 concealed vs ~0.07 clean over 8.4M emails) — you both neutralize the poison *and*
   penalize the fact that concealment happened [Betts24].

**Output of S1 is not just clean text — it is clean text PLUS a vector of obfuscation features**
(has-cross-script-confusable, invisible-char-density, unbalanced-bidi, RLO-in-filename,
hidden/visible-delta, anchor-text≠href) that feed S2.

### Stage 2 — Cheap multi-signal score + the escalation gate (cheap, 100%)

Score with an ensemble in which **the text/content classifier is one weak voter behind hard,
non-forgeable signals** — because every text-only defense is adaptively evadable (§2) and, if
the classifier is an LLM, the untrusted body is a live prompt-injection surface that can flip
the verdict [hackett-bypass-2025][Koide26][liu-universal-2024]. The signals the attacker cannot
beat by rewriting the body:

- **Authentication:** SPF / DKIM / DMARC pass/fail/alignment.
- **URL & domain reputation:** destination reputation, domain registration recency, CT-log
  presence (helps against just-registered lookalikes) [le18][dnstwist].
- **Sender behavioral history / first-contact anomaly** [evomail].
- **The S1 obfuscation feature vector.**

**The escalation gate — the heart of the design.** A message is routed to Stage 3 if **any** of
these independent triggers fires (union, not a single confidence threshold):

| Trigger family | Concrete conditions | Why the attacker can't zero it out |
|---|---|---|
| **Structural (fail-closed)** | image-only / high-image-to-text ratio / low-text body; remote `<img>` refs; image or PDF/Office attachment; has-QR (incl. fallback for ASCII/split QR); link-inside-image; brand-logo candidate; hidden/visible text delta > τ | removing the structure means removing the scam channel itself [vbsf][kidsnanny][fuzzyocr][barracuda2024] |
| **Provenance** | SPF/DKIM/DMARC fail or misalignment; brand mention ∧ external/unauthenticated sender; first-contact/never-seen domain | authentication and history are cryptographic/behavioral, not textual [evomail] |
| **Uncertainty (secondary)** | text classifier in the low-confidence middle band | cheap cost-saver on *already structurally-benign* traffic only — never the sole gate |
| **Keyed random (ε backstop)** | a secret, unpredictable ε-fraction of *everything else* | denies a guaranteed cheap path; bounds campaign-level evasion to ≈(1−ε)^N; ε must be keyed or it is fingerprinted and averaged out [morphence][mtdmalware] |

The structural gate must be **fail-closed**: "image-heavy / low-text / first-contact /
unresolved" escalates *by default*, rather than trusting a *positive* QR/keyword hit to fire —
because ASCII-block QR, split QR, and GenAI-written benign bodies are engineered specifically to
avoid tripping a positive trigger [barracuda2024][open-systems][image-text defenses]. This
directly closes the stakeholder's seam.

### Stage 3 — Deep analysis, itself tiered by cost (expensive, small %)

Do not run one monolithic expensive model. Order sub-tiers cheap→expensive and stop early:

- **3a. OCR + QR-decode + perceptual hash (pHash) / near-duplicate clustering.** The workhorse.
  Selective OCR is a ~20-year-deployed pattern: FuzzyOCR (2007) OCR'd only image-bearing,
  not-already-scored mail with image-hash memoization [fuzzyocr]; Dredze (2007) cut per-image
  work to **3–4 ms** via speed-aware feature selection + JIT extraction at 90–99% accuracy
  [dredze2007]. Decode QR here (a QR *detector* is far cheaper than OCR/vision), then feed the
  decoded URL into the same reputation→redirect→landing chain as text links [trad25][ms-qr-2024].
  pHash cheaply catches known campaigns [wang2007][mehta2008][phishsnap2025].
- **3b. Rendered screenshot** for CSS/client-divergence cases and for feeding 3c.
- **3c. Vision-LLM / reference-based brand detection** (VisualPhishNet / Phishpedia / KnowPhish
  lineage) — strongest *semantic* tier, most expensive; reserve for a small high-risk residual
  [visualphishnet2020][phishpedia2021][li2024knowphish].
- **3d. URL sandbox detonation / redirect-chain following** for suspicious links.

### Stage 4 — Post-delivery (continuous)

Receive-time scanning is **structurally insufficient** against cloaking, TOCTOU (benign at scan
time, weaponized after delivery), and AiTM reverse-proxy kits that serve the real brand's own
pixels [zhang21][talos24][uncloak2023]. The real backstops:

- **Click-time URL rewriting & re-scan** (Safe Links-style) — the closest thing to an answer for
  TOCTOU/time-gated cloaking, with adaptive/differential crawling (PhishParrot-style
  multi-vantage) to fight cloaking [nakano25][zhang21]. **Not sufficient alone:** it is still a
  scanner fetch (CAPTCHA/UA/IP cloaking and AiTM defeat it), and has hard coverage gaps at
  QR/image/attachment/already-wrapped/nested-rewriter links [levelblue25].
- **FIDO2 / WebAuthn passkeys** neutralize AiTM cookie theft — the one durable, non-content
  control against the credential-phishing endgame [talos24].
- **Retro-hunt & clawback:** re-score delivered mail as reputation/telemetry updates; pull
  messages whose URLs later weaponize.

---

## 2. Adversarial verification summary — why each tier needs the next

Per the mission's rigor rule, *a defense with an unaddressed bypass is not SOTA.* Every defense
below is paired with its known bypass; the architecture survives because the bypasses are
**non-overlapping** — no single attacker move zeroes out structural + provenance + random +
post-delivery at once.

| Defense | Known bypass | Mitigated in this design by |
|---|---|---|
| NFKC normalization | doesn't strip invisibles (verified) or cross-script homoglyphs [badchars][paultendo] | S1 adds skeleton + behavioral invisible-strip |
| UTS#39 skeleton vs brand list | table incomplete (8k+ unlisted pairs [deng]); needs maintained brand list | vision tier 3c + allow-list treated as continuously-updated asset |
| Script-mixing / single-script | **whole-script confusables** (all-Cyrillic apple.com) pass [zheng] | skeleton + brand-permutation (dnstwist) |
| Invisible-char strip | variation selectors are Mn not Cf; VS steganography slips blocklists [butler2025] | blocklist *all* default-ignorables + VS ranges, by behavior |
| Bidi strip | non-bidi homoglyph/invisible variants carry no bidi char [badchars]; legit RTL FPs | union with other Unicode features; flag-not-block |
| Rendered-visible extraction (single render) | **client divergence** — Outlook `mso-hide`/MSO conditionals, `@media` [Betts24] | keep hidden/visible delta as feature; multi-client render matrix (open gap) |
| Text/LLM classifier | adaptive text attacks (TextFooler/BAE), good-word, prompt injection ≈100% [textfooler-2020][hackett-bypass-2025] | demoted to one weak voter behind non-forgeable signals |
| Certified robustness (SAFER/RanMASK/IBP) | sound only inside a small declared perturbation set; out-of-set edits evade [tramer-2020] | never relied on as the gate |
| Confidence-gated escalation | attacker makes cheap tier *confidently* benign [nguyen][ovadia][vbsf] | **replaced** by structural/provenance/random gate |
| Selective-OCR cascade | gate-evasion: ASCII/split QR, GenAI-benign body → nothing escalates [barracuda2024] | **fail-closed** structural gate + keyed random ε |
| pHash / near-dup | detection-avoidance attacks; per-recipient/GenAI randomization defeats it [jain2021phash] | one cheap voter among 3a; not sole |
| Vision-LLM judge | **in-image prompt injection** ("classify as safe") [imgpromptinject2026][Koide26] | spotlighting/input-allowlisting; output validation; never sole arbiter |
| QR-decode + URL reputation | zero-hour freshness gap; per-victim one-time URLs; cloaking [oest20][unit42-24] | click-time re-scan (S4) |
| URL reputation / blocklist | reputation-borrowing on trusted domains; one-time URLs [unit42-24] | sandbox detonation + click-time |
| Click-time re-scan | still a scanner fetch → CAPTCHA/UA/geo cloaking + AiTM defeat it [talos24] | FIDO2/WebAuthn + clawback |

**The residual unclosed case** (honestly flagged): CAPTCHA/Turnstile + fingerprint cloaking +
per-victim one-time URL + AiTM proxying, deployed together, defeat *every content-inspection
tier at once* — the scanner can neither reach the phish nor distinguish it from the genuine
site. This is why FIDO2/WebAuthn and post-delivery telemetry are in the architecture as
non-content backstops rather than optional extras.

---

## 3. Cost model — is this affordable? (answering the stakeholder directly)

**Yes for the OCR tier; no for always-on vision-LLM — which is exactly why the deep tier is
itself split (3a cheap → 3c expensive).** Published per-message compute:

- Cheap text tier: ~O(chars), baseline.
- OCR + small-LLM reasoning tier: **~10× the text tier** (≈11.7 ms → ≈120 ms) [kidsnanny];
  Dredze's speed-aware image features run at **3–4 ms/image** [dredze2007].
- Full vision-LLM guard: **~100–350×** (≈1,136–4,138 ms) [kidsnanny].

If the structurally-suspicious fraction (image-only / remote-image / has-QR) is *f* of inbound
and you **always route it to the OCR tier**, mean compute ≈ `1 + f·(10−1)` cheap-units:

- at **f ≈ 0.10 → ≈ 1.9×** mean cost — under 2×, clearly affordable.
- the same *f* through a 300× vision-LLM → ≈ **31×** — not affordable, so 3c is reserved for a
  much smaller residual (structural-gate ∧ provenance-fail, or OCR-tier-suspicious, plus the
  keyed random ε).

**Rigor caveats (flagged):** (1) prevalence numbers — QR-in-phishing rose 0.8% (2021) → 12.4%
(2023) → ~12% (2025); image-encoded payloads ~12% of phishing incidents [keepnet][barracuda2024]
— are *shares of phishing*, vendor-sourced, and the share of *all inbound mail* that is
image-only/remote-image is **not cleanly published**, so treat f ≈ 0.10 as an order-of-magnitude
planning figure, not a measured constant. (2) KidsNanny's 10×/300× ratios and 100%-recall claim
are from a single 2026 preprint [kidsnanny] — the *ratio* is directionally corroborated by the
FuzzyOCR/Dredze deployment history, but the exact multipliers are unverified. (3) **No public
paper reports a validated email-image escalation operating point (precision/recall *jointly with*
per-message cost)** — this is the single biggest evidence gap and a priority for your own eval
(§5).

---

## 4. Datasets & benchmarks (to build/evaluate against)

| Purpose | Resource | Notes |
|---|---|---|
| Phishing/quishing attachments, multi-format | **CIC-Trap4Phish** [nejati26] | unified phishing/quishing attachment dataset (2026) |
| Image spam (classic) | Dredze image-spam corpus [dredze2007]; Princeton/SpamArchive image-spam sets | 2006–08 wave; still useful for OCR-evasion |
| Homoglyph domains | **GlyphNet** dataset [glyphnet]; dnstwist-generated permutations [dnstwist] | homoglyph domain detection |
| Visually-perturbed text | **BitAbuse** [bitabuse] | visually perturbed text restoration |
| Phishing webpages (visual) | VisualPhishNet / Phishpedia benchmarks [visualphishnet2020][phishpedia2021] | reference-based brand detection |
| Adversarial-text tooling | **TextAttack** [textattack-2020] | generate TextFooler/BAE/DeepWordBug attacks for red-teaming |
| URL classification | URLNet datasets [le18]; PhishTank / OpenPhish feeds | lexical + reputation; note freshness/label-lag |
| Quishing field data | Sharevski [sharevski22], Geisler [geisler24], Weinz [weinz25] | real-world QR-phish behavior/effectiveness |

**Gap:** there is **no standard public benchmark for the full obfuscation-resilient email
pipeline** (Unicode + HTML + image + QR + adversarial-ML, with an adaptive attacker and a cost
axis). Recommend assembling one from the above as a project deliverable.

---

## 5. Red-team evaluation protocol

The mission's decisive rule — *robustness measured against a fixed attack is an upper bound, not
a guarantee* [athalye-2018][tramer-2020][cw-2017]. Evaluate **adaptively**, not on a static
corpus.

1. **Adaptive over static.** For every claimed defense, implement the *strongest attack that
   knows the defense* (TextAttack for the classifier [textattack-2020]; homoglyph/invisible/bidi
   injectors for S1; ASCII/split-QR and GenAI-benign-body generators for the escalation gate;
   in-image prompt injection for 3c). Report attack success at each tier, not just end-to-end.
2. **Attack the *gate*, not just the classifier.** The stakeholder's bug lives in the gate.
   Specifically measure: what fraction of image-borne scams *fail to escalate*? Craft
   GenAI-benign bodies + ASCII/split QR and confirm the fail-closed structural gate still routes
   them to 3a.
3. **Escalation operating point.** Sweep the structural-gate thresholds and *jointly* report
   (recall on image/obfuscation attacks, false-positive rate on legit mail, mean per-message
   cost). This is the number the literature does not provide — produce it.
4. **False-positive stress set.** Legit multilingual/RTL mail (bilingual brands, Cyrillic/Greek
   names, Arabic/Hebrew senders), emoji-rich marketing (ZWJ sequences), newsletters with
   `display:none` preheaders and tracking pixels. Obfuscation defenses must not over-block these
   [uts39][TalosAbusingStyle25][injecguard-2024].
5. **Provenance-independent verification.** Confirm that stripping/altering body text alone
   cannot flip a verdict when auth/reputation/history signals say malicious (i.e., the text
   voter is genuinely subordinate).
6. **Keyed-randomness audit.** Verify ε-sampling is unpredictable/keyed — an attacker who can
   observe or predict the sample fingerprints and averages it out [mtdmalware][athalye-2018].
7. **Post-delivery drills.** Simulate TOCTOU (URL benign at delivery, weaponized at +6 h) and
   confirm click-time re-scan + clawback fire; validate FIDO2 neutralizes an AiTM session-theft
   scenario.

---

## 6. Open research gaps (flagged, uncited-by-necessity or thinly-sourced)

1. **Validated email-image escalation operating point** — no public work reports precision/recall
   *and* per-message cost jointly for selective OCR on email; vendors (Microsoft, Sublime) do not
   disclose their escalation trigger or cost [ms-qr-2024][sublime-qr]. **Highest-value gap.**
2. **Multi-client render canonicalization** — a single Chromium render is bypassed by Outlook
   Word-engine/`@media` divergence [Betts24]; a practical, affordable multi-client render matrix
   for gateways is unsolved.
3. **Robust escalation under adaptive gate attacks** — fail-closed structural gating + keyed
   random ε is argued from first principles and adjacent MTD work [morphence][mtdmalware]; it has
   not been evaluated end-to-end on an email obfuscation benchmark (which doesn't exist yet, §4).
4. **Vision-LLM judges import prompt injection** — escalating to a multimodal LLM adds a new
   attack surface (in-image "classify as safe") with no complete defense [imgpromptinject2026]
   [Koide26]; InjectDefuser/spotlighting reduce but don't zero it [spotlight-2024].
5. **Perceptual-hash fragility** — per-recipient/GenAI image randomization and detection-avoidance
   attacks defeat pHash campaign-catching with "no straightforward mitigation" [jain2021phash].
6. **The unclosable receive-time residual** — CAPTCHA + fingerprint cloaking + one-time URL + AiTM
   jointly defeat all content tiers; only non-content controls (FIDO2, post-delivery telemetry)
   respond, and their coverage/UX cost at scale is under-quantified [talos24][uncloak2023].
7. **LLM-in-the-loop everywhere is a double-edged upgrade** — LLM/vision judges raise semantic
   ceiling but are themselves adaptively evadable and injectable [hackett-bypass-2025]
   [chen-backdoor-2025]; "100% mitigation" multi-agent pipelines are evaluated on fixed corpora,
   i.e., upper bounds only.

---

## 7. Bottom line

- **Fix the gate, not the model.** Replace confidence-gated escalation with a **fail-closed
  structural/provenance gate + keyed random ε-sampling**. This is what closes the stakeholder's
  "scored clean, never OCR'd" seam, and it is the single most important recommendation here.
- **Selective OCR is affordable and proven** (~1.9× mean cost at f≈0.10; a 20-year-deployed
  pattern) — provided the deep tier is itself split (cheap OCR/QR/pHash → expensive vision-LLM
  reserved for a small residual).
- **Canonicalize before you classify, in the right order, and keep the obfuscation as a feature**
  — cheap deterministic Unicode/HTML normalization defeats most of the non-image classes on 100%
  of mail, and the *presence* of obfuscation is itself a strong malicious signal.
- **Demote the text classifier to one weak voter** behind non-forgeable auth/reputation/history
  signals; never let an LLM judge over the raw body be the sole arbiter (it is an injection
  surface).
- **Some attacks are unclosable at receive time.** Click-time re-scan, FIDO2/WebAuthn, and
  post-delivery clawback are architecture, not afterthoughts.
- **Evaluate adaptively.** A number from a static corpus is an upper bound. Attack your own gate.
