# Cost-tiered / cascade detection — defenses and their KNOWN BYPASSES

For each cascade/routing approach: name · cite · mechanism · **known bypass / failure
mode (mandatory)**. Then the adversarial-economics argument for risk + anomaly + random
escalation over confidence-alone. Citations = arXiv/DOI/URL + year; unverifiable flagged;
URLs defanged.

---

## D1. Confidence-thresholded escalation (cheap→deep on low confidence)
**Mechanism.** Run cheap text classifier; escalate to OCR/vision/detonation only when its
confidence is low / uncertainty high (Chen et al. 2023 FrugalGPT, arXiv:2305.05176;
Kotte 2026 UCCI, arXiv:2605.18796).

**KNOWN BYPASS — adversarial low-uncertainty (this is the user's exact problem).**
The escalation gate is a function of a score the attacker can optimize *down*. An attacker
crafts a **confidently-benign** message so the cheap tier never fires:
- Neural nets emit **high-confidence predictions on crafted/unrecognizable inputs**
  (Nguyen, Yosinski, Clune 2015, CVPR, arXiv:1412.1897) — high confidence is not evidence
  of correctness.
- Softmax confidence is an uncalibrated, gameable correctness signal (Hendrycks & Gimpel
  2017, arXiv:1610.02136; Guo et al. 2017, arXiv:1706.04599), and **calibration collapses
  precisely under distribution shift / novel inputs** — i.e. on new attacks (Ovadia et al.
  2019, arXiv:1906.02530). So the messages you most need to escalate are the ones whose
  confidence you can least trust.
- Concretely for email: put the scam entirely in an **image** with bland benign body text
  ("Please review the attached invoice"). The text tier is not *uncertain* — it is
  *confidently correct that the text is benign*, because it is. Nothing escalates. Image
  spam is designed to defeat text filters (Hossary & Tomasin 2025 VBSF, arXiv:2512.23788).
- Even calibrated routers (UCCI) only make the *confidence estimate* better on the training
  distribution; calibration does not make the signal **adversarially robust**, and UCCI's
  gains are a single-source 2026 preprint (arXiv:2605.18796, flagged).
**Verdict:** confidence-alone escalation is *defeatable by construction*. Necessary but not
sufficient.

---

## D2. Cost-sensitive / cascade classifiers (reject-early, budgeted features)
**Mechanism.** Cheap stages reject easy negatives; expensive tests bought only when
worthwhile (Viola & Jones 2001, DOI:10.1109/CVPR.2001.990517; Xu et al. Cost-Sensitive
Tree of Classifiers 2013, arXiv:1210.2771; Contardo et al. 2016, arXiv:1607.03691;
Kachuee et al. 2019, arXiv:1901.00243).

**KNOWN BYPASS — game the cheap features that gate the cascade.**
Because early stages decide *cheaply* on a few features, an attacker who knows (or probes)
those features drives the sample into the "reject/benign, stop" branch. Gradient and
transfer evasion of the front-line classifier is standard (Biggio et al. 2013,
arXiv:1708.06131), and ensembles/stages do not fix it — ensemble malware detectors are
still evaded by mixture-of-attacks even after adversarial training (Li & Li 2020,
arXiv:2006.16545). A budgeted cascade that uses *uncertainty* as the feature-value signal
(Kachuee 2019) inherits D1's low-uncertainty bypass. Reject-early cascades are especially
dangerous in spam because the cheap "stop" branch **is** the benign verdict the attacker
wants.

---

## D3. Escalate on STRUCTURAL ANOMALY, not just confidence (always-OCR image-only mail, etc.)
**Mechanism.** Make escalation a function of message *structure/provenance* the attacker
cannot remove without weakening the lure: image-only / high image-to-text ratio, remote
images, has-QR, link-in-image, hidden HTML/CSS text, SPF/DKIM/DMARC fail, brand-vs-sender
mismatch, first-contact, cheap-Unicode-normalization anomaly flags (taxonomy §3B–D).
Precedent that a rendered/visual pipeline catches what text misses: VBSF renders the email,
runs OCR + a CNN on the rendered image, and beats text-only filters on obfuscated spam
(Hossary & Tomasin 2025, arXiv:2512.23788); KidsNanny routes Stage-1 vision → Stage-2
OCR+LLM and gets **100% recall on text-in-image threats** that vision-only misses
(Panchal et al. 2026, arXiv:2603.16181). Commercial email security already does exactly
this recursive unpack + OCR + QR-decode + computer-vision-render on *selected* mail
(Sublime Security, 2024, hxxps://sublime[.]security/platform/ and
hxxps://sublime[.]security/blog/qr-code-phishing-decoding-hidden-threats/).

**CORRECTION (this claim was overstated — see §D3-bypass below).** An earlier version of
this section asserted the attacker "cannot suppress [the structural gate] without giving up
the image/QR channel." That is **false for the *cheap static* predicates** (image ratio,
remote-image, has-QR-in-a-single-decodable-image): each is individually and jointly evadable,
and the evasions are deployed in the wild (§D3-bypass). The gate that actually survives is the
*render-then-analyze* tier, which is expensive — so the honest cost story is worse than the
numbers below suggest (§D3-cost-shift).

**COST ANALYSIS — how much traffic is that, really?** Escalation here is triggered by a
*structural predicate*, not a learned score. The cost is bounded by how much mail actually has
that structure:
- QR-in-phishing rose 0.8% (2021) → 12.4% (2023), ~10.8% (2024), ~12% of phishing (2025);
  image-encoded payloads ~12–12.4% of phishing incidents; "image-based attacks surged
  ~400%" into 2025 (APWG / vendor telemetry via Keepnet 2024–2025,
  hxxps://keepnetlabs[.]com/blog/qr-code-phishing-trends-...; Barracuda Threat Spotlight
  2024, hxxps://blog.barracuda[.]com/2024/10/22/threat-spotlight-evolving-qr-codes-phishing-attacks).
  **Flag:** these are *shares of phishing*, and vendor-sourced; the share of *all inbound
  mail* that is image-only/remote-image is not cleanly published (unverified — treat the
  cost estimate as order-of-magnitude).
- Deep tier is ~10x the cheap tier for OCR+small-LLM (KidsNanny 11.7 ms → 120 ms,
  arXiv:2603.16181), ~100–350x for a full vision-LLM (1,136–4,138 ms, ibid.).
- **Worked bound:** if image-only/remote-image/has-QR mail is a fraction f of traffic and
  you *always* deep-scan it, added compute ≈ f · (c_deep − c_cheap). At f ≈ 0.10 and a 10x
  OCR tier, mean per-message cost rises from 1.0 to ≈ 1.9 cheap-units (< 2x) — clearly
  affordable. At f ≈ 0.10 and a 300x vision-LLM tier, mean cost ≈ 31 cheap-units — *not*
  affordable to apply the full vision-LLM to all of f; use the cheap OCR/QR-decode tier as
  the escalation target and reserve the vision-LLM for a much smaller high-risk residual.
**§D3-bypass — KNOWN BYPASS of the *cheap static* predicates (deployed in the wild).**
An attacker constructs a message that drives *every* cheap content-structural predicate to
benign *simultaneously*, without weakening the lure:
- **Defeat image-to-text ratio** — include genuine benign body text ("Please review the
  attached invoice"). Message is no longer image-only; the ratio gate does not fire.
- **Defeat remote-image gate** — inline every image as base64/`cid:` so there is no remote
  fetch to flag. Measured empirically: base64 (31.2% of samples) *co-occurring with*
  text-in-image (47%) is significantly associated with **lower** antispam scores
  (Dalmiere, Zhou, Auriol, Nicomette, Marchand 2025, "Measuring Modern Phishing Tactics",
  arXiv:2506.20228; regression R²=0.486, p<0.001; authors conclude "multi-modal defences
  against combined obfuscation" are required). The layering *works*.
- **Defeat has-QR gate** — split the QR so no single image/part decodes:
  - **Split-QR**: two half-images, each benign in isolation, assembled by the *client
    renderer* into one scannable code (Gabagool phishing kit; SQ Magazine 2026,
    hxxps://sqmagazine[.]co[.]uk/split-qr-phishing-evades-email-filters/; Sublime Security,
    "Modern QR code phishing evasion tactics," 2025,
    hxxps://sublime[.]security/blog/modern-qr-code-phishing-evasion-tactics-you-should-know-about/).
  - **CSS/multipart tiling**: many tiny image fragments CSS-positioned to composite a QR
    only on screen (ibid.).
  - **Imageless HTML-table QR**: each QR module is a `<td>` with a black/white background —
    *no image at all* to OCR or decode (SANS ISC diary 32606, 2025,
    hxxps://isc.sans[.]edu/diary/32606; gbhackers 2025,
    hxxps://gbhackers[.]com/malicious-qr-codes/).
This is exactly the user's construction, and it is **correct**: a gate built from
`{image-only, remote-image, single-image-QR}` static predicates is defeatable by construction,
just like the confidence gate in D1.

**§D3-render — what actually survives: render-then-analyze, NOT static parsing.** The bypass
above defeats *static MIME/structure inspection*. It does **not** defeat *rasterize-the-message-
as-the-victim-sees-it, then OCR/QR-decode/CV the pixels*. The attack's own defining premise —
"a full QR appears **only when the HTML is rendered**" — is precisely what a render-then-decode
defender exploits: presenting a scannable QR to the victim and hiding it from the defender are
the **same rendering operation**, and email clients strip JS while inlined content rasterizes
identically everywhere, so the defender's renderer reproduces the victim's pixels. VBSF and
Sublime's CV-render pipeline (cited in the Mechanism above) catch split-QR, CSS-tiled QR, and
HTML-table QR alike. So the split-QR family relocates the detection from *cheap parse* to
*expensive render* — it does not escape detection, it escapes the **cheap** detector.

**§D3-cost-shift — the real damage the user's attack does: it moves the cost curve.**
render-then-analyze is the expensive tier (§D3 cost figures: ~10x for OCR, ~100–350x for a
vision-LLM). If every *cheap* static gate can be driven benign, the defender can no longer
cheaply single out the ~10% suspicious structural sliver — the attacker forces render-scanning
of a much larger fraction of image-bearing HTML mail (a large share of *legitimate* marketing
mail also inlines images and uses HTML layout, so the cheap gate can't separate them). This
**partially defeats the cost-tiering premise** and is the strongest form of the user's
objection. Three responses, in increasing durability:
1. **Cheap *layout*-anomaly trigger (intermediate tier, pre-raster).** Parse HTML/CSS geometry
   *without* rasterizing: N inline images or table-cells tiled into a contiguous grid region,
   multipart-assembly, imageless-module-grid — all anomalous for legitimate senders (who use
   one image or a CDN-hosted banner). Cheaper than full raster; use it to *escalate to render*,
   not as a verdict. Caveat: this is an arms race (jitter, decoy tiles, overlap, animation,
   non-grid arrangements → Athalye-style noise, arXiv:1802.00420); treat it as a trigger with
   finite lifetime, not a solution.
2. **Provenance/auth/reputation signals orthogonal to content structure (the durable core).**
   Inlining images and tiling QRs does nothing to SPF/DKIM/DMARC *alignment* failure,
   brand-vs-sender mismatch, first-contact / never-seen sending domain, or campaign-similarity
   to prior caught mail (EvoMail, arXiv:2509.21129). The attacker evades these only by
   controlling authenticated look-alike infrastructure (costly) or warming domains (costly and
   itself detectable) — not by editing message body structure. **This is what the attacker
   cannot drive to zero by construction; the content-structural predicates are not.**
3. **Keyed random deep-scan (D5).** Detonates an ε fraction regardless of how benign the
   structure looks, bounding campaign-level evasion.

**Bottom line for D3 (revised):** the *content-structural* predicate set is evadable exactly
as the user argues, and pretending otherwise is the D1 mistake in a new costume. D3's real,
defensible content is (a) render-then-analyze as the catch for anything that composits to a
payload on screen — which the split-QR family cannot escape by its own definition — at the
price of a larger render-tier traffic share, plus (b) provenance/reputation anchors that are
orthogonal to body structure and are the only genuinely non-suppressible triggers. Structural
*content* gates are escalation heuristics, not guarantees; the guarantee lives in provenance
(§D3-cost-shift #2) and probabilistic sampling (D5).

---

## D4. LLM model-routing / cascade (FrugalGPT-style)
**Mechanism.** Cheap model on the easy majority; escalate the residual to an expensive
model. Evidence it is cost-viable: FrugalGPT **matches GPT-4 accuracy at up to 98% cost
reduction**, or +4% accuracy at equal cost (Chen et al. 2023, arXiv:2305.05176);
calibrated routing cuts cost ~31% at fixed F1 (UCCI 2026, arXiv:2605.18796, flagged);
per-query cost/accuracy prediction enables budget control (SCOPE 2026, arXiv:2601.22323,
flagged).

**KNOWN BYPASS / FAILURE MODE.** The router that decides escalation is itself a model with
a gameable confidence/quality signal (inherits D1). In an *adversarial* email setting
(unlike the benign NLP benchmarks these papers use) the "easy majority" is defined by the
attacker: they mass-produce mail the cheap model confidently clears. LLM detectors are also
directly attackable — phishing-detection LLMs are evaded by prompt injection, text
refinement, and multilingual attacks (Hasan et al. 2025, arXiv:2512.10104). So
FrugalGPT-style savings are real for *cost on benign traffic* but do **not** by themselves
close the escalation gap on adversarial traffic; the routing signal needs the structural/
provenance anchors of D3.

---

## D5. Randomized / probabilistic deep-scanning (scan X% at random + all high-risk)
**Mechanism.** Deny the attacker a *guaranteed* cheap path: deep-scan (a) everything the
risk/anomaly gate flags (D3) **plus** (b) a random ε-fraction of everything else. Now even
a perfectly cheap-tier-benign message has probability ε of being detonated/OCR'd, so a
campaign of N messages is caught with probability 1−(1−ε)^N → attacker cannot be *certain*
of evasion at scale. Conceptual precedent: moving-target defenses that randomize the
deployed model to break repeated/correlated attacks (Morphence, Amich & Eshete 2021,
arXiv:2108.13952; DDoS shuffling MTD, Zhou et al. 2019, arXiv:1903.10102); analogous to
audit/inspection sampling in security screening.

**KNOWN BYPASS / FAILURE MODE.** Randomization defenses fall when the randomness is
*observable, low-entropy, or fingerprintable*:
- MTDs for ML malware detection are evaded via transfer + query strategies and their
  hyperparameters can be fingerprinted (Rashid & Such 2023, arXiv:2302.00537).
- Stochastic/obfuscated defenses give a **false sense of security** when the attacker
  applies Expectation-over-Transformation / averages over the randomness
  (Athalye, Carlini, Wagner 2018, arXiv:1802.00420 — obfuscated gradients).
Practical mitigations: keep ε *secret and unpredictable per-message* (keyed CSPRNG, not a
guessable schedule), tie the sampled deep-scan results back into training so caught
campaigns raise the risk score of their siblings, and set ε high enough that the *expected
number of delivered scams before detection* is below the campaign's break-even. Random
sampling is a **probabilistic backstop, not a primary detector** — it bounds the attacker's
success rate rather than guaranteeing per-message detection.

---

## D6. Adversarial economics — why "escalate only if cheap-tier-suspicious" loses
A static gate `escalate iff cheap_tier_suspicious(x)` hands the attacker a white-box
objective: minimize `cheap_tier_suspicious` while keeping the payload. Evasion research
shows this objective is reliably solvable — test-time evasion (Biggio 2013,
arXiv:1708.06131), high-confidence fooling (Nguyen 2015, arXiv:1412.1897), ensemble/robust
detectors still evaded (Li & Li 2020, arXiv:2006.16545), LLM detectors evaded
(Hasan 2025, arXiv:2512.10104). The robust alternative is an escalation policy the attacker
**cannot drive to zero**, combining three independent triggers so suppressing one still
leaves the others:
1. **Risk/structural + provenance gate (D3)** — two *different-durability* halves, do not
   conflate them (§D3-bypass/§D3-cost-shift):
   - *Content-structural* (image-only/remote-image/has-QR/hidden-text): **evadable** — inline
     base64 + benign text + split/CSS/HTML-table QR drives all of them benign (2506.20228).
     Keep them only as cheap *escalation-to-render* heuristics, never as verdicts; expect their
     coverage to erode and maintain the render tier (D3b) as the actual catch.
   - *Provenance* (SPF-DKIM-DMARC alignment fail + brand-vs-sender mismatch + first-contact +
     never-seen domain): **the deterministic, non-suppressible part** — orthogonal to body
     structure, evaded only via costly authenticated look-alike infra / domain warming. This is
     the piece the attacker "cannot lower." Cost bounded by real prevalence (~<2x mean compute
     for a 10x OCR tier at ~10% structural traffic, §D3), but note the render tier's share
     rises under the §D3-bypass attack.
2. **Anomaly / novelty gate** — first-contact, never-seen sender-domain, campaign-similarity
   to prior caught mail (EvoMail heterogeneous-graph fusion, Huang et al. 2025,
   arXiv:2509.21129). Catches "looks benign but is unprecedented."
3. **Keyed random sampling (D5)** — probabilistic backstop denying a guaranteed cheap path;
   bounds campaign-level evasion probability.
Confidence-based routing (D1/D4) is retained only as a *fourth, cost-saving* input on
already-benign-structured traffic — never as the sole gate.

---

## D7. One-line residual-risk table
| Defense | Cost win | Killed by |
|---|---|---|
| D1 confidence gate | high | adversarial low-uncertainty (1412.1897, 1906.02530) |
| D2 cost-sensitive cascade | high | gaming cheap gating features (1708.06131, 2006.16545) |
| D3a structural *content* gate (image ratio / remote-img / has-QR) | bounded (~<2x for OCR tier) | **evadable by construction** — inline base64 + benign text + split/CSS/HTML-table QR (2506.20228; Gabagool split-QR; ISC 32606). Forces render tier → cost curve shifts up (§D3-cost-shift) |
| D3b render-then-analyze | expensive (10–350x) but catches split-QR family by its own premise | attacker moves to un-gated *render* (client-specific CSS, remote-variant content) |
| D3c provenance/auth/reputation (SPF/DKIM/DMARC align, brand-vs-sender, first-contact) | cheap, orthogonal to body structure | **the durable core** — evaded only via costly authenticated look-alike infra / domain warming (itself detectable) |
| D4 LLM routing (FrugalGPT) | up to ~98% cost cut on benign | router signal gameable; LLM evasion (2512.10104) |
| D5 keyed random deep-scan | tunable ε | observable/low-entropy randomness (1802.00420, 2302.00537) |
| **D3+D2anomaly+D5 combined** | affordable | requires maintained structural coverage |
