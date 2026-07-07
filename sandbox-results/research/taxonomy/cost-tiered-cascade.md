# Cost-tiered / cascade detection — taxonomy

Cross-cutting topic for the email-gateway survey: **deciding WHEN to spend expensive
compute** (OCR, vision-LLM render-and-screenshot, sandbox URL detonation) instead of
running it on every message. Central user pain: a low-latency text classifier scores a
99%-legit-looking email as clean and never escalates to analyze the embedded scam image.

All claims carry a citation (arXiv id / DOI / URL) + year. Unverifiable items are flagged.
Live URLs are defanged.

---

## 1. Framing the problem

### 1.1 The two competing budgets
An email gateway optimizes **detection quality** (precision/recall, or more precisely the
cost-weighted error where a missed BEC/credential-phish costs far more than a false
positive) against a **compute/latency budget** (per-message CPU, GPU-seconds for
vision-LLMs, wall-clock added to delivery, sandbox-detonation seconds). Deep analysis is
1–3 orders of magnitude more expensive than a text classifier:
- KidsNanny's two-stage multimodal moderator: Stage-1 ViT screen = **11.7 ms**; full
  Stage-1+2 pipeline with OCR + 7B LLM reasoning = **120 ms** (~10x). Compared vision-LLM
  guards run **1,136 ms (ShieldGemma-2)** to **4,138 ms (LlavaGuard)** — 100–350x the cheap
  tier (Panchal et al. 2026, arXiv:2603.16181).
- LLM API price spread across models is **up to two orders of magnitude** (Chen, Zaharia,
  Zou 2023, FrugalGPT, arXiv:2305.05176).
This is exactly why you cannot render-and-screenshot or vision-LLM every message; you must
*route*.

### 1.2 Per-message cost model (the object every cascade optimizes)
For a message routed through tiers t=1..T, expected cost per message is
`E[cost] = Σ_t P(reach t) · c_t`, and expected quality is set by which tier ultimately
decides. Cheap tier c_1 runs on 100% of traffic; each later tier runs only on the
escalated fraction `e_t`. So `E[cost] ≈ c_1 + e_2·c_2 + ... `. The design lever is the
**escalation fraction e_t** and *which messages* land in it. Cost-sensitive learning
formalizes that not all errors (and not all features/tests) cost the same
(Turney 2002, arXiv:cs/0212034; Elkan 2001, "The Foundations of Cost-Sensitive Learning,"
IJCAI, no DOI — foundational, cited from knowledge).

### 1.3 The "escalation gap" attackers exploit
A cascade that escalates **only when the cheap tier is suspicious** creates an adversarial
optimization target: make the cheap tier *confidently benign* and you are never charged
the deep tier. This is the user's exact failure — the scam lives in an image the text tier
never reads, and the text (a bland "Please see attached / view the document") is genuinely
benign-looking to the text model, so nothing triggers escalation. The gap exists because
the escalation gate is a **static function of features the attacker controls**. This is the
same structural weakness as adversarial evasion of any single classifier
(Biggio et al. 2013, arXiv:1708.06131) and is why escalation policy — not just cheap-tier
accuracy — is the security-critical design choice. Evidence that confident-but-wrong
predictions are cheap to induce: DNNs give **high-confidence predictions on
unrecognizable / crafted inputs** (Nguyen, Yosinski, Clune 2015, CVPR;
arXiv:1412.1897), and softmax confidence is a weak, uncalibrated signal of correctness
(Hendrycks & Gimpel 2017, arXiv:1610.02136; Guo et al. 2017 "On Calibration of Modern
Neural Networks," arXiv:1706.04599).

---

## 2. Taxonomy of cascade / routing designs

### 2.1 Cascade classifiers (Viola–Jones lineage) — reject-early
A sequence of increasingly expensive classifiers; each stage either **rejects** (declares
negative/benign, stops) or passes the sample on. Tuned so early cheap stages reject the
vast majority of easy negatives, and only hard candidates reach expensive stages.
- Viola & Jones 2001, "Rapid Object Detection using a Boosted Cascade of Simple Features,"
  CVPR, DOI:10.1109/CVPR.2001.990517 — the canonical attentional cascade.
- Modern deep analogues: Cascade R-CNN (Cai & Vasconcelos 2019, arXiv:1906.09756);
  chained cascade networks (Ouyang et al. 2017, arXiv:1702.07054).
- **Note for email:** classic cascades reject-early on *negatives*. In spam that means
  "declare benign and stop" — precisely the branch an attacker wants to reach cheaply.
  The security-relevant inversion is to make the cheap tier **escalate-on-doubt**, not
  reject-on-doubt.

### 2.2 Early-exit / anytime / adaptive-depth inference
One model with intermediate classifier heads; an input "exits" at the first head confident
enough, so easy inputs use less compute.
- Surveys: Laskaridis, Kouris, Lane 2021 (arXiv:2106.05022); Bajpai & Hanawal 2025, early-
  exit in NLP (arXiv:2501.07670); NACHOS NAS for early-exit under MAC constraints
  (Gambella et al. 2024, arXiv:2401.13330).
- Escalation signal is **prediction confidence at the head**; note the same calibration
  caveat (§1.3) applies to when the model is allowed to exit early.

### 2.3 Confidence-thresholded routing (cheap→expensive)
Run the cheap model; if its confidence/uncertainty crosses a threshold, escalate to the
expensive model/tier. The dominant deployed pattern.
- FrugalGPT LLM cascade: query models in sequence, stop when a learned scorer judges the
  answer reliable (Chen et al. 2023, arXiv:2305.05176).
- UCCI: **calibration-first** router mapping token-margin uncertainty to a per-query error
  probability via isotonic regression, choosing the escalation threshold by constrained
  cost minimization; reports 31% cost cut at fixed F1 and beats entropy/FrugalGPT-style
  thresholds (Kotte 2026, arXiv:2605.18796 — single-source 2026 preprint, numbers
  unverified externally, flagged).
- SCOPE: predicts each model's cost *and* accuracy per query, turning routing into a
  dynamic budget-controlled decision (Cao et al. 2026, arXiv:2601.22323 — single-source
  2026 preprint, flagged).

### 2.4 Cost-sensitive learning / budgeted feature acquisition
Learn *which tests/features to buy* for each input under a budget, treating expensive
signals (OCR, detonation) as costly features acquired only when their expected value of
information justifies the spend.
- Cost-Sensitive Tree of Classifiers (Xu et al. 2013, arXiv:1210.2771); Greedy Miser
  (Xu, Weinberger, Chapelle 2012, ICML — cited from knowledge).
- Budgeted / sequential cost-sensitive feature acquisition as RL: Contardo et al. 2016
  (arXiv:1607.03691); Opportunistic Learning using MC-dropout uncertainty as the
  feature-value signal (Kachuee et al. 2019, arXiv:1901.00243).
- Cost-sensitive feature selection with asymmetric FP/FN costs (Benítez-Peña et al. 2024,
  arXiv:2401.07627); taxonomy of costs (Turney 2002, arXiv:cs/0212034).

### 2.5 Model cascades / LLM routing ("big-little", speculative)
Cheap small model handles the easy majority; a large model is invoked only for the
residual hard set. Speculative decoding and "big-little" routing are the systems-level
cousins. FrugalGPT (2305.05176), UCCI (2605.18796), SCOPE (2601.22323) as above.

### 2.6 Randomized / probabilistic deep-scanning
Escalate a **random sample** of otherwise-benign traffic (plus all high-risk), so no
message has a *guaranteed* cheap path — an adversarial-economics move, not an accuracy
move. Analogues in security: moving-target defense that randomizes the deployed model
(Morphence, Amich & Eshete 2021, arXiv:2108.13952) and randomized/shuffling MTD for DDoS
(Zhou et al. 2019, arXiv:1903.10102). Caveat: these are defeatable if the randomization is
observable/low-entropy (§ defenses file; Rashid & Such 2023, arXiv:2302.00537).

---

## 3. Taxonomy of ESCALATION SIGNALS relevant to email obfuscation

Signals a cheap tier can compute in ~ms to *decide to spend the deep tier*. Grouped by
how hard they are for an attacker to suppress.

**A. Confidence / uncertainty (attacker-controllable — weak on its own)**
- Low text-classifier confidence / high entropy (§2.3). Bypassable: attacker crafts
  confidently-benign text (§1.3; Nguyen 2015 arXiv:1412.1897; Ovadia et al. 2019
  "Can You Trust Your Model's Uncertainty?", arXiv:1906.02530 — calibration collapses
  under distribution shift, i.e. exactly on novel attacks).

**B. Structural / modality anomalies (harder to suppress without losing the lure)**
- **High image-to-text ratio / image-only body**: the scam-in-an-image case. If the
  visible content is an image and the text is negligible, the text tier is *blind by
  construction* — escalate to OCR/vision regardless of text score. Image-based spam that
  defeats text filters is well documented (Hossary & Tomasin 2025, VBSF, arXiv:2512.23788).
- **Remote / externally-hosted images** (tracking pixels, image served from attacker host).
- **has-QR** in image or attachment (quishing) — text/link scanners see no URL
  (Sublime Security, "QR Code Phishing: Decoding Hidden Threats," 2024,
  hxxps://sublime[.]security/blog/qr-code-phishing-decoding-hidden-threats/).
- **link-in-image** / clickable image over hidden URL; HTML/CSS hidden-text ("salting").
- **Attachment that renders** (PDF/HTML) — candidate for render-and-screenshot / detonation.

**C. Identity / provenance anomalies (hard for a spoofer; cheap to compute)**
- SPF/DKIM/DMARC authentication failures or alignment failures.
- **Brand mention + external-sender / lookalike-domain mismatch** (e.g. body says
  "Microsoft" but sender is an unaligned external domain).
- Sender reputation / first-contact (never-seen sender or domain), display-name spoofing.
- First-contact + payload combination as an anomaly trigger (EvoMail fuses text, headers,
  domains, URLs, attachments into a heterogeneous graph; Huang et al. 2025,
  arXiv:2509.21129).

**D. Cheap-normalization anomaly flags (obfuscation tells)**
- Unicode confusables / mixed-script / zero-width or invisible characters detected by a
  cheap normalization pass — presence of these is itself an escalation trigger even if the
  post-normalization text scores benign.

Design implication (carried into the defenses file): **B, C, D are structural and
provenance signals the attacker cannot fully remove without weakening the lure**, whereas
**A is attacker-controllable**. A robust escalation policy is therefore risk-based
(B+C+D) OR anomaly-based OR random-sampled — *not confidence-alone*.

---

## 4. Years / recency note
This subfield moves fast. Cost-sensitive learning and Viola–Jones are 2001–2013 classics;
early-exit surveys 2021–2025; LLM-cascade/routing is 2023–2026 and the strongest 2026
routing claims (UCCI, SCOPE) are **single-source preprints flagged as unverified**.
Image/QR-phishing prevalence figures are 2024–2025 vendor telemetry (see defenses file).
