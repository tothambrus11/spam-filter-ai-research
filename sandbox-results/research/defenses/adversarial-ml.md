# Defenses — Adversarial-ML Evasion (each with its KNOWN BYPASS)

Rule of this file: a defense whose bypass is unaddressed is **not SOTA**. For every entry:
mechanism, then the adaptive/known bypass. The governing principle:

> **Adaptive-attacker rule.** Robustness measured only against a *fixed* attack is nearly
> worthless. Defenses that "detect" or "mask" adversarial inputs repeatedly fall to an
> attacker who optimizes against them. Canonical results (from vision, but the logic is
> modality-independent): Carlini & Wagner, *Adversarial Examples Are Not Easily Detected:
> Bypassing Ten Detection Methods*, AISec 2017 (arXiv:1705.07263) [cw-2017]; Athalye, Carlini
> & Wagner, *Obfuscated Gradients Give a False Sense of Security*, ICML 2018 (arXiv:1802.00420)
> — 7 of 9 ICLR'18 defenses broken by adaptive attacks [athalye-2018]; Tramèr et al.,
> *On Adaptive Attacks to Adversarial Example Defenses*, NeurIPS 2020 (arXiv:2002.08347) —
> 13 defenses broken [tramer-2020]. In NLP, Morris et al. (Reevaluating…, 2020) show the same
> evaluation sloppiness. **Treat any single-attack robustness number as an upper bound on
> safety, not a guarantee.**

---

## 1. Adversarial training / data augmentation with perturbed samples
- **Mechanism.** Generate perturbed spam (synonym swaps, typos, LLM rephrases) and train on
  them with correct labels. Domain instances: ACAT — elShehaby et al., *Adaptive Continuous
  Adversarial Training*, arXiv:2403.10461 (2024), raises an under-attack spam filter from 69%→88%
  over 3 retrain rounds [acat-2024]; FGPM adversarial training (Wang et al., AAAI 2021)
  [fgpm-2021]; Afane et al. (2411.13874) propose LLM-generated phishing variants as augmentation
  [afane-2024]. TextAttack packages augmentation [textattack-2020].
- **KNOWN BYPASS.** (i) *Generalization gap:* robustness concentrates on the perturbation
  *type* seen in training; a new transform (char-level when trained on synonyms, or a fresh
  LLM rephrase) evades. (ii) *Arms race / non-stationarity:* online good-word attackers simply
  move to new "good words" each round (Lowd & Meek; Nelson 2008) [lowd-goodword-2005],
  [nelson-2008]. (iii) In federated/transfer settings adversarial training gives only limited
  gains vs internal-evasion and transfer attacks — Kim et al., arXiv:2209.08412 [kim-federated-2022].
  (iv) It provides **no certificate** — an adaptive optimizer (GBDA, TextFooler with a wider
  synonym set) usually finds surviving perturbations.

## 2. Certified robustness for text (randomized smoothing / IBP)
- **Mechanisms.**
  - *IBP over a synonym set* — Jia et al., *Certified Robustness to Adversarial Word
    Substitutions*, EMNLP 2019 (interval bound propagation over a fixed synonym polytope); and
    Huang et al. 2019. [jia-ibp-2019]
  - *Randomized smoothing over substitutions* — **SAFER**, Ye, Gong & Liu, ACL 2020
    (arXiv:2005.14424): structure-free, black-box, builds a stochastic ensemble of random
    synonym substitutions and certifies via statistics; works on BERT. [safer-2020]
  - *Randomized masking* — **RanMASK**, Zeng et al., ACL 2023 (arXiv:2105.03743): mask a fixed
    fraction of tokens; certifies against a Hamming-distance ball, covers both word- and
    character-level. [ranmask-2021]
  - *Word substitution with differential privacy* (WordDP), NAACL 2021 [worddp-2021].
  - *Broader edit operations* — **Text-CRS**, Zhang et al., IEEE S&P 2024 (arXiv:2307.16630):
    permutation+embedding smoothing certifies substitution/reorder/insert/delete [textcrs-2023];
    **CERT-ED**, Huang et al., arXiv:2408.00728 (2024): randomized deletion certifies full edit
    distance, beats RanMASK on 4/5 datasets [certed-2024].
  - *LLM-scale* — Self-Denoise, Zhang et al., arXiv:2307.07171 (2023) [selfdenoise-2023];
    CR-UTP, Lou et al., arXiv:2406.01873 (2024) for universal perturbations [crutp-2024].
- **KNOWN BYPASS / scope limits.** (i) **The certificate only holds inside its declared
  threat set.** IBP/SAFER certify a *specific* synonym table or an ℓ0/Hamming ball; an attacker
  using synonyms outside that table, character/homoglyph edits (outside a word-substitution
  cert), or insertion/reordering (outside a substitution-only cert) is simply *out of scope* —
  no violation of the theorem, full evasion in practice. This is the text analog of Athalye's
  point: the guarantee is real but narrow. (ii) **Certified accuracy/radius is small** — often
  certifying only ~2–5 word changes on short text at a large clean-accuracy cost; long emails
  with many perturbable tokens fall outside any practical radius. (iii) **Assumption leakage:**
  early certs assumed the defender knows the attacker's synonym-generation rule (unrealistic) —
  RanMASK's own motivation; masking-based certs then trade radius for that generality.
  (iv) Smoothing inference cost (many forward passes) is often infeasible at gateway throughput.

## 3. Spelling/typo correction & input canonicalization front-ends
- **Mechanisms.** Put a corrector *before* the classifier so char-level perturbations are
  undone. **ScRNN word recognizer** — Pruthi, Dhingra & Lipton, *Combating Adversarial
  Misspellings with Robust Word Recognition*, ACL 2019 (arXiv:1905.11268) [pruthi-2019].
  **DISP** — Zhou et al., arXiv:1909.03084 (EMNLP 2019): a perturbation discriminator flags
  likely-perturbed tokens and a contextual embedding estimator restores them [disp-2019].
  Adversarial *purification* via mask-and-reconstruct MLM — Li, Song & Qiu, arXiv:2203.14207
  (2022) [purify-2022]. Plus Unicode NFKC + confusable-skeleton normalization (the overlap with
  the homoglyph defense class).
- **KNOWN BYPASS.** (i) *Correct-to-wrong:* Pruthi et al. themselves show the recognizer can be
  driven to "correct" a benign word into a different one, and that attacks *targeting the
  corrector* survive. (ii) *Adaptive attacker treats corrector+classifier as one model* and
  optimizes end-to-end (the Athalye lesson): perturbations chosen so correction is a no-op or
  maps to an adversarial token. (iii) *Ambiguous restoration:* homoglyph/zero-width strings and
  heavy BPE fragmentation have no unique "correct" form; canonicalization can over-normalize
  (false positives on legitimate mail) or under-normalize. (iv) Correctors handle char-level
  noise but do **nothing** against fluent word-level (TextFooler/BAE) or LLM-rephrase evasion.

## 4. Ensembles / randomization to raise attacker query cost
- **Mechanisms.** Randomize the model at inference (feature bagging, random subspaces, stochastic
  masking) or ensemble diverse learners so per-query gradients/scores are noisy and non-stationary
  — Yang & Chen, *Using Randomness to Improve Robustness … Against Evasion Attacks*,
  arXiv:1808.03601 (2018), evaluated on spam & intrusion [yang-random-2018]. Multi-signal
  ensembles (URL reputation + auth (SPF/DKIM/DMARC) + content model + LLM judge) force the
  attacker to satisfy *all* signals simultaneously.
- **KNOWN BYPASS.** (i) *EoT (Expectation over Transformation):* an adaptive attacker averages
  the randomness out over queries — the exact technique that broke randomized vision defenses
  (Athalye 2018) [athalye-2018]. (ii) *Transfer attacks* need **zero** queries, so raising query
  cost is moot when a surrogate transfers (guardrail bypass, Hackett 2025 [hackett-bypass-2025];
  Kim 2022 [kim-federated-2022]). (iii) Randomization trades clean accuracy / adds latency.
  *However* — genuine signal diversity (not just model-level noise) is the one lever that
  survives: an attacker can mangle text to beat the content model but still cannot forge DMARC
  or clean a known-bad URL. Ensembling only helps to the extent signals are **independent** and
  not all text-derived (see synthesis).

## 5. Robust word embeddings & anomaly / OOD detection on inputs
- **Mechanisms.** Counter-fitted / synonym-collapsing embeddings so substitutions move less in
  feature space (underpins Jia 2019, TextFooler's own constraint). Detectors that flag inputs as
  perturbed/OOD: DISP's discriminator [disp-2019]; frequency/perplexity anomaly on OOV bursts;
  **embedding-drift** detection for injected content — ZEDD, Sekar et al., arXiv:2601.12359
  (2026), >93% detection, <3% FPR on LLMail-Inject [zedd-2026]; UniGuardian unified
  attack-detector, arXiv:2502.13141 (2025) [uniguardian-2025].
- **KNOWN BYPASS.** (i) **Detection is the most-broken defense category** — Carlini & Wagner 2017
  broke ten detectors with adaptive attacks [cw-2017]; the same applies to a text perturbation
  discriminator once the attacker adds the detector to its loss. (ii) Fluent attacks (BAE,
  LLM-rephrase) are *in-distribution* — no perplexity/OOD spike to catch [afane-2024], [bae-2020].
  (iii) OOD/embedding-drift thresholds trade FPR against evasion; low FPR (needed at gateway
  volume) leaves headroom for an attacker who stays just under threshold.

## 6. Defenses specific to LLM classifiers / guardrails (prompt injection & jailbreak)
- **Mechanisms.**
  - *Instruction/data separation & instruction hierarchy* — **StruQ**, Chen et al., arXiv:2402.06363
    (2024): two-channel structured queries + fine-tune to ignore instructions in the data channel
    [struq-2024]. **SecAlign**, Chen et al., arXiv:2410.05451 (2024): preference-optimize secure
    vs insecure responses; injection success <10% even vs unseen attacks [secalign-2024].
  - *Spotlighting* (delimiting/datamarking/encoding untrusted text so the model treats it as data)
    — Hines et al., arXiv:2403.14720 (2024) [spotlight-2024]; **Mixture of Encodings** (Base64+),
    Zhang et al., arXiv:2504.07467 (2025) [mixenc-2025].
  - *Input sanitization / erase-and-check with a certificate* — Kumar et al., *Certifying LLM
    Safety against Adversarial Prompting*, arXiv:2309.02705 (2023) [kumar-erase-2023].
  - *Guardrail classifiers* — Meta Prompt Guard, Azure Prompt Shield; InjecGuard (Li & Liu,
    arXiv:2410.22770, 2024) addresses over-defense with the NotInject benchmark [injecguard-2024].
  - *Multi-agent adjudication* — CourtGuard, arXiv:2510.19844 (2025) [courtguard-2025]; a
    chain/coordinator pipeline claiming 100% mitigation, arXiv:2509.14285 (2025)
    [multiagent-2025]; runtime PCFI gateway, arXiv:2603.18433 (2026) [pcfi-2026].
- **KNOWN BYPASS.** (i) **Guardrail classifiers are evaded up to ~100%** by character injection
  (zero-width/homoglyph/Unicode-tag) + AML word-importance transfer — Hackett et al.,
  arXiv:2504.11168 (2025) vs Azure Prompt Shield & Meta Prompt Guard [hackett-bypass-2025].
  (ii) **Gradient-based universal injections** defeat defensive measures and expose robustness
  overestimation — Liu et al., arXiv:2403.04957 (2024) [liu-universal-2024]. (iii) **Instruction
  hierarchy / fine-tune defenses are nullified** by backdoor-powered injection when any tuning
  data is poisoned — Chen et al., arXiv:2510.03705 (2025) [chen-backdoor-2025]. (iv) **Over-defense:**
  trigger-word guardrails false-positive on benign mail (NotInject drops SOTA guards to ~60%,
  near chance) [injecguard-2024] — unusable FPR at gateway scale. (v) erase-and-check certifies
  only bounded-length adversarial insertions and is computationally heavy; outside that bound,
  no guarantee. (vi) **"100% mitigation" multi-agent claims are evaluated on fixed attack
  corpora, not adaptive attackers** — by the Athalye/Tramèr rule these numbers are upper bounds,
  not security; more LLM stages also multiply cost/latency and add more injectable surfaces.

---

## Bottom line for ranking
- **Strongest, real:** signal *diversity* (non-text signals: SPF/DKIM/DMARC auth, URL/domain
  reputation, sender history) + input canonicalization for the char-level overlap + adversarial
  training as hygiene. These raise cost broadly.
- **Real but narrow:** certified smoothing/IBP — sound *inside* a declared perturbation set,
  small radius, throughput-limited; deploy as defense-in-depth, never as the guarantee.
- **Weakest / do-not-rely-on-alone:** perturbation/OOD *detectors* and single LLM-judge
  guardrails — the most-bypassed categories under adaptive attack, and the ones with the worst
  FPR/latency at gateway volume.
- **Universal caveat:** every empirical robustness number above that was measured vs a fixed
  attack should be read as an upper bound. Demand adaptive-attack evaluation before trusting any
  of them.
