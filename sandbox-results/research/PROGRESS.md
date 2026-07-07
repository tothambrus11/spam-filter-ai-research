# PROGRESS — obfuscation-resilient spam/phishing detection

Started: 2026-07-02T13:08Z

## Scope decisions (from user, 2026-07-02)
- Target: **email gateway pipeline** (full MIME, HTML bodies, attachments, URLs).
- Optimize for: **evasion robustness**. Key user pain point: low-latency ML filters
  score a 99%-legit-looking email as clean and never fetch/analyze the embedded
  image that carries the actual scam. Open question: is there a cost-viable way to
  protect against image-based attacks (selective OCR / vision escalation)?
- Depth: comprehensive (parallel subagents, adversarial verification of every defense).
- Deliverable: ranked architecture + datasets/benchmarks + red-team eval protocol
  + open gaps → research/reports/SOTA.md

## Attack classes (7) + 1 cross-cutting thread
1. homoglyphs — homoglyph / Unicode confusables
2. zero-width — zero-width & invisible characters
3. mixed-script — mixed-script tricks (incl. bidi/RTL)
4. image-text — text hidden in images / image-based phishing  ← extra depth (user priority)
5. adversarial-ml — adversarial-ML evasion (token/word injection, tokenizer attacks)
6. html-css — HTML/CSS obfuscation & hidden text
7. qr-link — QR / link cloaking & redirect chains
8. cost-tiered-cascade — cross-cutting: cheap-triage → expensive-analysis escalation (user priority)

## Status
- [x] Round 0: scope clarified, directory tree created
- [x] Round 1: taxonomy + defense survey (8 parallel agents) — DONE (16 files in taxonomy/ + defenses/)
- [x] Round 2: adversarial verification — DONE (folded into Round 1; every defense has its known bypass in defenses/*.md)
- [x] Round 3: bibliography consolidation → research/sources.md (~125 keyed entries, 8 sections)
- [x] Round 4: synthesis → research/reports/SOTA.md — DONE

## Key cross-class findings (feed SOTA.md)
- Confidence-gated escalation is the root of the user's bug: an image-only email makes the
  cheap text tier CONFIDENTLY benign (it's correct that the bland visible text is clean), so
  nothing escalates. Fix = escalate on STRUCTURE/PROVENANCE, not classifier confidence.
- Selective OCR is a ~20-yr solved pattern (FuzzyOCR 2007, Dredze 2007 @3-4ms/img; MS/Sublime
  deploy it). Cost model: always-OCR the ~10% structurally-suspicious slice ≈1.9x mean cost;
  vision-LLM (100-350x) reserved for a smaller high-risk residual. [kidsnanny][dredze2007]
- Canonicalize-BEFORE-classify: NFKC + UTS#39 skeleton + invisible-char strip + rendered-
  visible-text extraction, run AFTER MIME/entity decode. NFKC does NOT strip invisible chars
  (verified in-sandbox) and does NOT fold cross-script homoglyphs.
- Every text-only ML/LLM defense has an adaptive-attack bypass; LLM judge over raw body is a
  live prompt-injection surface (Koide26, hackett-2025). Text classifier = one weak voter
  behind hard non-forgeable signals (SPF/DKIM/DMARC, URL/domain reputation, sender history).
- Receive-time scanning is structurally insufficient vs cloaking/TOCTOU/AiTM; click-time
  re-scan + FIDO2/WebAuthn + post-delivery clawback are the real backstops.
- Keep the hidden-vs-visible text DELTA as a malicious feature (Betts24), don't just discard
  hidden text. Single-render is bypassed by client divergence (Outlook mso-hide/@media).

## image-text class (subagent) — DONE
- Wrote research/taxonomy/image-text.md + research/defenses/image-text.md; appended ~35 refs to sources.md.
- Centerpiece answered: selective-OCR cascade IS achievable (FuzzyOCR 2007 + Dredze 2007 prove the pattern; MS/Sublime deploy it) but the cheap gate is itself the attack surface (ASCII/split QR, GenAI-benign body → nothing escalates). Cloaking defeats all receive-time tiers.
- UNVERIFIED/GAPS flagged: (1) no vendor discloses escalation trigger or per-message cost (MS, Sublime); (2) no public paper reports a validated email-image escalation operating point (precision/recall + cost jointly); (3) some 2025-26 arXiv IDs surfaced via WebSearch (image-prompt-injection) not individually fetched — cited from search snippets.
