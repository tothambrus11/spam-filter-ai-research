# Taxonomy — Text Hidden in Images / Image-Based Phishing & Spam

Scope: attacks where the scam-carrying payload (text, brand, link, or code) lives in a
**rendered image** rather than in machine-readable body text, so a low-latency NLP/keyword
classifier reads a clean, "99%-legit" body and never inspects the pixels. This is the
user's top-priority class. All URLs defanged.

---

## 1. Sub-types by how text/payload is hidden

| Sub-type | Description | Why it beats text filters |
|---|---|---|
| **Image-only email** | Entire message body is a single rendered image (advertisement, "invoice", login lure). Body HTML has ~no text. | Nothing for NLP/keyword filter to score; body is empty or a one-line "can't see this? click here". |
| **Text partially in image** | Benign human-written text in body + the scam ask (amount, wallet, phone, link) inside the image. | Body looks legit/conversational; classifier scores it clean. This is the user's exact pain point. |
| **Logo / brand impersonation via image** | Genuine brand logo pasted as image (Microsoft, Adobe, DocuSign, banks). | Brand string never appears as text; only pixels. Defeats brand-name keyword rules. |
| **Text embedded to defeat keyword/NLP** | Spam keywords ("Viagra", "wire transfer", "verify account") rendered as pixels. | Classic 2006-2008 evasion of Bayesian/keyword filters. |
| **Animated / sliced images** | Message assembled from many tiny image slices (HTML table of 1-px-bordered cells) or animated GIF frames; the human eye reconstructs one image. | Each slice is individually benign; no single image carries decodable text; defeats per-image OCR and pHash. |
| **QR code as image (quishing)** | Payload is a QR image; the malicious URL only exists after camera decode. | No clickable link for URL/link scanners; cross-ref `qr-link` class. Microsoft: QR-phish +146% Q1 2026, ~18M unique QR-in-body phish blocked weekly [ms-qr-2024]. |
| **Payload in attachment** | QR/image inside PDF/DOCX attachment (not the body). | Email layer sees a "clean PDF"; the image only decodes on a phone [abnormal-qr; isthisqrsafe]. |

### Delivery / load mechanism (critical for cost-tiering — see defenses)
- **Remote-referenced image** (`<img src="hxxps://cdn[.]evil[.]com/x.png">`): loaded at open time.
  Lets attacker **swap or geofence** the image *after* the scanner has passed (see bypasses).
- **Inline CID / base64 attachment**: pixels ship inside the message; scanner can inspect at
  receive time but pays the decode/OCR cost per message.

---

## 2. OCR-evasion tricks (defeat Tesseract-style pipelines)

- **Additive noise / speckle / background gradients** — degrade character segmentation
  [fumera2006; khanum2012].
- **Low contrast / near-colour text-on-background** — text below OCR binarization threshold.
- **CAPTCHA-style distortion, warping, wavy baselines, overlapping glyphs** — the same
  perturbations that beat OCR beat FuzzyOCR-style keyword matching; the JIT/fuzzy-match era
  answered with edit-distance matching (finds "INVSTORSZ" ≈ "investors") [fuzzyocr].
- **Font substitution, rotation, skew, per-character colour** — breaks fixed-orientation OCR.
- **Colour-channel / steganographic tricks** — text visible only in one channel or via CSS.
- **Sliced tables of tiny images** — no single image is OCR-able; text spans cell boundaries.
- **ASCII/Unicode-block "QR" codes** — QR drawn from █ block characters + CSS transparency;
  "to a typical OCR detection system it appears meaningless", and there is **no image file**
  for an image-QR decoder to find [barracuda2024].
- **Split QR** — one malicious QR cut into several image fragments that look like unrelated
  benign visuals to a scanner, reassembled by the rendering client [open-systems; isthisqrsafe].
- **Adversarial perturbations vs the classifier/OCR** — imperceptible pixel noise that flips a
  CNN image-spam classifier (universal adversarial perturbations, [phung2021]) or defeats OCR
  such that recovered text is garbage while humans read it fine ("Stealthy Porn", real-world
  adversarial promo images, [yuan2019sp]).

---

## 3. Historical arc (note the years — this field cycles)

- **2006-2008 image-spam wave.** At peak, image spam was a large share of all spam. Spammers
  moved keywords into images to beat Bayesian/keyword text filters. Academic answers:
  - text-in-image analysis + low-level image features [fumera2006];
  - **near-duplicate detection** — cluster incoming images against known-spam image sets, since
    spam campaigns reuse a template [wang2007; mehta2008];
  - **speed-first classifiers** — Dredze et al. selected features by *speed as well as accuracy*
    and did **just-in-time feature extraction**, cutting per-image cost from seconds to 3-4 ms
    (~1/1000×) — the earliest explicit cost-tiered image-spam pipeline [dredze2007];
  - **FuzzyOCR** SpamAssassin plugin: OCR image attachments, fuzzy-match keywords, and —
    importantly — **only runs on messages not already classed as spam and only those with
    gif/png/jpeg attachments**, and hashes images to avoid re-scanning [fuzzyocr]. This is a
    real, deployed **selective-OCR cascade from ~2007**.
  - The wave receded partly because randomized/animated images made per-image signatures
    expensive and OCR arms-raced; filters shifted to sender reputation + template hashing.

- **2023-2026 resurgence.** Two drivers:
  1. **Quishing (QR phishing).** ~1 in 20 mailboxes targeted with QR attacks in Q4 2023
     [barracuda2024]; Microsoft reports QR-phish +146% in Q1 2026 [ms-qr-2024]; org-level
     studies confirm quishing + LLM-phish evade common filters [quishing-orgs2025].
  2. **GenAI-generated images & LLM-rephrased lures.** Attackers generate novel, non-duplicate
     brand/lure images on demand (defeats pHash of known campaigns) and perfectly-worded benign
     body text (defeats NLP) — a 2024 study reported AI-phish click-through far above human
     baselines; LLM-rephrased phish evaded Gmail/SpamAssassin/Proofpoint [proofpoint-genai2024;
     jailbreak2025]. Multimodal-LLM defenses in turn face **image prompt injection** (see defenses).

---

## 4. Cross-references
- QR decode / redirect-chain / cloaking mechanics → `qr-link` class.
- Homoglyph/zero-width text-in-body (not image) → `unicode-confusables` class.
- HTML/CSS hidden text (block-char QR, transparent text) straddles this class and `html-css`.
