# Links, cloaking, and body-rewriting — defenses and their KNOWN BYPASSES

Covers the three branches the user mapped: (1) detecting obfuscation, (2) link/target
trustworthiness under trampolining + cloaking, (3) render+OCR/QR under fetch-time cloaking
and the "rewrite the body" defense. Citations = arXiv/DOI/URL + year; unverifiable flagged;
live phishing URLs defanged. Ties back to [[cost-tiered-cascade]] §D3-cost-shift: the
target-content race is expensive and partially unwinnable, so the durable signal keeps
falling back to provenance/reputation + the *structural fact* of obfuscation/redirection.

---

## L1. Can we DETECT obfuscation (vs. decode it)?
**Yes — detecting the *presence* of obfuscation is more robust than decoding it**, because
obfuscation is statistically anomalous in legitimate mail. This flips the attacker into a
lose-lose ("attacker's dilemma"): obfuscate → trip the anomaly gate / escalate; don't
obfuscate → the cheap text tier reads the payload.

**Cheap, deterministic obfuscation detectors (presence = escalation signal):**
- **Zero-width / invisible Unicode**: U+200B/C/D ZWSP/ZWNJ/ZWJ, U+FEFF BOM, U+00AD soft
  hyphen, tag chars U+E0000–E007F. Near-zero legitimate use in body text.
- **Homoglyph / confusables / mixed-script within a token**: Unicode UTS#39 confusable
  skeleton + Mixed-Script Confusable detection; a Latin+Cyrillic token is a strong flag.
- **Bidi control chars** (Trojan-Source class): Boucher & Anderson 2021, arXiv:2111.00169.
- **Hidden HTML/CSS text**: font-size:0, color==background, display:none, visibility:hidden,
  opacity:0, off-screen absolute positioning, 1px containers.
- **Invalid/malformed HTML** and **multipart abuse**: measured at 28.8% of phishing and —
  usefully — *correlated with HIGHER detection scores*, i.e. filters already treat
  malformation as suspicious (Dalmiere, Zhou, Auriol, Nicomette, Marchand 2025,
  "Measuring Modern Phishing Tactics," arXiv:2506.20228).
- **Layout anomaly** (from [[cost-tiered-cascade]] §D3-cost-shift): many tiny inline-base64
  images tiled into a contiguous region, imageless table-QR module grids.

**KNOWN BYPASS / LIMIT — presence-detection is a SIGNAL, not a VERDICT.**
- **Base-rate / false-positive problem.** Several obfuscations have legitimate uses: inline
  base64 images are ubiquitous in marketing; emoji ZWJ sequences use ZWJ legitimately;
  internationalized brand/personal names are legitimately mixed-script; foreign-language mail
  is legitimately non-Latin. "Any obfuscation → spam" over-blocks. So obfuscation-presence
  belongs as an **escalation trigger into the deep tier (render/OCR/decode) and a feature in
  the final classifier**, not a standalone block. (Same role as the structural gates in
  [[cost-tiered-cascade]] D3 — cheap escalation heuristic, not guarantee.)
- **Threshold-hugging.** Attacker uses *just enough* obfuscation to evade the text filter but
  *below* the anomaly detector's sensitivity, or obfuscation indistinguishable from legitimate
  (one legit inlined image; a real internationalized word). Canonicalize-then-classify
  (NFKC + confusable skeleton + strip zero-width + OCR) also has failure modes: over-
  normalization causes false merges (a legit foreign token → a scam skeleton) and loses
  information the classifier needed.
- **Net:** obfuscation is substantially detectable and it's one of the more *attacker-costly*
  signals because it's lose-lose — but it raises risk / forces escalation; it does not by
  itself convict.

---

## L2. Are the LINKS trustworthy? Trampolining + cloaking.
Two distinct problems the user correctly separated.

### L2a. Trampoline / open redirects / URL shorteners
Trusted domain → redirect → malicious. **First-hop reputation is worthless** when the trusted
domain hosts an open redirect (Google, tinyurl, is.gd, maps shortener, corporate redirectors)
or is a generic shortener. Defense: **resolve the entire redirect chain to its terminus** and
classify (a) the final landing URL and (b) the chain shape itself.
**BYPASS:** attackers chain multiple shorteners, use JS / `<meta http-equiv=refresh>` /
`window.location` redirects that a plain HTTP-30x follower misses, and redirect *conditionally*
(only humans get bounced). So chain resolution needs a **headless browser that executes JS**,
not just an HTTP client — which then exposes you to L2b cloaking.

### L2b. Cloaking — server serves different content to bots vs humans
The deep problem. The target site fingerprints the fetcher and shows benign content to
scanners, malicious to victims.
- **Server-side cloaking** (UA / IP-ASN / geo / referrer / cookie / rDNS checks): canonical
  detection is *differential fetching* — fetch the URL as a naive crawler AND as a
  realistic user (real browser fingerprint, residential-looking vantage, referrer/cookies),
  then treat any *content discrepancy* as the signal (Invernizzi, Thomas, Kapravelos,
  Comanescu, McCoy, Bursztein, et al., "Cloak of Visibility: Detecting When Machines Browse
  a Different Web," IEEE S&P 2016,
  hxxps://research.google/pubs/pub45581/ ; researchgate 306301774).
- **Client-side cloaking** (JS requiring mouse movement / interaction / CAPTCHA solve /
  timing before revealing the payload): CrawlPhish taxonomy of 8 techniques across User-
  Interaction / Fingerprinting / Bot-Behavior; detects cloaking at 1.45% FP / 1.75% FN but at
  ~30 s/site (Zhang, Oest, et al., "CrawlPhish," IEEE S&P 2021,
  hxxps://haehyun.github.io/papers/crawlphish-oakland21.pdf ; IEEE Xplore 9647013).
- **LLM-driven adaptive crawling** as the current arms-race response (mimic victim context to
  defeat cloaking): PhishParrot 2025, arXiv:2508.02035 [FLAG: single-source 2025 preprint].

**KNOWN BYPASS / HARD LIMIT — the target-content race is partially UNWINNABLE:**
- **One-time / burn-on-fetch links**: URL valid for a single visit; the scanner's fetch either
  burns it (victim gets a dead link — noisy but not blocked) or the scanner sees a fresh
  benign page while the victim's later visit is weaponized.
- **Delayed activation**: benign at delivery/scan window, weaponized after (time-of-click ≠
  time-of-scan).
- **CAPTCHA / real-session walls** the scanner cannot pass without a human.
Because target content can be made adversarial to *any* fetch, the durable signals fall back
(again) to things the attacker can't cloak: **URL/domain reputation, domain age, registration
& TLS-cert anomalies, redirect-chain structure, shortener-from-first-contact-sender, and the
mere STRUCTURAL FACT that the link is cloaked/redirected**. Cloaking-detection's own output —
"this URL serves different content to bots vs humans" — is itself a high-value verdict even
when you never see the payload.

---

## L3. Render + OCR/QR under fetch-time cloaking; and "can a spam filter rewrite the body?"
User's bypass: remote resources (images/QR targets) served *differently based on who fetches*.
User's proposed defense: fetch once and **re-serve the same resource to real users** — which
requires modifying the email body. User's question: *is that possible / OK?*

**ANSWER: yes, and it is standard, deployed practice — the user re-invented Gmail's image
proxy.**
- **Image proxying / caching (exact precedent for the user's defense).** Since Dec 2013 Gmail
  rewrites every remote `<img src>` to route through Google's cache
  (`ci*.googleusercontent.com/proxy/…`): Google fetches the image **once**, caches it, and
  serves that **single cached copy** to every viewer (Word to the Wise 2013,
  hxxps://www.wordtothewise[.]com/2013/12/gmail-deploys-image-proxy-servers ; Valsorda 2013,
  hxxps://words.filippo[.]io/how-the-new-gmail-image-proxy-works-and-what-this-means-for-you/ ).
  Effect: the origin sees one fetch (Google's) and **cannot serve benign-to-scanner +
  malicious-to-human for the same URL** — the per-fetch image-cloaking degree of freedom is
  removed, so OCR/CV on the cached copy sees exactly what the human sees. This is precisely
  the user's "fetch and re-serve" idea, in production for a decade.
  - *Residual:* the origin can still put a **unique URL per recipient** and serve malicious
    content *unconditionally* to it (the proxy faithfully caches+shows it) — but that's fine,
    because OCR/CV on the cached copy then catches it. Proxying kills *differential* serving,
    not *unconditional* payloads; the OCR tier handles the latter.
- **URL rewriting / time-of-click scanning.** For *links* (not images), body rewriting is
  also standard: Microsoft Defender **Safe Links**, Proofpoint **URL Defense**, Mimecast
  **URL Protect** rewrite every URL to a scanning proxy and re-evaluate the destination **at
  click time** — which is the correct answer to L2b delayed-activation, since scan-time ≠
  click-time.
- **Banners / headers / CDR.** Gateways inject `[EXTERNAL]` banners and rewrite/disarm active
  content (content-disarm-and-reconstruction) routinely. Body modification is normal.

**CAVEATS / COSTS of rewriting the body:**
- **DKIM body hash.** Standard DKIM signs a body hash (`bh=`); altering the *stored, signed*
  MIME invalidates it. Two clean ways around it: (a) modify only the **rendered view** shown
  to the user (Gmail's proxy rewrites the HTML at display time, not the signed message at
  rest — DKIM, verified at ingestion, is untouched); (b) rewrite the stored message **after**
  boundary DKIM verification, within your own trust domain, and if re-injecting downstream use
  **ARC** (Authenticated Received Chain, RFC 8617) to carry the verified auth results across
  the modifying intermediary. Either way: verify-then-modify, never modify-then-forward-and-
  expect-DKIM-to-hold.
- **End-to-end signed/encrypted bodies (S/MIME, PGP).** You cannot rewrite a
  cryptographically signed body without visibly breaking the signature, and cannot proxy
  images inside an encrypted body at all. These are a genuine blind spot for the re-serve
  defense — but signed/encrypted mail is itself a strong provenance signal and a tiny traffic
  share.
- **Fidelity/liability.** You become a fetch-and-store proxy for third-party content (privacy,
  legal, cache-poisoning surface); rewriting can break legitimate unsubscribe links, dynamic
  content, and legitimate open-tracking.

**Bottom line L3:** yes, a filter may (and mainstream ones do) modify the body / rendered
view; image-proxying is the deployed form of the user's exact defense and it *removes the
fetch-time image-cloaking bypass* by construction. It does **not** by itself solve *link*
cloaking (handle that with time-of-click URL rewriting, L2b) and cannot touch end-to-end
signed/encrypted bodies.

---

## L4. The through-line (ties to [[cost-tiered-cascade]])
All three branches converge on the same lesson as §D3-cost-shift: **you can raise the
attacker's cost and remove specific degrees of freedom (obfuscation becomes a lose-lose
signal; image-proxying kills fetch-time image cloaking; chain-resolution kills first-hop
trust), but the content/target-race is partially unwinnable (threshold-hugging, one-time
links, delayed activation, signed bodies).** The guarantees therefore live in signals the
attacker cannot cloak — provenance/auth (SPF/DKIM/DMARC alignment, first-contact, domain age/
reputation), the *structural fact* of obfuscation/redirection/cloaking itself, and keyed
random deep-scan ([[cost-tiered-cascade]] D5) — with render/OCR/decode as the escalation catch,
not the front line.

## L5. Residual-risk table
| Branch | Defense | Cost | Killed by / residual |
|---|---|---|---|
| L1 obfuscation | presence-detection (zero-width/homoglyph/hidden-CSS/invalid-HTML/layout) | cheap | base-rate FPs → signal not verdict; threshold-hugging (2506.20228, 2111.00169) |
| L2a trampoline | resolve full redirect chain (headless, exec JS) | medium | JS/meta/conditional redirects; first-hop reputation worthless |
| L2b cloaking | differential fetch (Cloak of Visibility) + client-side (CrawlPhish) | expensive (~30s/site) | one-time/burn links, delayed activation, CAPTCHA walls → fall back to reputation/provenance |
| L3 rendering | image-proxy re-serve (Gmail) + time-of-click URL rewrite (Safe Links) | medium | end-to-end signed/encrypted bodies; DKIM (needs verify-then-modify / ARC); per-recipient unconditional payloads (caught by OCR) |
