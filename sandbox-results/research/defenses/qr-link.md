# Defenses — QR / Link Cloaking & Redirect Chains (each with its KNOWN BYPASS)

Rule for this file: no defense is listed without its adversarial bypass. A defense
whose bypass is unaddressed is not SOTA against a motivated attacker. URLs DEFANGED.

---

## D1. QR decoding at the gateway + URL reputation/analysis
**Mechanism.** Rasterize every inbound image and PDF/Office attachment, run a QR
decoder (ZXing/quirc-class), extract the embedded URL, then feed it to the same
URL-reputation / sandbox pipeline used for text links. Restores visibility of the
hidden destination. Now common in SEGs (Abnormal, Barracuda, Proofpoint, Microsoft).
Research on QR-centric detection: Trad & Chehab (arXiv:2505.03451, 2025) classify
directly from QR *structure/pixels* (XGBoost, AUC 0.91) without decoding; CIC-
Trap4Phish (arXiv:2602.09015, 2026) adds a CNN image path + lexical URL path;
Nejati/Ghorbani et al. multi-format dataset incl. QR.

**KNOWN BYPASS.**
- **Decoded URL is only the first hop** — it points to a shortener / open redirect /
  Cloudflare-Turnstile wall, so reputation of the *decoded* string is clean
  (Unit 42, 2024). Decoding alone doesn't reach the phish.
- **Anti-OCR/anti-decoder QR obfuscation:** "fancy"/logo/colored QR codes, split or
  nested QR, QR-in-QR, low-contrast or partial codes, or a QR pasted inside a larger
  image defeat automated decoders while still scanning on a phone (Akram et al. ALFA,
  arXiv:2601.06768, 2026 — visual-DL QR detectors evaded by fancy QR).
- **Cost:** decoding *every* image/attachment on *every* email is expensive; some
  gateways sample or skip large/complex images, which attackers probe for.
- Pixel-structure classifiers (Trad & Chehab) never see the destination, so they
  cannot catch a benign-structured QR pointing at a cloaked/TOCTOU page.

## D2. URL reputation / blocklists (Google Safe Browsing, PhishTank, APWG)
**Mechanism.** Check the URL/domain against curated + crowd feeds. Cheap, low-FP for
*known* bad. (PhishTank crowd feed; PhishChain arXiv:2202.07882 proposes decentralized
blacklisting.)
**KNOWN BYPASS.**
- **Freshness / zero-hour gap:** blocklists lag campaign launch; PhishTime (Oest et
  al., USENIX Sec 2020) and PhishFarm (Oest et al. 2019, OpenAlex W2933056782)
  measured multi-hour reaction windows and showed evasion techniques that *further*
  delay or prevent listing. Attackers cycle domains faster than listing.
- **Cloaking defeats the verifier:** if the site cloaks against the blocklist's
  crawler (D5), it never gets listed (PhishFarm's core result).
- **Reputation borrowing:** LOTS hosting + open redirects put a *trusted* domain in
  the URL, so reputation is positively clean (Unit 42, 2024).
- **Per-victim / one-time URLs:** unique-per-target URLs never accumulate reports.

## D3. Redirect-chain following / sandbox crawling to the final landing page
**Mechanism.** Don't score the first hop — actually fetch it in an instrumented
browser/sandbox, follow 3xx / meta-refresh / JS redirects to the terminal page, then
classify the *final* content (URL + DOM + screenshot). This is what "detonation"
SEGs and Safe-Links-style scanners do.
**KNOWN BYPASS.**
- **Cloaking detects the sandbox** and serves benign content to it (see D5 bypasses):
  UA/IP/ASN/headless fingerprint gating (CrawlPhish, Zhang et al. S&P 2021).
- **CAPTCHA / Cloudflare Turnstile wall** — the crawler cannot pass human
  verification, so it never reaches the phish (Unit 42, 2024).
- **TOCTOU:** the chain is benign at scan time, weaponized after (D6).
- **One-time URLs:** the crawler's fetch consumes the token; the victim (or a re-scan)
  gets a different/dead page.
- **Resource cost / depth limits:** attackers add many hops or long JS delays to
  exceed crawl budgets.

## D4. URL-string ML without fetching (URLNet, lexical/DL models)
**Mechanism.** Classify from the URL string alone — char+word CNN (URLNet, Le et al.
arXiv:1802.03162, 2018), DNN-LSTM (OpenAlex W3189081616, 2021), DEPHIDES (2024,
W4390738590), PhishMatch (arXiv:2112.02226). Fast, no network fetch, catches
lexical tells (long random subdomains, brand look-alikes, punycode).
**KNOWN BYPASS.**
- **Nothing suspicious in the string:** shortener, open redirect on a trusted domain,
  and LOTS URLs are lexically *benign* — the malice is only at the (unfetched)
  destination. Purely lexical models are blind here.
- **Evasion attacks on the classifier itself:** Lei et al. (arXiv:2004.06954, 2020)
  achieved ~100% evasion of Google's phishing page filter and up to 81% on
  BitDefender TrafficLight with function/appearance-preserving mutations; Kim et al.
  (arXiv:2209.01454, 2022) show lexical models fail on URLs "camouflaged with
  legitimate patterns" (their network-graph method is a partial fix but needs
  neighbor data the gateway may lack).

## D5. Cloaking detection: differential/adaptive crawling
**Mechanism.** Crawl each URL from **multiple vantage points** — several UAs
(desktop/mobile), residential + datacenter IPs, geos, with/without Referer, real vs
headless browsers — and flag **content divergence** (split-view) as a cloaking
signal. Client-side: analyze/force-execute JS to reveal gated content.
- **CrawlPhish** (Zhang et al., IEEE S&P 2021): forced execution + taxonomy of 8
  client-side cloaking techniques across 112k sites.
- **PhishParrot** (Nakano/Koide/Chiba, arXiv:2508.02035, 2025): LLM builds optimal
  victim-like crawl profiles from similar past cases; +33.8% detection over standard
  crawling, 91 distinct environments.
- **PhishFarm** (Oest et al., 2019): methodology for measuring which cloaking beats
  which crawler.
**KNOWN BYPASS.**
- **Residential-proxy / mobile-carrier gating & narrow geo/time windows:** if the
  attacker only fires for a specific ISP/geo/time the crawler can't cheaply cover the
  full space (PhishParrot explicitly frames this as an unsolved coverage/cost
  problem — 91 environments and still incomplete).
- **CAPTCHA/Turnstile + human-interaction gates** stop forced execution from
  reaching the payload.
- **Referer/one-time-token gating:** without the exact per-victim link+referer the
  crawler is treated as a bot.
- **Fingerprint arms race:** kits detect `navigator.webdriver`, canvas/WebGL, timing;
  differential crawling raises attacker cost but never closes it (adversarial, ongoing).

## D6. Time-of-click rewriting & re-scan (Microsoft Safe Links / Proofpoint URL Defense)
**Mechanism.** Rewrite every URL to a gateway redirector; on **each click**, re-fetch
and re-evaluate the destination *at click time* — directly attacks TOCTOU because the
check happens when the user uses the link, not at delivery. Strongest single answer to
delayed weaponization and (partially) cloaking.
**KNOWN BYPASS.**
- **Cloaking still applies at click time:** the click-time fetch is still a *scanner*
  fetch; if the site cloaks (UA/IP/headless) or shows a CAPTCHA wall, the click-time
  scan sees benign content and lets the user through to the real phish
  (LevelBlue/SpiderLabs 2025; Microsoft Q&A 2026).
- **Rewrite-coverage gaps:** URLs in unsupported formats, inside images/QR, inside
  attachments, or already wrapped by another rewriter are **not rewritten**, so Safe
  Links never evaluates them (Microsoft Q&A; Guardian Digital 2024). **QR codes are
  the canonical rewrite gap.**
- **Nested-rewriter abuse:** attackers wrap their link in **3+ legitimate Safe-Links/
  rewriting services** so the visible domain is a trusted rewriter and the chain
  resolves only at the end (SpiderLabs/LevelBlue, peaked Jan 2026).
- **Per-click divergence / one-time links:** attacker can serve benign to the click-
  time scanner's fetch and malicious to the human's subsequent fetch.

## D7. Reference-based / visual + LLM landing-page classifiers (defense-in-depth)
**Mechanism.** Once (if) you reach the terminal page, judge it by brand-impersonation
/ credential-form / visual similarity rather than URL — PhishDebate (multi-agent LLM,
arXiv:2506.15656, 2025), on-device reference-based CV (arXiv:2405.18236, 2024),
PhishLang MobileBERT (2024, W4402386991).
**KNOWN BYPASS.**
- **AiTM reverse proxies (Evilginx/EvilProxy/Tycoon 2FA) serve the *real* brand's
  own HTML/pixels** — visual/reference detectors see a legitimate-looking Microsoft/
  Google page because it *is* proxied from the real one (Talos 2024; Abnormal 2024).
- Requires reaching the page at all — nullified by D3/D5/D6 cloaking bypasses upstream.

---

## Net assessment (strongest stack, residual gaps)
- **Best available = layered, click-time-anchored:** QR-decode (D1) + reputation (D2)
  as a cheap first pass, feeding **click-time re-scan with differential/adaptive
  crawling** (D6+D5/PhishParrot), backed by **landing-page visual/LLM judgment (D7)**.
- **Unclosed against a motivated attacker:** the *combination* of (i) CAPTCHA/Turnstile
  + fingerprint cloaking, (ii) per-victim one-time URLs, and (iii) AiTM proxying of
  genuine brand content defeats every content-based tier simultaneously — the scanner
  can neither reach the phish nor, if it does, tell it apart from the real site.
- **Therefore the durable controls are non-content:** phishing-resistant auth
  (FIDO2/WebAuthn passkeys) to neuter AiTM session-cookie theft, and post-delivery /
  click-time telemetry + rapid clawback — not any single scan.
