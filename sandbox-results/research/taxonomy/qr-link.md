# Taxonomy — QR / Link Cloaking & Redirect Chains ("quishing" + evasive URL delivery)

Scope: obfuscation of the *destination* of a link so that URL/text scanners in an
email gateway cannot see, reach, or evaluate the true malicious landing page at
scan time. This class is adversarial by construction: the attacker's goal is that
whatever the gateway sees is NOT what the victim sees.

All live/attacker URLs below are DEFANGED (hxxp, `[.]`). Do not re-fang.

---

## (a) QR / quishing — URL hidden inside an image

**Definition.** The malicious URL is encoded in the pixel matrix of a QR-code
image (PNG/JPG/SVG, or rendered inside a PDF/DOCX/XLSX attachment) instead of an
`<a href>` or plain-text link. A secure email gateway (SEG) parses headers, body
text, and `href`s, then checks extracted URLs against reputation/blocklists — but
"when the malicious URL is encoded inside the pixel matrix of an image, none of
those inspections apply" (Spambrella 2024; Abnormal AI 2024). This is fundamentally
a *text-hidden-in-image* problem (ties to the image-analysis attack class) plus a
URL-evasion problem. The QR also pushes the click onto a **mobile device**, which
typically sits outside the corporate SEG/EDR and has a small screen that hides the
address bar.

**Real examples / scale (2023–2025 surge):**
- APWG tracked a **~400% increase in image-based phishing** heading into 2025;
  Microsoft Digital Defense Report flagged **>15,000 QR-bearing phishing emails/day**
  against the education sector alone (summarized Acronis 2026; Abnormal AI 2024).
- Barracuda: detected **>500,000** phishing emails carrying QR codes **embedded in
  PDF attachments** (Barracuda Threat Spotlight, 2024-10-22) — moving the QR into an
  attachment defeats inline body scanning.
- Sharevski et al., *Gone Quishing* (arXiv:2204.04086, 2022): 173-participant field
  study; 67% signed up with Google/Facebook creds via a malicious QR pretext.
- Geisler & Pöhn, *Hooked: A Real-World Study on QR Code Phishing*
  (arXiv:2407.16230, 2024): campus campaign; professionally-designed QR lures drew
  significantly more scans.
- Weinz, Zannone, Allodi, Apruzzese (arXiv:2505.12104, 2025): 71k-email org study —
  quishing emails were **as effective as traditional phishing** at reaching the
  landing page, "much harder to identify even by operational detectors."
- Abnormal AI (2024): **C-suite executives receive ~42x more QR-code attacks** than
  the average employee (targeting).
- "Fancy"/colorful/logo QR codes: Akram et al., *ALFA* (arXiv:2601.06768, 2026) —
  aesthetic QR codes with non-standard modules evade visual-DL QR detectors while
  still scanning on phones.

## (b) Redirect chains & URL shorteners

**Definition.** The link in the email is not the landing page; it is the first hop
of a chain (`bit[.]ly` / `t[.]co` / `tinyurl` -> attacker redirector -> ... -> final
page). Shorteners hide the true destination from lexical inspection and let the
attacker swap the final target after delivery. Multi-hop chains (HTTP 3xx,
`<meta refresh>`, JS `location`, or a chain of *multiple* legitimate rewriters)
"obfuscate the attack, increasing the complexity for security crawlers and
concealing the infrastructure" (Unit 42, 2024).

**Real examples:**
- Grier et al. / "Click Traffic Analysis of Short URL Spam on Twitter" (2013,
  OpenAlex W1979332355) — early shortener abuse.
- Unit 42 (Palo Alto, 2024): quishing campaigns chain 2+ redirects and terminate on
  a Cloudflare-fronted host.
- SpiderLabs/LevelBlue (2025–2026): phishers chained **three or more legitimate URL-
  rewriting/Safe-Links services** so each layer looks like a trusted domain; activity
  peaked Jan 2026.

## (c) Open redirects on trusted domains

**Definition.** A legitimate site exposes an endpoint like
`hxxps://trusted[.]com/redirect?url=<attacker>` that 302s to any destination. The
email link's *visible* host is the trusted brand (google.com, a bank, an ad/marketing
tracker), so reputation and even human inspection pass; the redirect delivers the
victim to the attacker.

**Real examples:**
- Unit 42 (2024): a quishing email used a "cleverly formatted **Google** link that…
  redirects the visitor to the phishing site — a lookup of the URL would have
  classified the site (google.com) as safe."
- Common abused redirectors historically: Google (`google[.]com/url?q=`), YouTube,
  DoubleClick/ad trackers, LinkedIn `lnkd[.]in`, Baidu, and marketing-email click
  trackers.

## (d) Cloaking — serve benign to scanners, malicious to victims

**Definition.** The server decides *who* you are and returns different content.
Two families (CrawlPhish taxonomy, Zhang et al., IEEE S&P 2021):

- **Server-side cloaking** — gating on request metadata *before* content is sent:
  User-Agent, source **IP / ASN** (block known crawler ranges: Google, Microsoft,
  security vendors, cloud providers), **geo** (only fire in the target country),
  **Referer** (only fire if arriving from the phishing email/redirector), Accept-
  Language, time-of-day, or one-time single-use tokens. Scanners get a 404 / a
  benign page / a legit site; victims get the phish. (PhishFarm, Oest et al. 2019,
  OpenAlex W2933056782; "World-wide cloaking phishing websites detection" 2017,
  W2890465310.)
- **Client-side cloaking** — the page is served, but JS decides whether to render
  the phish. CrawlPhish taxonomy = 8 techniques in 3 categories: **User
  Interaction** (require a click/mouse-move/scroll before revealing), **Fingerprinting**
  (check screen size, `navigator.webdriver`, touch support, cookies, canvas/WebGL,
  timezone), and **Bot Behavior** (detect headless/automation). Modern kits gate on
  a **CAPTCHA / Cloudflare Turnstile** human-verification wall (Unit 42, 2024) that
  crawlers cannot pass.

**Real examples:**
- Zhang et al. CrawlPhish (S&P 2021): 112,005 wild phishing sites; client-side
  cloaking present and growing.
- Unit 42 (2024): quishing landing pages front-ended by **Cloudflare Turnstile** to
  "evade security crawlers."

## (e) TOCTOU / delayed weaponization (time-of-check vs time-of-use)

**Definition.** The URL is **benign when the gateway scans it** (at delivery) and
weaponized **after** — minutes/hours later, or on first victim click. The email
passes because the destination genuinely was clean at scan time. Variants: swap the
content at the final host; activate the redirect only after a delay; register/arm
the domain post-delivery; or one-time URLs that self-destruct after first fetch
(so the scanner's own fetch "uses up" the URL, and re-scans see a dead link).

**Real examples:**
- LevelBlue/SpiderLabs & Microsoft Q&A (2025–2026): "URL points to a clean page at
  delivery, then switches to malicious content after scanning."
- PhishTime / PhishFarm (Oest et al., USENIX Sec 2020 / 2019): measured that
  attackers time content and evasion around blacklist reaction windows.

## (f) Trusted-service abuse / living-off-trusted-sites (LOTS) & AiTM

**Definition.** Host the phish (or its early hops) on infrastructure with inherent
good reputation so domain/URL reputation can't flag it: Microsoft/Google/Cloudflare
services, `*.blob.core.windows.net`, `*.web.app` / Firebase, `*.r2.dev`,
`*.pages.dev`, IPFS gateways, SharePoint/OneDrive/Google-Docs share links, DocuSign,
Adobe, form builders, and **CDN/WAF fronting (Cloudflare)** that hides origin IP so
crawlers can't reach or reputation-score the true server.

**AiTM / reverse-proxy kits (a special, dominant case):**
- **Evilginx / EvilProxy / Tycoon 2FA / Sneaky 2FA** run a reverse proxy that sits
  between victim and the *real* Microsoft/Google login, relaying traffic and stealing
  the post-MFA **session cookie** — defeating MFA. By Aug 2024 "nearly 100%" of some
  observed campaigns had moved to proxy interception; Microsoft reported a **146%
  rise in AiTM attacks** in 2024; 91% led to BEC (Abnormal AI 2024; Talos 2024).
- Relevance to this class: the phishing URL is per-victim, short-lived, cloaked, and
  proxies genuine brand content — so both reputation and visual/reference-based
  detectors see the legitimate site's own HTML.

---

## Cross-cutting evasion primitives (why this class is hard)
1. **Invisible-to-scanner destination:** QR image, shortener, open redirect, or CDN
   fronting hides/relocates the true URL.
2. **Split view:** cloaking guarantees scanner-content != victim-content.
3. **Time split:** TOCTOU guarantees scan-time-content != click-time-content.
4. **Reputation borrowing:** LOTS/open-redirect/AiTM inherit trusted-domain scores.
5. **Per-victim uniqueness:** one-time tokens/URLs defeat blocklist sharing and
   re-scan.
6. **Mobile pivot (QR):** moves the click off the monitored corporate device.
