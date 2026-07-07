# Bibliography — obfuscation-resilient spam/phishing detection

Consolidated 2026-07-02. Organized by attack class (a handful of foundational
papers — e.g. Lowd & Meek 2005, Boucher et al. "Bad Characters" 2021 — recur across
sections by design). Every entry carries an arXiv id, DOI, or URL. Live phishing URLs
are defanged (hxxp / [.]). Citation keys used in `reports/SOTA.md` and the per-class
files under `taxonomy/` and `defenses/` resolve here.

Reliability flags: entries marked `[vendor-blog]` / `[vendor-docs]` are industry
sources (useful for prevalence and deployed-system behavior, weaker as primary
evidence). Several 2025–2026 arXiv preprints are single-source and flagged inline in
the per-class files; their *mechanisms* are cited but their headline numbers are
treated as unverified.

## Homoglyph / Unicode confusables (subagent contribution, 2026-07-02)
[uts39] UTS #39: Unicode Security Mechanisms (skeleton, confusables.txt, mixed-script, restriction levels) — Unicode Consortium. URL: https://www.unicode.org/reports/tr39/
[uax15] UAX #15: Unicode Normalization Forms (NFC/NFD/NFKC/NFKD) — Unicode Consortium. URL: https://www.unicode.org/reports/tr15/
[shamfinder] ShamFinder: An Automated Framework for Detecting IDN Homographs — Suzuki, Chiba, Yoneya, Mori, Goto (2019). arXiv:1909.07539
[woodbridge] Detecting Homoglyph Attacks with a Siamese Neural Network — Woodbridge, Anderson, Ahuja, Grant (2018). arXiv:1805.09738
[deng] Weaponizing Unicodes with Deep Learning — Identifying Homoglyphs with Weakly Labeled Data — Deng, Linsky, Wright (2020). arXiv:2010.04382
[glyphnet] GlyphNet: Homoglyph domains dataset and detection using attention-based CNNs — Gupta, Tomar, Garg (2023). arXiv:2306.10392
[badchars] Bad Characters: Imperceptible NLP Attacks — Boucher, Shumailov, Anderson, Papernot (2021; IEEE S&P 2022). arXiv:2106.09898
[bitabuse] BitAbuse: A Dataset of Visually Perturbed Texts for Defending Phishing Attacks — Lee, Lee, Lee, Lee (2025). arXiv:2502.05225
[phishdebate] PhishDebate: An LLM-Based Multi-Agent Framework for Phishing Website Detection — Li, Manickam, Chong, Karuppayah (2025). arXiv:2506.15656
[petrukha] Think Globally, React Locally — Real-time Reference-based Website Phishing Detection on macOS — Petrukha, Stulova, Kryvoblotskyi (2024). arXiv:2405.18236
[specialchar] Special-Character Adversarial Attacks on Open-Source Language Models (2025). arXiv:2508.14070
[zheng] Phishing with Unicode Domains (apple.com IDN homograph demo) — Xudong Zheng (2017). URL: https://www.xudongz.com/blog/2017/idn-phishing/
[mozbug] Bugzilla 1463219: Homograph attack not solved (Xudong Zheng's apple.com) — Mozilla (2017). URL: https://bugzilla.mozilla.org/show_bug.cgi?id=1463219
[dnstwist] dnstwist: Domain name permutation engine for homograph/typosquatting/brand impersonation — elceef. URL: https://github.com/elceef/dnstwist
[mathalnum] Mathematical Alphanumeric Symbols (U+1D400–U+1D7FF; spam filter evasion) — Wikipedia / Unicode charts. URL: https://en.wikipedia.org/wiki/Mathematical_Alphanumeric_Symbols
[paultendo] confusables.txt and NFKC disagree on 31 characters / LLM reads codepoints not glyphs — paultendo.github.io (2024–2025). URL: https://paultendo.github.io/posts/unicode-confusables-nfkc-conflict/
[codexissue] Unicode confusable characters can bypass exec policy matching — openai/codex issue #13095 (2025). URL: https://github.com/openai/codex/issues/13095

## Adversarial-ML evasion (subagent: adversarial-ml)
[lowd-goodword-2005] Good Word Attacks on Statistical Spam Filters — Lowd & Meek (2005). CEAS 2005.
[lowd-acre-2005] Adversarial Learning (ACRE query model) — Lowd & Meek (2005). KDD 2005.
[wittel-2004] On Attacking Statistical Spam Filters — Wittel & Wu (2004). CEAS 2004.
[nelson-2008] Exploiting Machine Learning to Subvert Your Spam Filter — Nelson et al. (2008). USENIX LEET 2008. openalex:W2162552722.
[barreno-2010] The Security of Machine Learning — Barreno, Nelson, Joseph, Tygar (2010). doi:10.1007/s10994-010-5188-5.
[biggio-wildpatterns-2018] Wild Patterns: Ten Years After the Rise of Adversarial ML — Biggio & Roli (2018). doi:10.1016/j.patcog.2018.07.023.
[biggio-svm-2014] Security Evaluation of SVMs in Adversarial Environments — Biggio et al. (2014). arXiv:1401.7727.
[hotflip-2018] HotFlip: White-Box Adversarial Examples for Text Classification — Ebrahimi et al. (2018). arXiv:1712.06751; ACL 2018 doi:10.18653/v1/p18-2006.
[deepwordbug-2018] Black-box Generation of Adversarial Text Sequences (DeepWordBug) — Gao et al. (2018). arXiv:1801.04354.
[textbugger-2019] TextBugger: Generating Adversarial Text Against Real-world Applications — Li et al. (2019). arXiv:1812.05271; NDSS 2019.
[textfooler-2020] Is BERT Really Robust? (TextFooler) — Jin et al. (2020). arXiv:1907.11932; AAAI 2020.
[bae-2020] BAE: BERT-based Adversarial Examples — Garg & Ramakrishnan (2020). arXiv:2004.01970; EMNLP 2020.
[gbda-2021] Gradient-based Adversarial Attacks against Text Transformers — Guo et al. (2021). doi:10.18653/v1/2021.emnlp-main.464.
[hotoglu-spam-2025] A Comprehensive Analysis of Adversarial Attacks against Spam Filters — Hotoğlu, Sen, Can (2025). arXiv:2505.03831.
[textattack-2020] TextAttack Framework — Morris et al. (2020). doi:10.18653/v1/2020.emnlp-demos.16.
[reeval-2020] Reevaluating Adversarial Examples in Natural Language — Morris et al. (2020). doi:10.18653/v1/2020.findings-emnlp.341.
[dyrmishi-2023] How do humans perceive adversarial text? — Dyrmishi et al. (2023). doi:10.18653/v1/2023.acl-long.491.
[salman-sms-2022] An Empirical Analysis of SMS Scam Detection Systems — Salman et al. (2022). arXiv:2210.10451.
[afane-2024] Next-Generation Phishing: How LLM Agents Empower Cyber Attackers — Afane et al. (2024). arXiv:2411.13874.
[kim-federated-2022] Characterizing Internal Evasion Attacks in Federated Learning — Kim et al. (2022). arXiv:2209.08412.
[cw-2017] Adversarial Examples Are Not Easily Detected: Bypassing Ten Detection Methods — Carlini & Wagner (2017). arXiv:1705.07263; AISec 2017.
[athalye-2018] Obfuscated Gradients Give a False Sense of Security — Athalye, Carlini, Wagner (2018). arXiv:1802.00420; ICML 2018.
[tramer-2020] On Adaptive Attacks to Adversarial Example Defenses — Tramèr et al. (2020). arXiv:2002.08347; NeurIPS 2020.
[acat-2024] Adaptive Continuous Adversarial Training (ACAT) — elShehaby et al. (2024). arXiv:2403.10461.
[fgpm-2021] Adversarial Training with Fast Gradient Projection Method — Wang et al. (2021). doi:10.1609/aaai.v35i16.17648.
[jia-ibp-2019] Certified Robustness to Adversarial Word Substitutions (IBP) — Jia et al. (2019). doi:10.18653/v1/d19-1423.
[safer-2020] SAFER: Structure-free Certified Robustness to Word Substitutions — Ye, Gong, Liu (2020). arXiv:2005.14424; ACL 2020.
[ranmask-2021] Certified Robustness to Text Adversarial Attacks by Randomized [MASK] (RanMASK) — Zeng et al. (2021/2023). arXiv:2105.03743.
[worddp-2021] Certified Robustness to Word Substitution Attack with Differential Privacy — (2021). doi:10.18653/v1/2021.naacl-main.87.
[textcrs-2023] Text-CRS: Generalized Certified Robustness Framework — Zhang et al. (2023/2024). arXiv:2307.16630; IEEE S&P 2024.
[certed-2024] CERT-ED: Certifiably Robust Text Classification for Edit Distance — Huang et al. (2024). arXiv:2408.00728.
[selfdenoise-2023] Certified Robustness for LLMs with Self-Denoising — Zhang et al. (2023). arXiv:2307.07171.
[crutp-2024] CR-UTP: Certified Robustness against Universal Text Perturbations — Lou et al. (2024). arXiv:2406.01873.
[pruthi-2019] Combating Adversarial Misspellings with Robust Word Recognition (ScRNN) — Pruthi, Dhingra, Lipton (2019). arXiv:1905.11268; ACL 2019.
[disp-2019] Learning to Discriminate Perturbations (DISP) — Zhou et al. (2019). arXiv:1909.03084; EMNLP 2019.
[purify-2022] Text Adversarial Purification as Defense — Li, Song, Qiu (2022). arXiv:2203.14207.
[yang-random-2018] Using Randomness to Improve Robustness Against Evasion Attacks — Yang & Chen (2018). arXiv:1808.03601.
[zedd-2026] Zero-Shot Embedding Drift Detection (ZEDD) — Sekar et al. (2026). arXiv:2601.12359.
[uniguardian-2025] UniGuardian: Unified Defense (injection/backdoor/adversarial) — Lin et al. (2025). arXiv:2502.13141.
[struq-2024] StruQ: Defending Against Prompt Injection with Structured Queries — Chen et al. (2024). arXiv:2402.06363.
[secalign-2024] SecAlign: Defending Against Prompt Injection with Preference Optimization — Chen et al. (2024). arXiv:2410.05451.
[spotlight-2024] Defending Against Indirect Prompt Injection with Spotlighting — Hines et al. (2024). arXiv:2403.14720.
[mixenc-2025] Defense against Prompt Injection via Mixture of Encodings — Zhang et al. (2025). arXiv:2504.07467.
[kumar-erase-2023] Certifying LLM Safety against Adversarial Prompting (erase-and-check) — Kumar et al. (2023). arXiv:2309.02705.
[injecguard-2024] InjecGuard: Benchmarking/Mitigating Over-defense in Prompt Injection Guards — Li & Liu (2024). arXiv:2410.22770.
[courtguard-2025] CourtGuard: Local Multiagent Prompt Injection Classifier — Wu & Maslowski (2025). arXiv:2510.19844.
[multiagent-2025] A Multi-Agent LLM Defense Pipeline Against Prompt Injection — Hossain et al. (2025). arXiv:2509.14285.
[pcfi-2026] Prompt Control-Flow Integrity (PCFI) — Alam et al. (2026). arXiv:2603.18433.
[hackett-bypass-2025] Bypassing LLM Guardrails: Empirical Analysis of Evasion Attacks — Hackett et al. (2025). arXiv:2504.11168.
[liu-universal-2024] Automatic and Universal Prompt Injection Attacks against LLMs — Liu et al. (2024). arXiv:2403.04957.
[chen-backdoor-2025] Backdoor-Powered Prompt Injection Attacks Nullify Defense Methods — Chen et al. (2025). arXiv:2510.03705.

## HTML/CSS obfuscation & hidden text (subagent: html-css)
- [Betts24] Exploring Content Concealment in Email — Betts, Biddle, Lottridge, Russello (2024). arXiv:2410.11169
- [Koide26] Clouding the Mirror: Stealthy Prompt Injection Attacks Targeting LLM-based Phishing Detection — Koide, Nakano, Chiba (2026). arXiv:2602.05484
- [Opara20] Look Before You Leap (WebPhish) — Opara, Chen, Wei (2020). arXiv:2011.04412
- [Kulal25] Robust ML Detection ... Advanced Text Preprocessing — Kulal et al. (2025). arXiv:2510.11915
- [LowdMeek05] Good Word Attacks on Statistical Spam Filters — Lowd, Meek (2005). CEAS 2005
- [TalosSeasoning25] Seasoning email threats with hidden text salting — Cisco Talos (2025-01-24). hxxps://blog.talosintelligence[.]com/seasoning-email-threats-with-hidden-text-salting/ [vendor-blog]
- [TalosAbusingStyle25] Abusing with style: CSS for evasion and tracking — Cisco Talos (2025-03-13). hxxps://blog.talosintelligence[.]com/css-abuse-for-evasion-and-tracking/ [vendor-blog]
- [TalosTooSalty25] Too salty to handle: CSS abuse for hidden text salting — Cisco Talos (2025-10-07). hxxps://blog.talosintelligence[.]com/too-salty-to-handle-exposing-cases-of-css-abuse-for-hidden-text-salting/ [vendor-blog]
- [SublimeKeywords] Detect keywords in body (inner_text vs raw) — Sublime Security docs [vendor-docs]
- [SublimeRules] sublime-security/sublime-rules — open detection rules [vendor]
- [SublimeCredPhish] Credential phishing: browser-emulation + computer vision — Sublime Security [vendor-blog]
- [gbhackersOutlook] Outlook HTML-based phishing (MSO conditional comments) — gbhackers [vendor-blog]

## Image-based phishing/spam (text-hidden-in-image) — added by image-text subagent

[fumera2006] Spam Filtering Based on the Analysis of Text Information Embedded into Images — Fumera, Pillai, Roli (2006). JMLR 7. (text-in-image + low-level features; ~137 cites)
[dredze2007] Learning Fast Classifiers for Image Spam — Dredze, Gevaryahu, Elias-Bachrach (2007). CEAS 2007. https://www.cs.jhu.edu/~mdredze/publications/image_spam_ceas07.pdf (speed-aware feature selection + JIT extraction; 3-4 ms/image; CASCADE anchor)
[wang2007] Filtering Image Spam with Near-Duplicate Detection — Wang et al. (2007). CEAS 2007. (near-dup campaign clustering)
[mehta2008] Detecting Image Spam Using Visual Features and Near Duplicate Detection — Mehta et al. (2008). WWW 2008. doi:10.1145/1367497.1367565
[khanum2012] Trends in Combating Image Spam E-mails — Khanum, Ketari (2012). arXiv:1212.1763
[kumar2018] DeepImageSpam: Deep Learning based Image Spam Detection — Kumar, Vinayakumar, Soman (2018). arXiv:1810.03977 (91.7%)
[kim2020] DeepCapture: Image Spam Detection Using Deep Learning and Data Augmentation — Kim, Abuadbba, Kim (2020). arXiv:2006.08885 (CNN-XGBoost, F1 88%; overfitting-to-unseen framing)
[phung2021] Universal Adversarial Perturbations and Image Spam Classifiers — Phung, Stamp (2021). arXiv:2103.05469 (BYPASS: universal adv. perturbations flip CNN image-spam classifiers)
[sharmin2022] Convolutional Neural Networks for Image Spam Detection — Sharmin, Di Troia, Potika, Stamp (2022). arXiv:2204.01710 (raw image + Canny edges)
[zhang2022] Explainable AI to Detect Image Spam Using CNN — Zhang et al. (2022). arXiv:2209.03166
[visualphishnet2020] VisualPhishNet: Zero-Day Phishing Website Detection by Visual Similarity — Abdelnabi, Krombholz, Fritz (2020). CCS 2020. doi:10.1145/3372297.3417233
[phishpedia2021] Phishpedia: A Hybrid Deep Learning Approach to Visually Identify Phishing Webpages — Lin et al. (2021). USENIX Security 2021.
[li2024knowphish] KnowPhish: LLMs Meet Multimodal Knowledge Graphs for Reference-Based Phishing Detection — Li et al. (2024). USENIX Security 2024. arXiv:2403.02253
[phishagent2025] PhishAgent: A Robust Multimodal Agent for Phishing Webpage Detection — (2025). AAAI 2025. doi:10.1609/aaai.v39i27.35003
[phishsnap2025] PhishSnap: Image-Based Phishing Detection Using Perceptual Hashing — (2025). arXiv:2512.02243
[yuan2019sp] Stealthy Porn: Understanding Real-World Adversarial Images for Illicit Online Promotion — Yuan et al. (2019). IEEE S&P 2019. doi:10.1109/sp.2019.00032 (BYPASS: real adv. images defeat OCR/classifiers)
[jain2021phash] Adversarial Detection Avoidance Attacks: Robustness of Perceptual-Hashing Client-Side Scanning — Jain, Cretu, de Montjoye (2021). arXiv:2106.09820 (USENIX Sec 2022) (pHash BYPASS)
[phash-inversion2024] Perceptual Hash Inversion Attacks on Image-Based Sexual Abuse Removal Tools — (2024). arXiv:2412.06056 (attacks on PDQ/NeuralHash/PhotoDNA/aHash)
[ocr-postcorrection2022] OCR Post-Correction for Detecting Adversarial Text Images — (2022). doi:10.1016/j.jisa.2022.103170
[carlini2017] Towards Evaluating the Robustness of Neural Networks — Carlini, Wagner (2017). IEEE S&P. doi:10.1109/sp.2017.49
[kurakin2018] Adversarial Examples in the Physical World — Kurakin, Goodfellow, Bengio (2018).
[imgpromptinject2026] From Pixels to Prompts: Systematic Study of Image Prompt Injection Attacks — IEEE Computer (2026). https://www.computer.org/csdl/magazine/co/2026/04/11459349/2fj9AyLXAgU (VISION-LLM prompt-injection via in-image text)
[vlmguard2024] VLMGuard: maliciousness-estimation for VLM inputs (Oct 2024). (input-layer defense vs image prompt injection)
[quishing-orgs2025] The Impact of Emerging Phishing Threats: Assessing Quishing and LLM-generated Phishing Emails against Organizations — (2025). doi:10.1145/3708821.3736195
[jailbreak2025] Jailbreaking Generative AI: Multivector Phishing Threats and Transformer-based Defenses — (2025). arXiv:2507.12185
[qrml2025] Comparing Machine Learning and Deep Learning Models for QR Code Phishing Detection — (2025). doi:10.1109/cyber-ai66431.2025.11233820
[uncloak2023] Uncovering the Cloak: A Systematic Review of Techniques Used to Conceal Phishing Websites — (2023). doi:10.1109/access.2023.3293063 (cloaking/geofencing)
[fuzzyocr] FuzzyOcr Plugin — Apache SpamAssassin wiki (~2007). https://cwiki.apache.org/confluence/display/spamassassin/FuzzyOcrPlugin (deployed selective-OCR cascade: OCR only non-spam-scored mail with image attachments; image-hash memoization)
[ms-qr-2024] How Microsoft Defender for Office 365 Innovated to Address QR Code Phishing — Microsoft Security Blog (Nov 2024). https://www.microsoft.com/en-us/security/blog/2024/11/04/how-microsoft-defender-for-office-365-innovated-to-address-qr-code-phishing-attacks/ (escalation trigger + cost NOT disclosed)
[sublime-ocr] OCR for image/QR/screenshot email attacks — Sublime Security (2024-25). https://sublime.security/labels/optical-character-recognition/
[sublime-qr] QR Code Phishing: Decoding Hidden Threats — Sublime Security (2024). https://sublime.security/blog/qr-code-phishing-decoding-hidden-threats/
[barracuda2024] Novel Phishing Techniques: ASCII-based QR Codes and 'Blob' URIs — Barracuda (Oct 2024). https://blog.barracuda.com/2024/10/09/novel-phishing-techniques-ascii-based-qr-codes-blob-uri (OCR/QR gate evasion; ~1 in 20 mailboxes hit Q4 2023)
[open-systems] The Evolution of Quishing: How QR Code Phishing Bypasses Modern Security — Open Systems (2024-25). https://www.open-systems.com/blog/evolution-of-quishing/ (split-QR)
[abnormal-qr] What is QR Code Phishing? — Abnormal AI glossary. https://abnormal.ai/glossary/qr-code-phishing-attacks
[isthisqrsafe] Quishing Complete Guide (2026). https://www.isthisqrsafe.com/learn/quishing-complete-guide
[proofpoint-genai2024] GenAI Is Powering the Latest Surge in Modern Email Threats — Proofpoint (2024). https://www.proofpoint.com/us/blog/email-and-cloud-threats/genai-powering-latest-surge-modern-email-threats

## Mixed-script & bidi / Trojan Source (subagent: mixed-script)
[TrojanSource2021] Trojan Source: Invisible Vulnerabilities — Nicholas Boucher, Ross Anderson (2021). arXiv:2111.00169; CVE-2021-42574, CVE-2021-42694
[UTR36] UTR #36: Unicode Security Considerations — Unicode Consortium. https://unicode.org/reports/tr36/
[MozBug1332714] IDN Phishing using whole-script confusables — Mozilla Bugzilla #1332714 (2017). https://bugzilla.mozilla.org/show_bug.cgi?id=1332714
[ChromiumIDN] IDN in Google Chrome (display policy) — Chromium docs (current). https://chromium.googlesource.com/chromium/src/+/main/docs/idn.md
[MITRE_T1036_002] Masquerading: Right-to-Left Override (T1036.002) — MITRE ATT&CK. https://attack.mitre.org/techniques/T1036/002/
[Hornetsecurity] 20-Year-Old RLO Technique still scamming M365 users — Hornetsecurity (blog) [vendor-blog]
[CVE-2009-3376] Mozilla RLO filename-display spoofing (2009). NVD https://nvd.nist.gov/vuln/detail/CVE-2009-3376
[RedHatRHSB2021-007] Trojan Source (CVE-2021-42574 / -42694) — Red Hat Security Bulletin (2021) [vendor]
[Veit2026] A Comprehensive List of User Deception Techniques in Emails — Veit, Mossano, Länge, Volkamer (2026). arXiv:2604.04926
(cross-refs also used: [uts39], [uax15], [zheng], [badchars] above)

## Zero-width & invisible characters (subagent: zero-width)
[reversecaptcha2026] Reverse CAPTCHA: Evaluating LLM Susceptibility to Invisible Unicode Instruction Injection (2026). arXiv:2603.00164
[cisco2024tag] Understanding and Mitigating Unicode Tag Prompt Injection — Cisco AI blog (2024/2025). hxxps://blogs[.]cisco[.]com/ai/understanding-and-mitigating-unicode-tag-prompt-injection [vendor-blog]
[rehberger2024] ASCII Smuggling and Hidden Prompt Instructions — Johann Rehberger, Embrace The Red (2024-02). hxxps://embracethered[.]com/blog/posts/2024/ascii-smuggling-and-hidden-prompt-instructions/ [vendor-blog]
[butler2025] Smuggling Arbitrary Data Through an Emoji (variation-selector steganography) — Paul Butler (2025). hxxps://paulbutler[.]org/2025/smuggling-arbitrary-data-through-an-emoji/ [vendor-blog]
[avanan2019zwasp] Phishers Use Zero-Width Spaces (Z-WASP) to Bypass Office 365 — Avanan, via SecurityWeek (disclosed 2018-11, MS fix 2019-01-09). hxxps://www[.]securityweek[.]com/phishers-use-zero-width-spaces-bypass-office-365-protections/ [vendor-blog]
[threatpost2010shy] Spammers Using SHY (soft hyphen U+00AD) to Hide Malicious URLs — Threatpost (2010). hxxps://threatpost[.]com/spammers-using-shy-character-hide-malicious-urls-100710/74558/ [vendor-blog]
[sans2025shy] A Phishing with Invisible Characters in the Subject Line (U+00AD via RFC2047) — SANS ISC diary (2025-10-28). hxxps://isc[.]sans[.]edu/diary/32428 [vendor]
[talos2024salting] Hidden Text Salting to Bypass Spam Filters — Cisco Talos, via gbhackers (H2 2024). hxxps://gbhackers[.]com/hackers-use-hidden-text-salting-to-bypass-spam-filters/ [vendor-blog]
[microsoft2021] Trend-spotting email techniques: modern phishing hides in plain sight — Microsoft Security Blog (2021) [vendor-blog]
[naeini2020] A High Capacity Text Steganography Utilizing Unicode Zero-Width Characters (2020). doi:10.1109/ithings-greencom-cpscom-smartdata-cybermatics50389.2020.00116
[textstegreview2021] A Review on Text Steganography Techniques (2021). doi:10.3390/math9212829
[xgboost2026] Detecting Zero-Width Characters Obfuscated in Phishing URLs using XGBOOST (2026). doi:10.56211/hanif.v3i1.56
[promptreview2026] Prompt Injection Attacks in LLMs and AI Agent Systems: A Comprehensive Review (2026). doi:10.3390/info17010054
(cross-refs also used: [badchars], [spotlight-2024], [vbsf] above)

## QR / link cloaking & redirect chains (subagent: qr-link)
[sharevski22] Gone Quishing: A Field Study of Phishing with Malicious QR Codes — Sharevski, Devine, Pieroni, Jachim (2022). arXiv:2204.04086
[geisler24] Hooked: A Real-World Study on QR Code Phishing — Geisler, Pöhn (2024). arXiv:2407.16230
[weinz25] The Impact of Emerging Phishing Threats: Quishing and LLM-generated Phishing Emails against Organizations — Weinz, Zannone, Allodi, Apruzzese (2025). arXiv:2505.12104
[trad25] Detecting Quishing Attacks with ML Through QR Code Analysis — Trad, Chehab (2025). arXiv:2505.03451
[akram26] ALFA: A Safe-by-Design Approach to Mitigate Quishing via Fancy QR Codes — Akram, Sood, Ul Hassan, Thiruvady (2026). arXiv:2601.06768
[nejati26] CIC-Trap4Phish: Unified Multi-Format Dataset for Phishing/Quishing Attachment Detection — Nejati, Rabbani, Ghorbani, Dadkhah (2026). arXiv:2602.09015
[zhang21] CrawlPhish: Large-scale Analysis of Client-side Cloaking Techniques in Phishing — Zhang, Oest, Cho, Doupé, Ahn et al. (2021). IEEE S&P 2021, doi:10.1109/SP40001.2021.00021
[nakano25] PhishParrot: LLM-Driven Adaptive Crawling to Unveil Cloaked Phishing Sites — Nakano, Koide, Chiba (2025). arXiv:2508.02035
[oest19] PhishFarm: Measuring Effectiveness of Evasion Techniques against Browser Phishing Blacklists — Oest et al. (2019). doi:10.1109/SP.2019.00049
[oest20] PhishTime: Continuous Longitudinal Measurement of Anti-Phishing Blacklist Effectiveness — Oest et al. (2020). USENIX Security 2020
[le18] URLNet: Learning a URL Representation with Deep Learning for Malicious URL Detection — Le, Pham, Sahoo, Hoi (2018). arXiv:1802.03162
[lei20] Advanced Evasion Attacks and Mitigations on Practical ML-Based Phishing Website Classifiers — Lei, Chen, Fan, Song, Liu (2020). arXiv:2004.06954
[kim22] Phishing URL Detection: A Network-based Approach Robust to Evasion — Kim, Park, Hong, Kim (2022). arXiv:2209.01454
[unit42-24] Evolution of Sophisticated Phishing Tactics: The QR Code Phenomenon — Palo Alto Unit 42 (2024). hxxps://unit42[.]paloaltonetworks[.]com/qr-code-phishing/ [vendor-blog]
[barracuda24] Threat Spotlight: The evolving use of QR codes in phishing attacks — Barracuda (2024-10-22) [vendor-blog]
[levelblue25] Weaponizing Safe Links: Abuse of Multi-Layered URL Rewriting — SpiderLabs/LevelBlue (2025). hxxps://levelblue[.]com/ [vendor-blog]
[talos24] State-of-the-art phishing: MFA bypass (Evilginx/AiTM) — Cisco Talos (2024). hxxps://blog[.]talosintelligence[.]com/state-of-the-art-phishing-mfa-bypass/ [vendor-blog]
[abnormal24] QR Code Phishing Attacks (C-suite ~42x data) — Abnormal AI (2024) [vendor-blog]
(cross-refs also used: [phishdebate], [uncloak2023] above)

## Links / cloaking / body-rewriting (subagent: links-cloaking-rendering)
[invernizzi16] Cloak of Visibility: Detecting When Machines Browse a Different Web — Invernizzi, Thomas, Kapravelos, Comanescu, McCoy, Bursztein, et al. (2016). IEEE S&P 2016, doi:10.1109/SP.2016.50; hxxps://research.google/pubs/pub45581/ [CORE cite for differential-fetch cloaking detection, L2b]
[gmailproxy13] Gmail Deploys Image Proxy Servers (fetch-once, cache, re-serve single copy) — Word to the Wise (2013-12). hxxps://www.wordtothewise[.]com/2013/12/gmail-deploys-image-proxy-servers [vendor/industry — precedent for the "fetch-and-re-serve" defense, L3]
[valsorda13] How the New Gmail Image Proxy Works and What This Means for You — Filippo Valsorda (2013). hxxps://words.filippo[.]io/how-the-new-gmail-image-proxy-works-and-what-this-means-for-you/ [technical writeup, L3]
(cross-refs also used: [zhang21]=CrawlPhish, [nakano25]=PhishParrot, [modernphish]=2506.20228, [TrojanSource2021], [levelblue25]=Safe Links rewriting, [oest19]=PhishFarm above)

## Cost-tiered cascade / model routing (subagent: cost-tiered-cascade)
[frugalgpt] FrugalGPT: How to Use LLMs While Reducing Cost and Improving Performance — Chen, Zaharia, Zou (2023). arXiv:2305.05176
[ucci] UCCI: Calibrated Uncertainty for Cost-Optimal LLM Cascade Routing — Kotte (2026). arXiv:2605.18796 [FLAGGED single-source 2026 preprint]
[scope] Models Under SCOPE: Scalable and Controllable Routing via Pre-hoc Reasoning — Cao et al. (2026). arXiv:2601.22323 [FLAGGED single-source 2026]
[violajones] Rapid Object Detection using a Boosted Cascade of Simple Features — Viola & Jones (2001). CVPR, doi:10.1109/CVPR.2001.990517
[cascadercnn] Cascade R-CNN: Delving into High Quality Object Detection — Cai & Vasconcelos (2019). arXiv:1906.09756
[ee-survey] Adaptive Inference through Early-Exit Networks — Laskaridis, Kouris, Lane (2021). arXiv:2106.05022
[ee-nlp] A Survey of Early Exit DNNs in NLP — Bajpai & Hanawal (2025). arXiv:2501.07670
[cstree] Cost-Sensitive Tree of Classifiers — Xu et al. (2013). arXiv:1210.2771
[budgetfa] Sequential Cost-Sensitive Feature Acquisition — Contardo et al. (2016). arXiv:1607.03691
[opplearn] Opportunistic Learning: Budgeted Cost-Sensitive Learning from Data Streams — Kachuee et al. (2019). arXiv:1901.00243
[costtax] Types of Cost in Inductive Concept Learning — Turney (2002). arXiv:cs/0212034
[biggio] Evasion Attacks against Machine Learning at Test Time — Biggio et al. (2013). arXiv:1708.06131
[nguyen] Deep Neural Networks are Easily Fooled: High Confidence Predictions for Unrecognizable Images — Nguyen, Yosinski, Clune (2015). CVPR, arXiv:1412.1897
[msp] A Baseline for Detecting Misclassified and Out-of-Distribution Examples (softmax confidence) — Hendrycks & Gimpel (2017). arXiv:1610.02136
[guo] On Calibration of Modern Neural Networks — Guo et al. (2017). arXiv:1706.04599
[ovadia] Can You Trust Your Model's Uncertainty? (calibration under dataset shift) — Ovadia et al. (2019). arXiv:1906.02530
[morphence] Morphence: Moving Target Defense Against Adversarial Examples — Amich & Eshete (2021). arXiv:2108.13952
[mtdmalware] Effectiveness of Moving Target Defenses for Adversarial Attacks in ML Malware Detection — Rashid & Such (2023). arXiv:2302.00537
[ddosmtd] A Cost-effective Shuffling Method against DDoS using MTD — Zhou et al. (2019). arXiv:1903.10102
[ensmalware] Adversarial Deep Ensemble: Evasion Attacks and Defenses for Malware Detection — Li & Li (2020). arXiv:2006.16545
[vbsf] VBSF: A Visual-Based Spam Filtering Technique for Obfuscated Emails — Hossary & Tomasin (2025). arXiv:2512.23788
[kidsnanny] KidsNanny: Two-Stage Multimodal Content Moderation (ViT→OCR+LLM) — Panchal et al. (2026). arXiv:2603.16181 [FLAGGED single-source 2026; cost ratios directionally corroborated by fuzzyocr/dredze2007]
[evomail] EvoMail: Self-Evolving Cognitive Agents for Adaptive Spam/Phishing Defense — Huang et al. (2025). arXiv:2509.21129
[llmpea] Phishing Email Detection Using LLMs (evasion via prompt injection/refinement) — Hasan et al. (2025). arXiv:2512.10104
[keepnet] QR Code Phishing / Quishing Trends & Statistics — Keepnet (2024–2025). hxxps://keepnetlabs[.]com/blog/ [vendor-blog]
[modernphish] Measuring Modern Phishing Tactics: A Quantitative Study of Body Obfuscation Prevalence, Co-occurrence, and Filter Impact — Dalmiere, Zhou, Auriol, Nicomette, Marchand (2025). arXiv:2506.20228 [386 emails; text-in-image 47%, base64 31.2%, invalid-HTML 28.8%; base64+text-in-image → lower antispam scores, R²=0.486 p<0.001; concludes multi-modal defence needed — CORE cite for §D3-bypass]
[gabagool-splitqr] Split QR Codes Evade Email Filters (Gabagool phishing kit) — SQ Magazine (2026). hxxps://sqmagazine[.]co[.]uk/split-qr-phishing-evades-email-filters/ [vendor/news]
[sublime-qrevasion] Modern QR Code Phishing Evasion Tactics You Should Know About — Sublime Security (2025). hxxps://sublime[.]security/blog/modern-qr-code-phishing-evasion-tactics-you-should-know-about/ [vendor-blog; split/nested/CSS-assembled QR + render-based detection]
[isc-htmlqr] A Phishing Campaign with QR Codes Rendered Using an HTML Table (imageless QR, each module a table cell) — SANS Internet Storm Center diary 32606 (2025). hxxps://isc.sans[.]edu/diary/32606
(cross-refs also used: [athalye-2018]=obfuscated-gradients, [sublime-qr], [barracuda2024], [ms-qr-2024] above)
