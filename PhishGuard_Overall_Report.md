# PhishGuard — Project Report
### AI-Powered Phishing Detection Browser Extension
---

## 1. Introduction

Every day, billions of people use the internet to check their bank accounts, pay bills, shop online, and communicate with others. The internet has made life significantly more convenient — but it has also created a dangerous playground for criminals. One of the most common and damaging crimes on the internet today is **phishing**.

Phishing is the act of tricking a person into visiting a fake website that looks exactly like a real one — a fake bank, a fake government portal, a fake email login — with the goal of stealing their passwords, personal details, or money.

**PhishGuard** is a software tool built to fight this problem. It is a browser extension — a small program that runs inside your web browser (like Google Chrome or Microsoft Edge) — that automatically detects and blocks phishing websites in real time, before the user even sees them. It uses Artificial Intelligence (AI) to recognize the patterns of phishing websites, even ones that have never been seen before.

What makes PhishGuard particularly significant is its approach: it works entirely inside your browser, never sending any of your browsing data to a server or company. It is private, fast, free, and requires no technical knowledge to use.

---

## 2. The Problem — Phishing in the Modern World

### 2.1 What is Phishing?

The term "phishing" is derived from the word "fishing" — because criminals cast a bait (a fake email, a fake SMS, a fake link) and wait for unsuspecting users to take the bite.

A typical phishing attack works like this:
- A criminal creates a website that looks exactly like your bank, your email provider, or a popular shopping site
- They send you a link to it via email, SMS, WhatsApp, or even an advertisement
- You visit the link, think you are on the real website, and type in your username, password, or credit card details
- The criminal now has your login credentials and can access your real accounts

### 2.2 How Serious Is the Problem?

Phishing is not an occasional nuisance. It is a global epidemic:

- Over **3.4 billion** phishing emails are sent every single day worldwide
- A new phishing website is created **every 20 seconds**
- **90% of all data breaches** begin with a phishing attack
- Phishing costs individuals and businesses over **$3.5 billion** every year
- Even educated, experienced professionals fall victim — phishing is designed to exploit psychology, not ignorance

### 2.3 Why Existing Tools Are Not Enough

Most people assume their browser or antivirus already protects them from phishing. To some degree they do, but with critical limitations:

**Blocklists are too slow.** Tools like Google Safe Browsing maintain lists of known phishing sites. But a new phishing site can deceive thousands of people in the first few hours before it gets reported, reviewed, and added to any blocklist. This window is exactly when criminals do the most damage.

**Cloud-based scanners compromise privacy.** Some tools work by sending every URL you visit to a company's servers for checking. This means a third party knows every website you visit — which is itself a serious privacy concern.

**Tunnel-based phishing bypasses traditional defences.** Criminals have discovered that by hosting their fake websites behind free internet tunneling services (such as Cloudflare tunnels), they can hide the true location of their servers and bypass IP-based blocking systems entirely.

**Existing tools don't explain the danger.** Most security tools simply say "Dangerous site" with no explanation. Users learn nothing, and the same mistakes are repeated.

---

## 3. What is PhishGuard?

PhishGuard is a **browser extension** built on Google's Manifest V3 standard — the latest, most secure framework for building browser extensions. It runs inside Chrome, Edge, Brave, and other Chromium-based browsers.

Its core purpose is simple: **protect the user from phishing websites before they can cause harm.**

It does this through a combination of:
1. Hardcoded security rules (for known attack patterns)
2. An on-device AI model (for pattern-based threat detection)
3. Real-time page structure analysis (for hidden HTML-level threats)

Everything runs inside the browser. No data is ever transmitted externally.

---

## 4. How PhishGuard Works

### 4.1 The Moment You Navigate

The instant a user clicks a link or types a web address and presses enter, PhishGuard intercepts the navigation. This happens before the website loads — before any content, images, or code from that site reaches the user's browser.

### 4.2 Layer 1 — Instant Rule Check

The first thing PhishGuard checks is a set of hardcoded rules:

- **Is it a restricted browser page?** Internal browser URLs (like `chrome://settings`) are skipped.
- **Is it on the user's personal allowlist?** Sites the user has explicitly approved are let through.
- **Is it a Cloudflare tunnel?** Any URL ending in `.trycloudflare.com` or `.trycloudflare.net` is **immediately blocked** with a risk score of 100%. Legitimate businesses virtually never use temporary tunnel services for actual websites. These are a hallmark of criminal phishing infrastructure.

If a site passes all three rule checks, it moves to the AI layer.

### 4.3 Layer 2 — Artificial Intelligence Analysis

This is the core of PhishGuard. The AI looks at **27 different measurable signals** extracted from the website's URL and analyzes them together to produce a **Threat Score** between 0% and 100%.

Some of the signals the AI examines:

| Signal | What It Detects |
|---|---|
| URL length | Phishing URLs are often unusually long to hide the real domain |
| Number of hyphens | Fake sites use hyphens excessively (e.g., `secure-paypal-login-verify.xyz`) |
| Suspicious domain endings | `.xyz`, `.top`, `.tk`, `.ml` are popular with criminals because they are free or very cheap |
| Suspicious keywords | Words like `login`, `verify`, `secure`, `bank`, `confirm` in the URL are a red flag |
| Character randomness (entropy) | Random-looking web addresses signal auto-generated phishing domains |
| IP address as hostname | Real businesses use domain names; criminals sometimes use raw IP addresses |
| Tunnel service keywords | Presence of known tunneling terms (ngrok, cloudflare, localtunnel) in the host |
| Homograph detection | Criminals use characters from other alphabets (e.g., Cyrillic) that look identical to English letters to fool users |
| Subdomain depth | Deep nesting like `login.verify.paypal.confirm.xyz` is a classic trick |
| Presence of HTTPS | Lack of a security certificate on a login page is deeply suspicious |

After analyzing all 27 signals, the AI comes to a conclusion:

- **Below 30%** → Safe (green) — allowed through, no action taken
- **30–84%** → Suspicious (yellow) — logged, user is informed
- **85–95%** → High Risk (orange) → Safe Mode activates to add extra protections
- **96–100%** → **BLOCKED** → user is redirected to PhishGuard's warning page

The AI model that does this analysis is a **Random Forest** — an algorithm where 100 independent decision-making trees each vote on whether a URL is phishing or legitimate. The final score is the average of all 100 votes. This voting system makes the AI far more reliable than any single decision tree could be.

### 4.4 Layer 3 — Page Structure (DOM) Analysis

Even after the AI check, PhishGuard does one more layer of inspection once the page has loaded — it reads the page's underlying code (called the DOM — Document Object Model) and looks for two critical red flags:

**Red Flag 1 — Password field on an unencrypted connection:** Any page that asks for a password but doesn't use HTTPS (the secure protocol shown by the padlock icon in your browser) is immediately suspicious. Legitimate websites never ask for passwords without proper encryption.

**Red Flag 2 — Form that submits data to a different website:** If a page has a form (like a login box), but when submitted, the data is sent to a completely different domain than the one you're on — this is the technical mechanism behind credential theft. PhishGuard detects and reports this.

If the DOM analysis score reaches 80% or higher, the page is blocked even if the AI gave it a moderate score. These two layers protect each other's blind spots.

---

## 5. What Users Experience

### 5.1 Day-to-Day — Nothing

For the vast majority of everyday browsing, users experience nothing unusual. PhishGuard operates completely in the background, silently scanning every website and finding them safe. The user notices no delay, no popups, no interruptions.

### 5.2 When a Threat is Detected — The Block Page

When PhishGuard identifies a high-probability phishing site, the user is redirected to a clear, red warning page that includes:

- The dangerous URL in a visible box
- A plain-English explanation of **why specifically** the site was blocked:
  - If it was a Cloudflare tunnel: the page explains how criminals use tunnels to hide phishing sites
  - If it was a suspicious DOM structure: the page explains credential harvesting
  - If it was the AI model: the page explains URL-based phishing anti-patterns
- A **"Go Back to Safety"** button
- An **"Allow this site"** button with a confirmation step — giving the user full control in case of a false alarm

This educational approach is intentional. Every blocked site is an opportunity for the user to learn something real about how phishing works.

### 5.3 The Popup Panel

Clicking the PhishGuard icon in the browser toolbar opens a compact control panel showing:

- An animated **speedometer-style gauge** sweeping from green to red indicating the current page's threat level
- A **status badge** — SAFE, SUSPICIOUS, or DANGER
- A **list of detected red flags** (e.g., "Encrypted Tunnel Detected", "High-Risk TLD", "Visual Homograph")
- A **Safe Mode toggle** for manual extra protection
- A **Dashboard button** to access full analytics

### 5.4 The Security Dashboard

The Dashboard is a full analytics page that provides:

- **Sites Scanned** — total count of websites analyzed
- **Threats Prevented** — total blocked sites
- **True Positives** — real threats correctly blocked
- **False Positives** — safe sites incorrectly blocked (and subsequently allowed by the user)
- **True Negatives** — safe sites correctly allowed
- **False Negatives** — threats reported by the user that the AI missed
- **Activity Log** — a detailed table of the last 50 website visits with timestamps, risk scores, and detected flags

---

## 6. The Technology Stack

| Technology | Role | Why Chosen |
|---|---|---|
| **JavaScript (ES6+)** | All browser-side logic: detection, UI, AI inference | Only language that runs natively inside a browser |
| **Python (scikit-learn)** | Training the AI model offline | Industry-standard for machine learning; rich ecosystem |
| **Random Forest Algorithm** | Core AI for phishing classification | Fast, accurate, explainable, works without a GPU |
| **Chrome Extension API (MV3)** | Framework for the browser extension | Latest official Google standard for secure extensions |
| **chrome.storage.local** | Local data storage | Keeps all data on the user's device — zero cloud dependency |
| **HTML + Vanilla CSS** | UI for popup, dashboard, and block page | Clean, no external dependencies, fast loading |
| **Google Fonts (Outfit)** | Typography | Modern, readable, professional appearance |
| **JSON (model.json)** | Serialized AI model format | Browser-readable, no additional libraries needed |

The AI model is trained once using Python, exported as a JSON file (~3.9 MB), and bundled inside the extension. The JavaScript inference engine (`model_predict.js`) then runs this model entirely within the browser — no external computation required.

---

## 7. Key Features Summary

| Feature | Description |
|---|---|
| **Real-Time Phishing Detection** | Every URL analyzed in under 20 milliseconds |
| **Zero-Day Threat Detection** | Catches brand-new phishing sites never seen in any blocklist |
| **Cloudflare Tunnel Blocking** | Immediate block of `.trycloudflare.com` and similar tunnel domains |
| **Homograph Attack Detection** | Detects fake domains using foreign-alphabet characters that look like English |
| **DOM-Level Analysis** | Inspects page HTML structure for credential harvesting patterns |
| **Safe Mode** | Adds red borders to password fields and disables autofill on suspicious pages |
| **Educational Block Page** | Explains in plain English why a site was blocked |
| **User Allowlist** | Users can permanently trust specific domains — they always retain control |
| **False Positive Reporting** | Users can mark incorrect blocks; tracked in analytics |
| **Full Analytics Dashboard** | TP/FP/TN/FN tracking and full scan history |
| **Privacy-First Architecture** | Zero data transmitted — all processing and storage is local |
| **Safe Domain Shortcircuit** | Major trusted domains (Google, GitHub, etc.) skip AI entirely for speed |
| **LRU Prediction Cache** | Recently analyzed URLs are cached to avoid redundant computation |

---

## 8. Impact on Society

### 8.1 Protecting Vulnerable Users

The people most at risk from phishing are those least able to defend themselves: elderly users unfamiliar with digital deception, students and young adults who click quickly without thinking, and first-time internet users in developing economies. PhishGuard requires no technical knowledge — it works automatically the moment it is installed, acting as a silent guardian for those who need it most.

### 8.2 Closing the Speed Gap

The most dangerous moment in a phishing attack is the window between when the criminal deploys their fake site and when that site gets added to security blocklists. This gap can be hours or even days. During this window, thousands of people can unknowingly hand over their credentials. PhishGuard's AI closes this window entirely — it can detect a phishing site on its very first second of operation.

### 8.3 Economic Protection

With over $3.5 billion lost to phishing annually, tools like PhishGuard have a direct, measurable economic impact. For an individual whose account is drained, the financial and emotional damage can be devastating. For businesses, phishing is often the entry point for ransomware attacks that cost millions.

### 8.4 A Privacy-Respecting Model

PhishGuard demonstrates that effective cybersecurity does not require users to surrender their privacy. This is not merely a product feature — it is an important statement about how security software should be designed. Security tools that collect browsing history create their own risks: data breaches, government surveillance, and commercial exploitation.

### 8.5 Digital Literacy Through Education

Every time PhishGuard blocks a site and explains why, the user learns something real. Over time, users become more aware of phishing patterns — more likely to notice suspicious URLs independently, more skeptical of urgent emails, more cautious with personal information. PhishGuard contributes to a broader improvement in digital literacy.

---

## 9. Advantages

1. **No Learning Curve** — Users install it and forget it. There is nothing to configure, no settings to manage.
2. **Works on Brand-New Threats** — Does not depend on known bad-site lists; uses AI pattern recognition.
3. **Complete Privacy** — The only security tool that protects you without watching you.
4. **Multi-Layer Defence** — Three independent detection systems make it extremely hard to bypass.
5. **Transparent Decisions** — Always tells users exactly why a site was blocked.
6. **User Remains in Control** — The allowlist and override system means users are never locked out of sites they trust.
7. **Performance Optimized** — Results in under 20ms; cached predictions; safe domain shortcuts.
8. **Honest Analytics** — Full TP/FP/TN/FN tracking lets users see exactly how well the AI is performing.
9. **Zero Cost** — No subscription, no account, no payment.
10. **Open and Auditable** — Every line of code is readable; no hidden behaviour.

---

## 10. Current Limitations

| Limitation | Explanation |
|---|---|
| **Browser Only** | Does not protect mobile apps, desktop apps, email clients, or SMS |
| **Chrome/Edge Only** | Firefox and Safari do not support extensions the same way; not yet ported |
| **Visual Clone Limitation** | A pixel-perfect copy of a real site at a convincing URL could potentially evade detection |
| **AI is Not 100% Accurate** | False positives (blocking safe sites) and false negatives (missing some threats) occur |
| **No Email Scanning** | Links inside email applications are not scanned unless clicked in the browser |
| **No QR Code Protection** | QR codes that lead to phishing sites are not currently detected before the browser loads the URL |

---

## 11. Future Scope

PhishGuard is built with a clear architectural foundation that can be extended significantly:

- **Email link scanner** — scanning URLs before they are clicked in email applications
- **QR code safety checking** — detecting phishing URLs embedded in QR codes
- **Visual similarity detection** — using computer vision to compare a website's appearance to known brands
- **Cross-browser support** — expanding to Firefox and Safari
- **Continuous model retraining** — using the anonymously collected scan data to improve AI accuracy over time
- **Enterprise / school dashboard** — allowing IT administrators to monitor phishing attempts across an organization or institution
- **Mobile browser support** — protecting users on Android and iOS
- **Multilingual phishing detection** — extending keyword features to cover phishing in Hindi, Tamil, Telugu, and other regional languages

---

## 12. Conclusion

PhishGuard addresses one of the most serious and pervasive threats in the digital world — phishing — with a technically sound, privacy-respecting, and user-friendly approach. By combining Artificial Intelligence, real-time page analysis, and hardcoded security rules into a single lightweight browser extension, it delivers a level of protection that traditional blocklist-based tools cannot match.

Its most important distinction is its philosophy: **security should not require sacrifice.** Users should not have to choose between being protected and being private. They should not need technical expertise to stay safe online. And they should not have to pay for protection against criminals.

In a landscape where phishing attacks are becoming faster, smarter, and more psychologically sophisticated — and where the consequences of being tricked grow ever more severe — PhishGuard represents both a practical tool and a proof of concept for what security software should aspire to be.

> *PhishGuard — Because your safety on the internet should never depend on how much you already know about cybersecurity.*

---

**Project:** PhishGuard v1.0
**Type:** Browser Extension (Chromium — Manifest V3)
**Language:** JavaScript + Python
**AI Model:** Random Forest (100 Trees, 27 Features)
**Privacy:** 100% On-Device — Zero External Data Transmission
**Cost:** Free & Open Source
