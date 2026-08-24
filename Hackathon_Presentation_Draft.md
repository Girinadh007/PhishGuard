# PhishGuard: Hackathon Idea Submission

*Aligned with Cognizant Idea Submission Template (WHY, HOW, WHAT).*

---

## 1. WHY - Explain the Problem

**The Crisis:**
*   **Massive Scale:** 3B+ malicious emails daily; drives 36% of data breaches.
*   **High Financial Impact:** $25B in global losses; average breach costs $4.8M.
*   **The Zero-Day Gap:** 82.6% of phishing is AI-generated, easily bypassing legacy blocklists. Median click time is just 21 seconds.
*   **Privacy Risks:** Cloud-based analysis compromises browsing data privacy and adds latency.

**Target Stakeholders:**
*   **Consumers (B2C):** Need seamless, zero-config protection from financial fraud.
*   **Enterprises (B2B):** Require robust "zero-day" threat prevention to protect networks.
*   **Telcos/ISPs:** Need to reduce customer churn caused by security/fraud incidents.

---

## 2. HOW - Explain the Solve

**Solution Overview:**
PhishGuard is a **privacy-first, edge-AI browser extension** that detects and blocks zero-day phishing sites in real-time, directly on the user's device.

**Technical Architecture:**
*   **Platform:** Manifest V3 extension (Chrome, Edge). Uses background service workers (`chrome.webNavigation`).
*   **Edge-AI Model:** Lightweight ML model runs natively in-browser on local compute.
*   **100% Offline Inference:** No cloud dependency; browsing routing data never leaves the device.

**Innovation & Tech Appeal:**
*   **Proactive Security:** Behavioral AI identifies new threats without waiting for blocklist updates.
*   **Cost Efficiency:** Eliminates expensive cloud GPU requirements for inference.
*   **Absolute Privacy:** Solves the security-vs-privacy tradeoff via edge computing.

---

## 3. WHAT - Value Proposition

**Primary Benefits:**
*   **Zero Latency Security:** Instant blocking without disrupting the user experience or network speeds.
*   **Operational Cost Savings:** No recurring cloud inference costs; scalable from 10 to 10M users effortlessly.
*   **Business Impact:** Prevents costly corporate data breaches and IT credential theft.
*   **Customer Retention (Telecom/ISP):** A high-value security add-on that builds trust and reduces service churn.
*   **Social Good:** Protects vulnerable internet users from devastating financial fraud.

---

## 4. Additional Context | Financials & Timelines

### Investments
*   **Infrastructure:** Near-zero. Static hosting only; no live API/GPU cloud.
*   **Development:** Developer hours for edge-optimized ML model training and compression.
*   **Operational Friction:** Minimal. Simple extension install with zero network re-engineering.

### Returns & ROI
*   **Massive Margins:** Decentralized compute eliminates cloud GPU overhead.
*   **Revenue Potential:** B2B enterprise licensing and B2B2C ISP partnerships.
*   **Productivity:** Drastically cuts IT security support tickets.

### Timelines
*   **Time to Solve:** Instant protection upon installation.
*   **M1:** Core ML model training & browser optimization.
*   **M2:** UI/UX and network intercept logic (Manifest V3).
*   **M3:** Beta testing & false-positive tuning.
*   **M4:** Launch & scale.
