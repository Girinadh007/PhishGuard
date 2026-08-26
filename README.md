# PhishGuard 🛡️

PhishGuard is a blazing-fast, privacy-first Chrome Extension that detects and blocks phishing websites in real-time. Instead of relying on slow cloud servers or external APIs, PhishGuard runs a fully localized **Random Forest Machine Learning Model** directly inside your browser. 

This guarantees zero-latency protection, zero privacy leaks (your browsing history never leaves your device), and complete offline capability.

## ✨ Features
- **Local AI Inference**: Evaluates URLs in `< 0.1ms` using a lightweight Random Forest model.
- **Top 100k Allowlist**: Automatically bypasses scanning for the top 100,000 most trusted domains worldwide (0ms interception time), virtually eliminating false positives.
- **Privacy-First**: No external API calls. Your browsing data is never sent to a server.
- **Heuristic Engine**: Extracts 15+ features from URLs locally (entropy, tunneling services, homograph attacks, suspicious TLDs, etc.).

## 📊 Benchmark Results (on 450,000+ URLs)
We rigorously benchmarked PhishGuard against a massive real-world dataset. The extension boasts:
- **F1 Score**: 96.94%
- **Precision**: 99.97%
- **Recall (Detection Rate)**: 94.09%
- **AI Inference Time**: 0.054ms per URL
- **Allowlist Check Time**: 0.001ms per URL
- **Memory Footprint**: ~19.39 MB

---

## 🚀 Installation (For Regular Users)
You do not need to install Node.js or Python to use this extension. 

1. Download or clone this repository to your computer.
2. Open your Chromium-based browser (Chrome, Edge, Brave) and go to `chrome://extensions/`.
3. Enable **Developer mode** in the top right corner.
4. Click **Load unpacked** and select the `PhishGuard` folder.
5. The extension is now active and protecting your browsing!

---

## 🛠️ Development & Benchmarking
If you wish to modify the code, run the performance benchmarks, or retrain the AI model, you will need some development tools.

### Requirements
- **Node.js** (For benchmarking and allowlist generation)
- **Python 3** (Optional, only for training a new model)

### Running the Benchmarks
To replicate the accuracy and speed metrics shown above:
1. Ensure `node` is installed.
2. Run the benchmark script:
```bash
node scripts/benchmark.js
```
*(Note: Ensure you have the `phishing_dataset.csv` in the `model/` directory to evaluate the F1 score).*

### Rebuilding the Allowlist
If you have a new `top-1m.csv` and want to extract the top 100,000 domains into the compressed extension format:
```bash
node scripts/build_allowlist.js
```

### Retraining the Model (Optional)
If you want to train a new Random Forest model from scratch:
1. Ensure Python 3 is installed.
2. Install dependencies: `pip install scikit-learn pandas`
3. Run the export script:
```bash
python train_export_rf.py
```
This will generate a new `model.json` file used by the extension.
