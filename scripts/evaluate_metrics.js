const fs = require('fs');
const readline = require('readline');
const path = require('path');
const vm = require('vm');

async function evaluate() {
  console.log("Loading model and dataset...");
  const modelPath = path.join(__dirname, '..', 'model', 'model.json');
  const rawModel = fs.readFileSync(modelPath, 'utf8');
  const modelJson = JSON.parse(rawModel);

  const scriptPath = path.join(__dirname, 'model_predict.js');
  let scriptCode = fs.readFileSync(scriptPath, 'utf8');
  scriptCode = scriptCode.replace(
    /export\s*\{[^}]+\};?/g,
    'module.exports = { loadModel, extractFeaturesFromUrl, predictProbability };'
  );

  const moduleObj = { exports: {} };
  const context = vm.createContext({
    module: moduleObj,
    exports: moduleObj.exports,
    fetch: async () => ({ json: async () => modelJson }),
    URL: URL,
    Int16Array: Int16Array,
    Int32Array: Int32Array,
    Float32Array: Float32Array,
    Map: Map,
    Math: Math,
    Date: Date,
    console: console
  });

  vm.runInContext(scriptCode, context);
  const { loadModel, extractFeaturesFromUrl, predictProbability } = moduleObj.exports;
  await loadModel(modelJson);

  const datasetPath = path.join(__dirname, '..', 'phishing_dataset.csv');
  const fileStream = fs.createReadStream(datasetPath);
  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity
  });

  let total = 0;
  let tp = 0, fp = 0, tn = 0, fn = 0;
  let isHeader = true;
  const startTime = Date.now();

  for await (const line of rl) {
    if (isHeader) {
      isHeader = false;
      continue;
    }
    if (!line.trim()) continue;

    const lastCommaIdx = line.lastIndexOf(',');
    if (lastCommaIdx === -1) continue;

    const url = line.substring(0, lastCommaIdx);
    const rawLabel = line.substring(lastCommaIdx + 1).trim().toLowerCase();

    let actual = -1;
    if (rawLabel === 'phishing' || rawLabel === '1') actual = 1;
    else if (rawLabel.startsWith('legitimate') || rawLabel === '0') actual = 0;
    else continue;

    let feat, prob;
    try {
      feat = extractFeaturesFromUrl(url);
      prob = predictProbability(feat, null);
    } catch (e) {
      continue;
    }
    const predicted = prob >= 0.5 ? 1 : 0;

    if (actual === 1 && predicted === 1) tp++;
    else if (actual === 0 && predicted === 1) fp++;
    else if (actual === 0 && predicted === 0) tn++;
    else if (actual === 1 && predicted === 0) fn++;

    total++;
    if (total % 50000 === 0) {
      process.stdout.write(`Evaluated ${total.toLocaleString()} URLs...\r`);
    }
  }

  const durationSec = (Date.now() - startTime) / 1000;
  const accuracy = ((tp + tn) / total) * 100;
  const precision = ((tp) / (tp + fp)) * 100;
  const recall = ((tp) / (tp + fn)) * 100;
  const specificity = ((tn) / (tn + fp)) * 100;
  const f1 = (2 * (precision * recall) / (precision + recall));
  const fpr = (fp / (fp + tn)) * 100;

  console.log("\n========================================================");
  console.log("   📊 PHISHGUARD RESEARCH PAPER EVALUATION RESULTS     ");
  console.log("========================================================");
  console.log(`Evaluated Dataset:      ${total.toLocaleString()} URLs`);
  console.log(`Evaluation Time:        ${durationSec.toFixed(2)} seconds`);
  console.log(`Throughput:             ${Math.round(total / durationSec).toLocaleString()} URLs/sec\n`);
  console.log("--- CONFUSION MATRIX ---");
  console.log(`True Positives (TP):    ${tp.toLocaleString().padStart(8)}  (Correctly detected phishing)`);
  console.log(`True Negatives (TN):    ${tn.toLocaleString().padStart(8)}  (Correctly identified safe)`);
  console.log(`False Positives (FP):   ${fp.toLocaleString().padStart(8)}  (Safe incorrectly flagged)`);
  console.log(`False Negatives (FN):   ${fn.toLocaleString().padStart(8)}  (Phishing missed)\n`);
  console.log("--- CLASSIFICATION METRICS (FOR RESEARCH PAPER) ---");
  console.log(`Accuracy:               ${accuracy.toFixed(2)}%`);
  console.log(`Precision:              ${precision.toFixed(2)}%`);
  console.log(`Recall (Sensitivity):   ${recall.toFixed(2)}%`);
  console.log(`Specificity:            ${specificity.toFixed(2)}%`);
  console.log(`F1-Score:               ${f1.toFixed(2)}%`);
  console.log(`False Positive Rate:    ${fpr.toFixed(2)}%`);
  console.log("========================================================\n");

  console.log("--- MARKDOWN TABLE (FOR RESEARCH_PAPER.md) ---");
  console.log("| Metric | Value |");
  console.log("| :--- | :--- |");
  console.log(`| Total Evaluated URLs | ${total.toLocaleString()} |`);
  console.log(`| Accuracy | ${accuracy.toFixed(2)}% |`);
  console.log(`| Precision | ${precision.toFixed(2)}% |`);
  console.log(`| Recall / Sensitivity | ${recall.toFixed(2)}% |`);
  console.log(`| Specificity | ${specificity.toFixed(2)}% |`);
  console.log(`| F1-Score | ${f1.toFixed(2)}% |`);
  console.log(`| False Positive Rate (FPR) | ${fpr.toFixed(2)}% |`);
  console.log(`| Inference Latency | ${(durationSec / total * 1000).toFixed(4)} ms/URL |`);
  console.log("");

  console.log("--- LATEX TABLE (FOR IEEE PAPER .TEX) ---");
  console.log("\\begin{table}[htbp]");
  console.log("\\caption{PhishGuard Performance Metrics on Evaluated Dataset}");
  console.log("\\begin{center}");
  console.log("\\begin{tabular}{|l|c|}");
  console.log("\\hline");
  console.log("\\textbf{Metric} & \\textbf{Value} \\\\");
  console.log("\\hline");
  console.log(`Accuracy & ${accuracy.toFixed(2)}\\% \\\\`);
  console.log(`Precision & ${precision.toFixed(2)}\\% \\\\`);
  console.log(`Recall (Sensitivity) & ${recall.toFixed(2)}\\% \\\\`);
  console.log(`Specificity & ${specificity.toFixed(2)}\\% \\\\`);
  console.log(`F1-Score & ${f1.toFixed(2)}\\% \\\\`);
  console.log(`False Positive Rate & ${fpr.toFixed(2)}\\% \\\\`);
  console.log(`Inference Speed & ${Math.round(total / durationSec).toLocaleString()} URLs/sec \\\\`);
  console.log("\\hline");
  console.log("\\end{tabular}");
  console.log("\\label{tab:metrics}");
  console.log("\\end{center}");
  console.log("\\end{table}\n");
}

evaluate().catch(console.error);
