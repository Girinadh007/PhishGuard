const fs = require('fs');
const readline = require('readline');
const path = require('path');
const { performance } = require('perf_hooks');

// Polyfill fetch
global.fetch = async (url) => {
    return {
        json: async () => JSON.parse(fs.readFileSync(url, 'utf8'))
    };
};

const MODEL_PATH = path.join(__dirname, '../model/model.json');
const ALLOWLIST_PATH = path.join(__dirname, '../model/allowlist.json');
const PHISHING_DATASET_PATH = path.join(__dirname, '../model/phishing_dataset.csv');
const TOP1M_PATH = path.join(__dirname, '../model/top-1m.csv');

async function runBenchmark() {
    console.log("=== Loading Modules & Data ===");
    const memBefore = process.memoryUsage().heapUsed;
    
    const { loadModel, extractFeaturesFromUrl, predictProbability } = await import('file://' + path.join(__dirname, 'model_predict.js'));
    
    // 1. Memory and Load time for Allowlist
    const t0 = performance.now();
    const allowlist = new Set(JSON.parse(fs.readFileSync(ALLOWLIST_PATH, 'utf8')));
    const t1 = performance.now();
    console.log(`Allowlist Loaded: ${allowlist.size} domains in ${(t1-t0).toFixed(2)}ms`);
    
    // 2. Memory and Load time for Model
    const t2 = performance.now();
    await loadModel(MODEL_PATH);
    const t3 = performance.now();
    console.log(`Model Loaded in ${(t3-t2).toFixed(2)}ms`);
    
    const memAfter = process.memoryUsage().heapUsed;
    console.log(`Memory Footprint: ${((memAfter - memBefore)/1024/1024).toFixed(2)} MB\n`);
    
    console.log("=== Interception Time (Speed) ===");
    // Sample URLs
    const sampleSize = 1000;
    
    let modelTimes = [];
    let allowlistTimes = [];
    
    const phishingFileStream = fs.createReadStream(PHISHING_DATASET_PATH);
    const rl = readline.createInterface({ input: phishingFileStream, crlfDelay: Infinity });
    
    let samples = [];
    for await (const line of rl) {
        if (line.startsWith('url,')) continue;
        const [url, label] = line.split(',');
        samples.push(url);
        if (samples.length >= sampleSize) break;
    }
    
    // Test AI Model time
    for (let url of samples) {
        const start = performance.now();
        const features = extractFeaturesFromUrl(url);
        await predictProbability(features, url);
        const end = performance.now();
        modelTimes.push(end - start);
    }
    const avgModelTime = modelTimes.reduce((a,b)=>a+b, 0) / modelTimes.length;
    
    // Test Allowlist time
    for (let url of samples) {
        const start = performance.now();
        try {
            const hostname = new URL(url).hostname.replace(/^www\./, '');
            allowlist.has(hostname);
        } catch(e) {}
        const end = performance.now();
        allowlistTimes.push(end - start);
    }
    const avgAllowlistTime = allowlistTimes.reduce((a,b)=>a+b, 0) / allowlistTimes.length;
    
    console.log(`Average Allowlist Check Time: ${avgAllowlistTime.toFixed(4)}ms per URL`);
    console.log(`Average AI Inference Time: ${avgModelTime.toFixed(4)}ms per URL`);
    
    console.log("\n=== Accuracy / F1 Score ===");
    console.log("Evaluating on phishing_dataset.csv... (this may take a minute)");
    
    let tp = 0; let fp = 0; let tn = 0; let fn = 0;
    let count = 0;
    
    const fullStream = fs.createReadStream(PHISHING_DATASET_PATH);
    const fullRl = readline.createInterface({ input: fullStream, crlfDelay: Infinity });
    
    for await (const line of fullRl) {
        if (line.startsWith('url,')) continue;
        const [url, label] = line.split(',');
        if (!url || !label) continue;
        
        let isPhishPredict = false;
        
        try {
            const hostname = new URL(url).hostname.replace(/^www\./, '');
            if (allowlist.has(hostname)) {
                isPhishPredict = false;
            } else {
                const features = extractFeaturesFromUrl(url);
                const prob = await predictProbability(features, url);
                isPhishPredict = prob >= 0.85; // Using the warn threshold
            }
        } catch(e) {
            isPhishPredict = false;
        }
        
        const isPhishActual = label.trim() === 'phishing';
        
        if (isPhishPredict && isPhishActual) tp++;
        else if (isPhishPredict && !isPhishActual) fp++;
        else if (!isPhishPredict && !isPhishActual) tn++;
        else if (!isPhishPredict && isPhishActual) fn++;
        
        count++;
        if (count % 50000 === 0) {
            console.log(`Processed ${count} URLs...`);
        }
    }
    
    const precision = tp / (tp + fp);
    const recall = tp / (tp + fn);
    const f1 = 2 * (precision * recall) / (precision + recall);
    
    console.log(`Total Evaluated: ${count}`);
    console.log(`True Positives: ${tp}`);
    console.log(`False Positives: ${fp}`);
    console.log(`True Negatives: ${tn}`);
    console.log(`False Negatives: ${fn}`);
    console.log(`Precision: ${(precision*100).toFixed(2)}%`);
    console.log(`Recall (Detection Rate): ${(recall*100).toFixed(2)}%`);
    console.log(`F1 Score: ${(f1*100).toFixed(2)}%`);
}

runBenchmark().catch(console.error);
