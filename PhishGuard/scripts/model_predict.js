// model_predict.js
// Loads model.json (packaged with extension or fetched) and exposes predict(urlFeatures)

let MODEL = null;

async function loadModel(modelUrl) {
  const resp = await fetch(modelUrl);
  MODEL = await resp.json();
}

// Expect features object keys same as Python feature_names order
function extractFeaturesFromUrl(url) {
const a = new URL(url.startsWith('http') ? url : ('http://' + url));
  const host = a.hostname || '';
  const path = a.pathname || '';
  const q = a.search || '';
  const full = host + path + q;

  const features = {};
  features['url_length'] = url.length;
  features['host_length'] = host.length;
  features['path_length'] = path.length;
  features['count_dots'] = (host.match(/\./g) || []).length;
  features['count_hyphens'] = (url.match(/-/g) || []).length;
  features['count_at'] = (url.match(/@/g) || []).length;
  features['count_percent'] = (url.match(/%/g) || []).length;
  features['count_slash'] = (url.match(/\//g) || []).length;
  features['has_https'] = (a.protocol === 'https:') ? 1 : 0;
  features['has_ip'] = (/^\d+\.\d+\.\d+\.\d+$/.test(host)) ? 1 : 0;
  features['num_digits'] = (url.match(/\d/g) || []).length;
  features['entropy'] = shannonEntropy(full);

  const SUSP_TOK = ['login', 'secure', 'account', 'update', 'verify', 'bank', 'confirm', 'signin'];
  SUSP_TOK.forEach(tok => {
    features['tok_' + tok] = url.toLowerCase().includes(tok) ? 1 : 0;
  });

  return features;
}

function shannonEntropy(s) {
  if (!s) return 0;
  const counts = {};
  for (const c of s) counts[c] = (counts[c] || 0) + 1;
  let ent = 0;
  const len = s.length;
  for (const k in counts) {
    const p = counts[k] / len;
    ent -= p * Math.log2(p);
  }
  return ent;
}

function evalTree(node, features) {
  if (node.leaf) return node.prob;
  const f = features[node.feature];
  if (f <= node.threshold) return evalTree(node.left, features);
  return evalTree(node.right, features);
}

function predictProbability(features) {
  if (!MODEL) throw new Error("Model not loaded");
  const trees = MODEL.trees;
  let sum = 0;
  for (const t of trees) {
    sum += evalTree(t, features);
  }
  return sum / trees.length; // average probability
}

export { loadModel, extractFeaturesFromUrl, predictProbability };