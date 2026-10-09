// model_predict.js
// High-Performance Flattened Typed-Array ML Engine & Feature Extractor

let MODEL = null;
let FLAT_FOREST = null;

// Compile nested JSON tree into contiguous typed arrays (zero-allocation evaluation)
function compileModelToFlatForest(modelJson) {
  const featureNames = modelJson.features || [];
  const featureMap = new Map();
  featureNames.forEach((name, i) => featureMap.set(name, i));

  // Count total nodes across all trees to pre-allocate exact contiguous buffers
  let totalNodes = 0;
  function countNodes(node) {
    totalNodes++;
    if (!node.leaf) {
      countNodes(node.left);
      countNodes(node.right);
    }
  }

  const trees = modelJson.trees || [];
  for (const tree of trees) {
    countNodes(tree);
  }

  const treeCount = trees.length;
  const treeOffsets = new Int32Array(treeCount);
  const featureIndices = new Int16Array(totalNodes);
  const thresholds = new Float32Array(totalNodes);
  const leftChildren = new Int32Array(totalNodes);
  const rightChildren = new Int32Array(totalNodes);
  const probabilities = new Float32Array(totalNodes);

  let cursor = 0;

  function flattenNode(node) {
    const idx = cursor++;
    if (node.leaf) {
      featureIndices[idx] = -1;
      thresholds[idx] = 0;
      leftChildren[idx] = -1;
      rightChildren[idx] = -1;
      probabilities[idx] = node.prob;
    } else {
      const fIdx = featureMap.has(node.feature) ? featureMap.get(node.feature) : -1;
      featureIndices[idx] = fIdx;
      thresholds[idx] = node.threshold;
      probabilities[idx] = 0;

      const leftIdx = flattenNode(node.left);
      const rightIdx = flattenNode(node.right);
      leftChildren[idx] = leftIdx;
      rightChildren[idx] = rightIdx;
    }
    return idx;
  }

  for (let i = 0; i < treeCount; i++) {
    treeOffsets[i] = flattenNode(trees[i]);
  }

  return {
    featureNames,
    featureMap,
    treeCount,
    totalNodes,
    treeOffsets,
    featureIndices,
    thresholds,
    leftChildren,
    rightChildren,
    probabilities,
    version: modelJson.version || '1.0.0',
    loadedAt: Date.now()
  };
}

async function loadModel(modelSource) {
  try {
    if (typeof modelSource === 'string') {
      const resp = await fetch(modelSource);
      MODEL = await resp.json();
    } else if (typeof modelSource === 'object' && modelSource !== null) {
      MODEL = modelSource;
    } else {
      throw new Error('Invalid modelSource format');
    }

    FLAT_FOREST = compileModelToFlatForest(MODEL);
    return FLAT_FOREST;
  } catch (err) {
    console.error('[PhishGuard] Failed to load/compile model:', err);
    throw err;
  }
}

function getModelInfo() {
  if (!FLAT_FOREST) {
    return { loaded: false };
  }
  return {
    loaded: true,
    engine: 'Flattened Typed-Array Engine (JIT-Optimized)',
    version: FLAT_FOREST.version,
    treeCount: FLAT_FOREST.treeCount,
    totalNodes: FLAT_FOREST.totalNodes,
    featureCount: FLAT_FOREST.featureNames.length,
    loadedAt: FLAT_FOREST.loadedAt
  };
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

  // Features for Zero-Day & Tunneling
  features['is_tunnel'] = /(ngrok(-free)?\.app|ngrok\.io|trycloudflare\.com|localtunnel\.me|serveo\.net|telebit\.io)/.test(host) ? 1 : 0;
  features['is_homograph'] = host.includes('xn--') ? 1 : 0;
  features['subdomain_count'] = Math.max(0, host.split('.').length - 2);

  const suspiciousTlds = ['.xyz', '.top', '.link', '.pw', '.club', '.online', '.site', '.work', '.icu', '.gq', '.tk', '.ml'];
  features['suspicious_tld'] = suspiciousTlds.some(tld => host.endsWith(tld)) ? 1 : 0;

  const SUSP_TOK = ['login', 'secure', 'account', 'update', 'verify', 'bank', 'confirm', 'signin', 'wp-admin', 'admin', 'auth'];
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

const predictionCache = new Map();
const CACHE_SIZE_LIMIT = 500;

const SAFE_DOMAINS = [
  'github.com', 'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
  'linkedin.com', 'netflix.com', 'youtube.com', 'wikipedia.org', 'paypal.com',
  'yahoo.com', 'facebook.com', 'twitter.com', 'x.com', 'reddit.com', 'instagram.com',
  'openai.com', 'chatgpt.com', 'anthropic.com', 'aws.amazon.com', 'azure.com',
  'stackoverflow.com', 'medium.com', 'gitlab.com', 'bitbucket.org', 'notion.so',
  'slack.com', 'discord.com', 'twitch.tv', 'spotify.com', 'dropbox.com',
  'box.com', 'zoom.us', 'webex.com', 'salesforce.com', 'atlassian.com',
  'okta.com', 'auth0.com', 'vercel.com', 'netlify.com', 'heroku.com',
  'localhost', '127.0.0.1'
];

function predictProbability(features, urlForCache = null) {
  if (!FLAT_FOREST && !MODEL) throw new Error("Model not loaded");

  if (urlForCache) {
    try {
      if (
        (!urlForCache.startsWith('http://') && !urlForCache.startsWith('https://')) ||
        urlForCache.startsWith('chrome-extension://') ||
        urlForCache.startsWith('moz-extension://') ||
        urlForCache.includes('dashboard.html') ||
        urlForCache.includes('blocked.html') ||
        urlForCache.includes('popup.html')
      ) {
        return 0.0;
      }
      const host = new URL(urlForCache).hostname;
      const isSafe = SAFE_DOMAINS.some(safe => host === safe || host.endsWith('.' + safe));
      if (isSafe) {
        return 0.0;
      }
    } catch(e) {}
  }

  // Cache lookup
  if (urlForCache && predictionCache.has(urlForCache)) {
    return predictionCache.get(urlForCache);
  }

  let prob = 0.0;

  // Ultra-fast iterative typed-array evaluation (no recursive call stack, no object allocation)
  if (FLAT_FOREST) {
    const featureNames = FLAT_FOREST.featureNames;
    const numFeatures = featureNames.length;
    const featureVector = new Float32Array(numFeatures);
    for (let i = 0; i < numFeatures; i++) {
      featureVector[i] = features[featureNames[i]] || 0;
    }

    const featureIndices = FLAT_FOREST.featureIndices;
    const thresholds = FLAT_FOREST.thresholds;
    const leftChildren = FLAT_FOREST.leftChildren;
    const rightChildren = FLAT_FOREST.rightChildren;
    const probabilities = FLAT_FOREST.probabilities;
    const treeOffsets = FLAT_FOREST.treeOffsets;
    const numTrees = FLAT_FOREST.treeCount;

    let sum = 0.0;
    for (let t = 0; t < numTrees; t++) {
      let idx = treeOffsets[t];
      while (true) {
        const fIdx = featureIndices[idx];
        if (fIdx === -1) {
          sum += probabilities[idx];
          break;
        }
        idx = (featureVector[fIdx] <= thresholds[idx]) ? leftChildren[idx] : rightChildren[idx];
      }
    }
    prob = sum / numTrees;
  } else {
    // Fallback if flat forest unavailable
    let sum = 0;
    for (const t of MODEL.trees) {
      let node = t;
      while (!node.leaf) {
        const val = features[node.feature] || 0;
        node = (val <= node.threshold) ? node.left : node.right;
      }
      sum += node.prob;
    }
    prob = sum / MODEL.trees.length;
  }

  if (features['is_tunnel'] === 1) {
    prob = Math.min(1.0, prob + 0.85);
  }

  const HIGH_VALUE_BRANDS = ['microsoft', 'apple', 'paypal', 'google', 'facebook', 'amazon', 'netflix'];
  if (urlForCache) {
    try {
      const host = new URL(urlForCache).hostname.toLowerCase();
      const hostParts = host.split('.');
      let rootDomain = hostParts.length > 1 ? hostParts.slice(-2).join('.') : host;
      if (hostParts.length > 2 && hostParts[hostParts.length - 2].length <= 3) {
        rootDomain = hostParts.slice(-3).join('.');
      }

      let brandImpersonated = false;
      HIGH_VALUE_BRANDS.forEach(brand => {
        if (host.includes(brand) && !rootDomain.includes(brand)) {
          brandImpersonated = true;
        }
      });

      if (brandImpersonated) {
        prob = Math.min(1.0, prob + 0.5);
        features['brand_impersonation'] = 1;
      }
    } catch(e) {}
  }

  // Update Cache
  if (urlForCache) {
    if (predictionCache.size > CACHE_SIZE_LIMIT) {
      predictionCache.delete(predictionCache.keys().next().value);
    }
    predictionCache.set(urlForCache, prob);
  }

  return prob;
}

export { loadModel, extractFeaturesFromUrl, predictProbability, getModelInfo };