# train_export_rf.py
import pandas as pd
import re
import json
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score
import joblib

# --- Feature extraction ---
SUSPICIOUS_TOKENS = ['login','secure','account','update','verify','bank','confirm','signin']

def shannon_entropy(s):
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    import math
    return - sum(p * math.log2(p) for p in probs)

def extract_features_from_url(url):
    parsed = urlparse(url if url.startswith(('http://','https://')) else 'http://' + url)
    host = parsed.netloc
    path = parsed.path or ''
    query = parsed.query or ''
    full = host + path + query

    features = {}
    features['url_length'] = len(url)
    features['host_length'] = len(host)
    features['path_length'] = len(path)
    features['count_dots'] = host.count('.')
    features['count_hyphens'] = url.count('-')
    features['count_at'] = url.count('@')
    features['count_percent'] = url.count('%')
    features['count_slash'] = url.count('/')
    features['has_https'] = int(parsed.scheme == 'https')
    features['has_ip'] = int(bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', host)))
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['entropy'] = shannon_entropy(full)
    # suspicious tokens
    for tok in SUSPICIOUS_TOKENS:
        features[f'tok_{tok}'] = int(tok in url.lower())
    return features

# --- Load dataset ---
# Make sure phishing_dataset.csv has columns: url,label
df = pd.read_csv('phishing_dataset.csv')  

# Standardize labels (phishing → 1, legitimate → 0)
df['label'] = df['label'].astype(str).str.lower().map({'phishing': 1, 'legitimate': 0, '1': 1, '0': 0})

X = [extract_features_from_url(u) for u in df['url'].astype(str)]
X = pd.DataFrame(X)
y = df['label'].astype(int)

# --- Train/test split ---
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)

# --- Train RF ---
rf = RandomForestClassifier(n_estimators=100, max_depth=14, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)

# --- Evaluate ---
y_pred = rf.predict(X_test)
y_proba = rf.predict_proba(X_test)[:,1]
print(classification_report(y_test, y_pred))
print("ROC AUC:", roc_auc_score(y_test, y_proba))

scores = cross_val_score(rf, X, y, cv=5, scoring='f1')
print("5-fold F1:", scores.mean())

# --- Save model for backup ---
joblib.dump(rf, 'rf_backup.joblib')

# --- Export model.json for extension ---
from sklearn.tree import _tree

def tree_to_dict(tree: _tree.Tree, feature_names):
    def recurse(node):
        if tree.feature[node] != _tree.TREE_UNDEFINED:
            name = feature_names[tree.feature[node]]
            threshold = float(tree.threshold[node])
            return {
                "feature": name,
                "threshold": threshold,
                "left": recurse(tree.children_left[node]),
                "right": recurse(tree.children_right[node])
            }
        else:
            value = tree.value[node][0].tolist()
            total = sum(value)
            p1 = value[1]/total if total>0 else 0.0
            return {"leaf": True, "prob": float(p1)}
    return recurse(0)

feature_names = list(X.columns)
forest_json = {"n_features": len(feature_names), "features": feature_names, "trees": []}
for est in rf.estimators_:
    forest_json["trees"].append(tree_to_dict(est.tree_, feature_names))

with open('model.json','w') as f:
    json.dump(forest_json, f)

print("Exported model.json with", len(forest_json["trees"]), "trees.")
