"""
train_model.py — Train the Random Forest phishing URL classifier.

Dataset: Uses the "Phishing URL Dataset" from UCI / Kaggle.
Run: python ml/train_model.py
"""

import pandas as pd
import numpy as np
import joblib
import json
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

# ── Import feature extractor ────────────────────────────────────────────────
import sys
sys.path.insert(0, '.')
from services.url_analyzer import URLAnalyzer

analyzer = URLAnalyzer()

# ── Load dataset ────────────────────────────────────────────────────────────
print("📦 Loading dataset...")
# Replace with your actual dataset path
# Expected columns: 'url' (string) and 'label' (0=legit, 1=phishing)
try:
    df = pd.read_csv('data/phishing_urls.csv')
    print(f"   Loaded {len(df)} samples")
except FileNotFoundError:
    print("⚠️  Dataset not found. Generating synthetic demo data...")
    # Synthetic demo data — replace with real dataset in production
    legit_urls = [
        'https://www.google.com/search?q=weather',
        'https://github.com/microsoft/vscode',
        'https://stackoverflow.com/questions/123',
        'https://www.amazon.com/dp/B09ABC',
        'https://docs.python.org/3/library/os.html',
    ] * 200
    phish_urls = [
        'http://paypal-secure-login.xyz/verify',
        'http://192.168.1.1/admin/bank',
        'http://apple-id-locked.tk/verify',
        'http://amazon-prize-claim.ml/win',
        'https://accounts.google.com-update.info/login',
    ] * 200
    df = pd.DataFrame({
        'url': legit_urls + phish_urls,
        'label': [0]*1000 + [1]*1000,
    })
    print(f"   Created {len(df)} synthetic samples")

# ── Feature extraction ───────────────────────────────────────────────────────
print("\n🔧 Extracting features...")
features_list = []
for url in df['url']:
    try:
        feats = analyzer.extract_features(url)
        features_list.append(feats)
    except Exception:
        features_list.append({k: 0 for k in analyzer.extract_features('http://x.com').keys()})

features_df = pd.DataFrame(features_list)
print(f"   Extracted {len(features_df.columns)} features per URL")

X = features_df.values
y = df['label'].values

# ── Train/test split ─────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── Train model ──────────────────────────────────────────────────────────────
print("\n🤖 Training Random Forest classifier...")
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    min_samples_split=5,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1,
)
model.fit(X_train, y_train)

# ── Evaluate ─────────────────────────────────────────────────────────────────
print("\n📊 Evaluation Results:")
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
print(f"ROC-AUC Score: {roc_auc_score(y_test, y_prob):.4f}")

cv_scores = cross_val_score(model, X, y, cv=5, scoring='f1')
print(f"5-Fold CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

# ── Feature importance ───────────────────────────────────────────────────────
print("\n🏆 Top 10 Feature Importances:")
feat_names = list(features_df.columns)
importances = sorted(
    zip(feat_names, model.feature_importances_),
    key=lambda x: x[1], reverse=True
)
for name, imp in importances[:10]:
    print(f"   {name:30s}: {imp:.4f}")

# ── Save model ───────────────────────────────────────────────────────────────
import os
os.makedirs('models', exist_ok=True)
joblib.dump(model, 'models/url_classifier.pkl')
joblib.dump(feat_names, 'models/feature_names.pkl')

meta = {
    "model": "RandomForestClassifier",
    "n_estimators": 200,
    "features": feat_names,
    "accuracy": float((y_pred == y_test).mean()),
    "roc_auc": float(roc_auc_score(y_test, y_prob)),
}
with open('models/model_meta.json', 'w') as f:
    json.dump(meta, f, indent=2)

print("\n✅ Model saved to models/url_classifier.pkl")
print("   Ready for production use!")
