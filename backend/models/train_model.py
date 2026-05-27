"""
train_model.py
PhishGuard AI — Full ML Training Pipeline (v2)

Trains: Logistic Regression, Random Forest, XGBoost, SVM (rbf)
        → Soft Voting Ensemble
Saves:  ensemble_model.pkl, tfidf_vectorizer.pkl, scaler.pkl, imputer.pkl
        model_stats.json  (accuracy / F1 / AUC per model)

Usage:
    python -X utf8 backend/models/train_model.py
"""

import os
import sys
import json
import time
import datetime
import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import joblib

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
)
from sklearn.pipeline import Pipeline
from sklearn.base import BaseEstimator, ClassifierMixin
import scipy.sparse as sp

from xgboost import XGBClassifier

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE         = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE, "dataset", "phishing_dataset.csv")
MODELS_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH   = os.path.join(MODELS_DIR, "ensemble_model.pkl")
TFIDF_PATH   = os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl")
SCALER_PATH  = os.path.join(MODELS_DIR, "scaler.pkl")
IMPUTER_PATH = os.path.join(MODELS_DIR, "imputer.pkl")
STATS_PATH   = os.path.join(MODELS_DIR, "model_stats.json")

sys.path.insert(0, BASE)
from models.feature_extractor import (
    extract_structural_features, FEATURE_NAMES,
    STRUCTURAL_FEATURE_NAMES, REPUTATION_FEATURE_NAMES
)

# Reputation columns pre-computed in CSV (domain_rank, tranco_rank_log, backlink_count_estimate)
_REPUTATION_CSV_COLS = REPUTATION_FEATURE_NAMES


# ─── Step 1: Load Dataset ─────────────────────────────────────────────────────

def load_dataset(path: str) -> pd.DataFrame:
    print(f"\n{'='*60}")
    print("  PhishGuard AI — Model Training Pipeline v2")
    print(f"{'='*60}")
    print(f"\n[1/7] Loading dataset from: {path}")

    if not os.path.exists(path):
        print(f"[!] Dataset not found at {path}")
        print("    Run:  python backend/dataset/download_dataset.py")
        sys.exit(1)

    df = pd.read_csv(path)
    print(f"    Rows loaded : {len(df):,}")
    print(f"    Columns     : {list(df.columns)}")

    # Normalise label column name
    for col in ["label", "phishing", "Result", "CLASS_LABEL", "status"]:
        if col in df.columns:
            df = df.rename(columns={col: "label"})
            break

    # Normalise URL column
    for col in ["url", "URL", "Url"]:
        if col in df.columns:
            df = df.rename(columns={col: "url"})
            break

    if "url" not in df.columns:
        print("[!] No 'url' column found in dataset.")
        sys.exit(1)
    if "label" not in df.columns:
        print("[!] No label column found.")
        sys.exit(1)

    # Normalise labels to {0, 1}
    unique = df["label"].unique()
    if set(unique) == {-1, 1}:
        df["label"] = df["label"].map({-1: 0, 1: 1})
    elif set(unique) == {"phishing", "legitimate"}:
        df["label"] = df["label"].map({"phishing": 1, "legitimate": 0})

    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)
    df["url"]   = df["url"].astype(str).str.strip()

    phish = (df["label"] == 1).sum()
    legit = (df["label"] == 0).sum()
    print(f"    Phishing    : {phish:,}")
    print(f"    Legitimate  : {legit:,}")

    return df


# ─── Step 2: Feature Extraction ───────────────────────────────────────────────

def extract_all_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract structural URL features + pre-computed reputation columns from CSV.

    FEATURE_NAMES (27 total):
      - 24 structural (pure URL text, no network)
      - 3  reputation  (domain_rank, tranco_rank_log, backlink_count_estimate)
    """
    print(f"\n[2/7] Extracting features from {len(df):,} URLs …")

    # ── Structural features (pure URL text, no network calls) ─────────────────
    struct_rows = []
    for i, (_, row) in enumerate(df.iterrows()):
        try:
            f = extract_structural_features(row["url"])
        except Exception:
            f = {k: 0 for k in STRUCTURAL_FEATURE_NAMES}
        struct_rows.append(f)
        if i % 10_000 == 0 and i > 0:
            print(f"    processed {i:,} …")

    struct_df = pd.DataFrame(struct_rows)

    # ── Reputation features (pre-computed in CSV) ─────────────────────────────
    rep_df = pd.DataFrame(index=range(len(df)))
    for col in REPUTATION_FEATURE_NAMES:
        if col in df.columns:
            rep_df[col] = df[col].values
        else:
            rep_df[col] = np.nan

    # ── Combine in canonical order ────────────────────────────────────────────
    feat_df = pd.concat([struct_df.reset_index(drop=True),
                         rep_df.reset_index(drop=True)], axis=1)

    for col in FEATURE_NAMES:
        if col not in feat_df.columns:
            feat_df[col] = np.nan
    feat_df = feat_df[FEATURE_NAMES]

    print(f"    Features extracted: {len(feat_df.columns)} cols → {list(feat_df.columns)}")
    return feat_df


# ─── Step 3: TF-IDF ───────────────────────────────────────────────────────────

def build_tfidf(urls: pd.Series, fit: bool = True, vectorizer=None) -> tuple:
    print("\n[3/7] Building TF-IDF representation …")
    if fit:
        vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(2, 4),
            max_features=1000,
            sublinear_tf=True,
        )
        tfidf_matrix = vectorizer.fit_transform(urls)
    else:
        tfidf_matrix = vectorizer.transform(urls)
    print(f"    TF-IDF shape: {tfidf_matrix.shape}")
    return tfidf_matrix, vectorizer


# ─── Step 4: Preprocessing ────────────────────────────────────────────────────

def preprocess(feat_df: pd.DataFrame, tfidf_matrix,
               scaler=None, imputer=None, fit: bool = True):
    print("\n[4/7] Imputing missing values and scaling numeric features …")
    X_raw = feat_df[FEATURE_NAMES].values.astype(float)

    if fit:
        imputer = SimpleImputer(strategy="median")
        X_imputed = imputer.fit_transform(X_raw)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_imputed)
    else:
        X_imputed = imputer.transform(X_raw)
        X_scaled  = scaler.transform(X_imputed)

    X = sp.hstack([sp.csr_matrix(X_scaled), tfidf_matrix])
    print(f"    Combined feature matrix: {X.shape}")
    return X, scaler, imputer


# ─── Step 5: Train ────────────────────────────────────────────────────────────

def train_models(X_train, y_train, X_test, y_test):
    print(f"\n[5/7] Training models …\n")

    models = {
        "Logistic Regression": LogisticRegression(
            C=1.0, max_iter=1000, solver="lbfgs",
            random_state=42, n_jobs=-1
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, max_depth=15,
            random_state=42, n_jobs=-1
        ),
        "XGBoost": XGBClassifier(
            n_estimators=200, learning_rate=0.1, max_depth=6,
            random_state=42,
            eval_metric="logloss", verbosity=0, n_jobs=-1
        ),
        "SVM": SVC(
            kernel="rbf", C=1.0, probability=True,
            random_state=42
        ),
    }

    results = {}
    trained = {}

    for name, clf in models.items():
        print(f"  ► Training {name} …", end=" ", flush=True)
        t0 = time.time()
        clf.fit(X_train, y_train)
        elapsed = time.time() - t0

        y_pred = clf.predict(X_test)
        y_prob = clf.predict_proba(X_test)[:, 1]

        acc  = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec  = recall_score(y_test, y_pred, zero_division=0)
        f1   = f1_score(y_test, y_pred, zero_division=0)
        auc  = roc_auc_score(y_test, y_prob)
        cm   = confusion_matrix(y_test, y_pred)

        results[name] = {
            "accuracy":         round(acc,  4),
            "precision":        round(prec, 4),
            "recall":           round(rec,  4),
            "f1_score":         round(f1,   4),
            "roc_auc":          round(auc,  4),
            "confusion_matrix": cm.tolist(),
            "train_time_s":     round(elapsed, 1),
        }
        trained[name] = clf
        print(f"Done ({elapsed:.1f}s) | Acc={acc:.4f} | F1={f1:.4f} | AUC={auc:.4f}")

    # ── Ensemble ──────────────────────────────────────────────────────────────
    print(f"\n  ► Building Soft Voting Ensemble …", end=" ", flush=True)
    ensemble = VotingClassifier(
        estimators=[
            ("lr",  trained["Logistic Regression"]),
            ("rf",  trained["Random Forest"]),
            ("xgb", trained["XGBoost"]),
            ("svm", trained["SVM"]),
        ],
        voting="soft",
        weights=[1, 2, 2, 1],
    )
    # Mark sub-estimators as already fitted
    le = LabelEncoder()
    le.fit([0, 1])
    ensemble.le_ = le
    ensemble.estimators_ = [
        trained["Logistic Regression"],
        trained["Random Forest"],
        trained["XGBoost"],
        trained["SVM"],
    ]
    ensemble.classes_ = np.array([0, 1])
    ensemble.named_estimators_ = {
        "lr":  trained["Logistic Regression"],
        "rf":  trained["Random Forest"],
        "xgb": trained["XGBoost"],
        "svm": trained["SVM"],
    }

    y_pred_ens = ensemble.predict(X_test)
    y_prob_ens = ensemble.predict_proba(X_test)[:, 1]
    acc_ens    = accuracy_score(y_test, y_pred_ens)
    f1_ens     = f1_score(y_test, y_pred_ens, zero_division=0)
    auc_ens    = roc_auc_score(y_test, y_prob_ens)
    cm_ens     = confusion_matrix(y_test, y_pred_ens)

    results["Ensemble (Voting)"] = {
        "accuracy":         round(acc_ens, 4),
        "f1_score":         round(f1_ens,  4),
        "roc_auc":          round(auc_ens, 4),
        "confusion_matrix": cm_ens.tolist(),
    }
    print(f"Done | Acc={acc_ens:.4f} | F1={f1_ens:.4f} | AUC={auc_ens:.4f}")

    return ensemble, results


# ─── Step 6: Print Report ─────────────────────────────────────────────────────

def print_report(results: dict):
    print(f"\n{'='*60}")
    print("  MODEL PERFORMANCE REPORT")
    print(f"{'='*60}")
    header = f"{'Model':<25} {'Accuracy':>9} {'F1':>8} {'AUC':>8}"
    print(header)
    print("-" * 55)
    for name, m in results.items():
        acc = m.get("accuracy", "—")
        f1  = m.get("f1_score", "—")
        auc = m.get("roc_auc", "—")
        print(f"{name:<25} {acc:>9.4f} {f1:>8.4f} {auc:>8.4f}")

    ens = results.get("Ensemble (Voting)", {})
    if "confusion_matrix" in ens:
        cm = ens["confusion_matrix"]
        print(f"\n  Ensemble Confusion Matrix:")
        print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
        print(f"    FN={cm[1][0]}  TP={cm[1][1]}")
    print(f"{'='*60}\n")


# ─── Step 7: Save ─────────────────────────────────────────────────────────────

def save_artifacts(ensemble, vectorizer, scaler, imputer, results, dataset_size):
    print("[6/7] Saving model artifacts …")
    joblib.dump(ensemble,   MODEL_PATH)
    joblib.dump(vectorizer, TFIDF_PATH)
    joblib.dump(scaler,     SCALER_PATH)
    joblib.dump(imputer,    IMPUTER_PATH)

    ens_stats = results.get("Ensemble (Voting)", {})
    stats = {
        "model":             "SoftVotingEnsemble_v2",
        "accuracy":          ens_stats.get("accuracy", 0),
        "f1_score":          ens_stats.get("f1_score", 0),
        "roc_auc":           ens_stats.get("roc_auc", 0),
        "dataset_size":      dataset_size,
        "features_count":    len(FEATURE_NAMES),
        "feature_names":     FEATURE_NAMES,
        "training_date":     datetime.datetime.now().strftime("%Y-%m-%d"),
        "per_model_results": results,
    }
    with open(STATS_PATH, "w") as f:
        json.dump(stats, f, indent=2)

    print(f"    ensemble_model.pkl    → {MODEL_PATH}")
    print(f"    tfidf_vectorizer.pkl  → {TFIDF_PATH}")
    print(f"    scaler.pkl            → {SCALER_PATH}")
    print(f"    imputer.pkl           → {IMPUTER_PATH}")
    print(f"    model_stats.json      → {STATS_PATH}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    df = load_dataset(DATASET_PATH)

    feat_df      = extract_all_features(df)
    tfidf_matrix, vectorizer = build_tfidf(df["url"])
    X, scaler, imputer       = preprocess(feat_df, tfidf_matrix)
    y = df["label"].values

    print("\n[4b/7] Splitting data (80/20 stratified) …")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"    Train: {X_train.shape[0]:,} | Test: {X_test.shape[0]:,}")

    ensemble, results = train_models(X_train, y_train, X_test, y_test)
    print_report(results)
    save_artifacts(ensemble, vectorizer, scaler, imputer, results, len(df))

    print("[7/7] Training complete! ✓")
    print("\n  Next step: python -X utf8 backend/app.py\n")


if __name__ == "__main__":
    main()
