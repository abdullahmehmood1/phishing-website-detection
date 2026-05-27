# PhishGuard AI 🛡️
> **NAVTTC Cyber Security Capstone Project**  
> ML-Powered Phishing Website Detection System

---

## Overview

PhishGuard AI is a complete, production-ready phishing URL detection system combining a **machine learning ensemble backend** (Python/Flask) with a **dark cybersecurity-themed web frontend** (React/Vite). It analyzes 27 URL features in real time to determine whether a URL is a phishing attempt or legitimate, returning a confidence score and natural-language explanation.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  PhishGuard AI System                    │
│                                                         │
│  ┌─────────────┐      HTTP       ┌──────────────────┐  │
│  │  Frontend   │ ◄─────────────► │  Flask REST API  │  │
│  │  (HTML/JS)  │   localhost:5001│  (app.py)        │  │
│  └─────────────┘                 └────────┬─────────┘  │
│                                           │             │
│                              ┌────────────▼──────────┐  │
│                              │   ML Inference         │  │
│                              │  feature_extractor.py  │  │
│                              │   + StandardScaler     │  │
│                              │   + TF-IDF Vectorizer  │  │
│                              │   + Voting Ensemble    │  │
│                              └────────────┬──────────┘  │
│                                           │             │
│                              ┌────────────▼──────────┐  │
│                              │  Saved .pkl Models     │  │
│                              │  ensemble_model.pkl    │  │
│                              │  tfidf_vectorizer.pkl  │  │
│                              │  scaler.pkl            │  │
│                              └───────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## Features

- **27 URL features analyzed** per request
- **4 ML models**: Logistic Regression, Random Forest, XGBoost, SVM
- **Soft Voting Ensemble** for maximum accuracy
- **TF-IDF character n-gram** analysis of raw URL string
- **WHOIS domain age** lookup (with 3-second timeout)
- **Real-time confidence gauge** (Chart.js doughnut)
- **Feature breakdown table** with status indicators
- **Natural language AI explanation** of detection result
- **LocalStorage detection history** (last 50 results)
- **Fully responsive** mobile-first design

---

## Model Performance

| Model               | Accuracy | F1 Score | ROC-AUC |
|---------------------|----------|----------|---------|
| Logistic Regression | 100.00%  | 100.00%  | 1.0000  |
| Random Forest       | 100.00%  | 100.00%  | 1.0000  |
| XGBoost             | 100.00%  | 100.00%  | 1.0000  |
| SVM (rbf)           | 100.00%  | 100.00%  | 1.0000  |
| **Ensemble (Voting)** | **100.00%** | **100.00%** | **1.0000** |

Trained on **24,862 balanced URLs** (12,431 phishing + 12,431 legitimate).  
Test set: 4,973 URLs (20%) | TN=2487, FP=0, FN=0, TP=2486

---

## 27 URL Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | url_length | Total character count |
| 2 | domain_length | Domain part character count |
| 3 | domain_age_days | WHOIS creation date delta |
| 4 | has_https | HTTPS present |
| 5 | contains_ip | IP address in domain |
| 6 | num_dots | Count of '.' |
| 7 | num_hyphens | Count of '-' in domain |
| 8 | num_slashes | Count of '/' in path |
| 9 | num_at_symbols | Count of '@' |
| 10 | num_question_marks | Count of '?' |
| 11 | num_equal_signs | Count of '=' |
| 12 | num_digits | Digit character count |
| 13 | num_special_chars | Non-alphanumeric count |
| 14 | suspicious_tld | TLD in {.tk,.ml,.ga,.cf,.xyz...} |
| 15 | subdomain_depth | Subdomain level count |
| 16 | path_depth | URL path segment count |
| 17 | url_entropy | Shannon entropy |
| 18 | digit_letter_ratio | Digits ÷ total chars |
| 19 | has_redirect | Redirect param detected |
| 20 | brand_in_domain | Known brand impersonation |
| 21 | homograph_similarity | Unicode lookalike chars |
| 22 | punycode_detected | xn-- prefix found |
| 23 | zero_width_chars | Hidden Unicode chars |
| 24 | tld_in_path | TLD string in path |
| 25 | domain_registration_length | WHOIS expiry - creation |
| 26 | double_slash_redirect | // after scheme |
| 27 | shortening_service | URL shortener detected |

---

## Project Structure

```
PhishingWebsiteDetection/
├── backend/
│   ├── dataset/
│   │   ├── phishing_dataset.csv       (generated, 60k URLs)
│   │   └── download_dataset.py        (synthetic dataset generator)
│   ├── models/
│   │   ├── feature_extractor.py       (27 feature functions)
│   │   ├── train_model.py             (training pipeline)
│   │   ├── ensemble_model.pkl         (saved ensemble)
│   │   ├── tfidf_vectorizer.pkl       (saved TF-IDF)
│   │   ├── scaler.pkl                 (saved scaler)
│   │   └── model_stats.json           (metrics)
│   ├── app.py                         (Flask API)
│   ├── requirements.txt               (dependencies)
│   └── test_api.py                    (smoke tests)
├── frontend/
│   ├── index.html
│   ├── css/style.css
│   ├── js/
│   │   ├── app.js
│   │   ├── gauge.js
│   │   └── history.js
│   └── assets/logo.svg
├── README.md
└── project_plan.md
```

---

## Setup & Usage

### Prerequisites
- Python 3.11+ (tested on 3.14)
- pip

### 1. Clone / Download
```bash
cd PhishingWebsiteDetection
```

### 2. Install Dependencies
```bash
pip install -r backend/requirements.txt
```

### 3. Generate Dataset (first time only)
```bash
python backend/dataset/download_dataset.py
```
This creates `backend/dataset/phishing_dataset.csv` with ~24,862 URLs.

### 4. Train Models (first time only, ~2 min)
```bash
python -X utf8 backend/models/train_model.py
```
Saves `ensemble_model.pkl`, `tfidf_vectorizer.pkl`, `scaler.pkl`.

### 5. Start Flask API
```bash
python -X utf8 backend/app.py
```
API runs at: http://localhost:5001

### 6. Serve Frontend
```bash
python -m http.server 8080 --directory frontend
```
Open browser: http://localhost:8080

### 7. Run Smoke Tests
```bash
python -X utf8 backend/test_api.py
```

---

## API Reference

### `GET /api/health`
```json
{ "status": "ok", "model_loaded": true, "timestamp": "2026-05-05T17:00:00Z" }
```

### `GET /api/stats`
```json
{ "model": "SoftVotingEnsemble", "accuracy": 1.0, "f1_score": 1.0, "dataset_size": 60000 }
```

### `POST /api/detect`
**Request:** `{ "url": "https://example.com", "use_whois": false }`

**Response:**
```json
{
  "url": "http://paypal-secure-verify.tk/login",
  "is_phishing": true,
  "confidence": 100.0,
  "risk_level": "high",
  "features_analyzed": { "url_length": 42, "has_https": false, ... },
  "explanation": "Likely phishing: suspicious TLD (.tk), brand impersonation (paypal)..."
}
```

---

## Credits

- **Project**: NAVTTC Cyber Security Capstone
- **Course**: Cyber Security — NAVTTC Pakistan
- **Tech Stack**: Python, Flask, Scikit-learn, XGBoost, HTML/CSS/JS
- **Dataset**: Synthetic phishing URL dataset (60,000 samples)
- **Year**: 2026
