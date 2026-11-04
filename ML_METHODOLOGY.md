# SMS Shield — Machine Learning Methodology & Architecture

SMS Shield employs two independent, decoupled machine learning pipelines:
1. **Module A**: SMS Text Scam & Phishing NLP Classifier
2. **Module B**: URL Lexical Feature Classifier

---

## 1. Module A: SMS NLP Classification

### 1.1 Objective & Class Strategy
Classifies incoming SMS messages into:
- `legitimate` (transactional, conversational, promotional)
- `scam` / `phishing` (fraudulent lures, credential theft, impersonation)

### 1.2 Pipeline Architecture
```text
Raw SMS Text
    │
    ▼
[Text Preprocessor]
- Lowercasing & unicode normalization
- URL placeholder replacement (TOKEN_URL)
- Numeric token normalization (TOKEN_CURRENCY, TOKEN_PHONE)
- Punctuation & whitespace cleanup
    │
    ▼
[Feature Extraction]
- Word N-grams (1-3)
- Character N-grams (3-5)
- Linguistic indicators:
  * Urgency score ("immediate", "blocked", "within 24 hrs")
  * Verification/KYC keywords ("kyc", "pan", "aadhaar", "update")
  * Payment & Banking fraud patterns ("upi", "refund", "lottery", "credited")
  * Credential request markers ("otp", "pin", "password")
    │
    ▼
[Baseline Models Comparison]
1. TF-IDF + Logistic Regression (calibrated probabilities)
2. TF-IDF + Linear Support Vector Classifier (LinearSVC + Platt scaling)
3. Complement Naive Bayes (imbalanced text baseline)
```

### 1.3 Evaluation & Metrics
- Primary Metric: **Precision-Recall AUC (PR-AUC)** and **F1-Score**.
- Minimizing False Positives: Critical for SMS applications to avoid blocking authentic bank notifications. High precision thresholding (>95% precision target) is prioritized over raw recall.

---

## 2. Module B: URL Lexical Feature Classification

### 2.1 Feature Engineering (Privacy-Safe & Zero Probing)
Extracted purely from the URL string without network fetching:
- `url_length`: Total character length of URL.
- `hostname_length`: Character length of domain.
- `num_dots`: Dot count in hostname (indicator of deep subdomains).
- `num_hyphens`: Hyphen count (frequently used in typosquatting).
- `num_digits`: Digit count in hostname and path.
- `is_ip`: Boolean indicator for IPv4/IPv6 addresses used as host.
- `is_https`: Boolean indicator (note: HTTPS does not imply benign status).
- `suspicious_tld`: Known high-abuse TLDs (`.xyz`, `.top`, `.tk`, `.club`).
- `entropy`: Shannon entropy of hostname string (detects DGA domains).
- `is_shortened`: Domain matches curated URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`, etc.).
- `punycode_flag`: Detects IDN homograph attack prefixes (`xn--`).

### 2.2 Candidate Models
- **Logistic Regression**: Linear baseline with L2 penalty.
- **Random Forest**: Ensemble decision tree baseline.
- **XGBoost Classifier**: Gradient boosted trees with early stopping and PR-AUC optimization.

---

## 3. Data Leakage Prevention Protocol

To ensure reproducible, scientifically valid metrics:
1. **Deduplication Before Splitting**: Exact duplicates and near-duplicates are consolidated before partitioning to avoid optimistic metric bias.
2. **Stratified Split**: Train (70%), Validation (15%), Test (15%) preserving class balance.
3. **Pipeline Encapsulation**: Vectorizers, scalers, and imputers are fitted strictly on the Training set and only applied to Validation and Test sets.
4. **No Metric Fabrication**: All metrics presented in the dashboard are generated from actual hold-out test predictions.
