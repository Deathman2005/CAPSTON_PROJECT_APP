# SMS Shield — Dataset Registry & Provenance Specification

SMS Shield mandates strict transparency regarding the source, licensing, and limitations of all data utilized for training and evaluating machine learning models.

---

## 1. Dataset Registry

| ID | Dataset Name | Source / Citation | License | Records | Language | Primary Classes |
|---|---|---|---|---|---|---|
| `DS-01` | **UCI SMS Spam Collection** | Almeida et al., 2012 (UCI ML Repository) | CC BY 4.0 | 5,574 | English | `ham`, `spam` |
| `DS-02` | **ISOT Fake / Scam SMS Dataset** | University of Victoria / ISOT | Academic / Research | ~12,000 | English | `legitimate`, `scam` |
| `DS-03` | **PhishTank Phishing URL Feed** | PhishTank (OpenDNS / Cisco) | Community Terms | ~30,000 | Global | `phishing` |
| `DS-04` | **URLhaus Abuse Feed** | abuse.ch | CC0 (Public Domain)| Active | Global | `malware`, `phishing` |
| `DS-05` | **Majestic Million Benign Domains** | Majestic-12 | Creative Commons | 1,000,000 | Global | `benign` |

---

## 2. Licensing Compliance & Distribution Rules

1. **Non-Commercial & Academic Prototype**: External threat feeds and datasets are consumed according to their respective acceptable use policies.
2. **Zero Fabrication**: No synthetic training examples are presented as real-world user messages. When synthetic test fixtures are used for unit testing, they are clearly labeled as synthetic.
3. **No Private User Data in Training**: Training sets never contain data harvested from app users.

---

## 3. Preprocessing & Partitioning Standards

```text
[Raw Datasets]
       │
       ▼
[Deduplication & Hygiene]
  - Strip byte-order marks and control characters
  - Deduplicate on normalized text
  - Discard corrupt or unparseable records
       │
       ▼
[Stratified Partitioning]
  ├── Train Split (70%)      -> Fits Transformers & Models
  ├── Validation Split (15%) -> Hyperparameter Tuning & Threshold Calibration
  └── Test Split (15%)       -> Final Unbiased Metric Evaluation
```
