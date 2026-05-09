# Pre-Deployment Detection of Terraform Security Misconfigurations Using Machine Learning

## Project Purpose

This research prototype demonstrates how machine learning can be applied to Infrastructure-as-Code (IaC) security analysis. The system scans Terraform configuration snippets *before* deployment and classifies each one as **Low**, **Medium**, or **High** security risk — helping developers catch dangerous misconfigurations in CI/CD pipelines before they reach production.

---

## Research Problem

Cloud infrastructure misconfigurations are a leading cause of data breaches. Common examples include:

- Security groups open to the entire internet (`0.0.0.0/0`)
- SSH or RDP ports exposed publicly
- Unencrypted databases accessible from the internet
- Overly permissive IAM policies using wildcard actions/resources
- S3 buckets with public ACLs

Traditional static analysis tools rely on hand-crafted rules. This project explores whether a supervised ML classifier trained on feature-engineered Terraform snippets can achieve competitive accuracy with less manual rule maintenance.

---

## Project Structure

```
terraform-security-ml/
├── data/
│   ├── generate_dataset.py     # Synthetic dataset builder
│   └── terraform_dataset.csv   # Generated dataset (created at runtime)
├── src/
│   ├── __init__.py
│   ├── feature_extractor.py    # Regex-based feature extraction
│   ├── model_trainer.py        # Training, evaluation, chart generation
│   └── predictor.py            # Inference on new snippets
├── notebooks/
│   └── exploration.ipynb       # Optional exploratory analysis
├── outputs/                    # Generated at runtime
│   ├── evaluation_report.json
│   ├── confusion_matrix_randomforest.png
│   ├── confusion_matrix_decisiontree.png
│   ├── feature_importance_randomforest.png
│   ├── feature_importance_decisiontree.png
│   └── models/
│       ├── randomforest.joblib
│       └── decisiontree.joblib
├── main.py                     # CLI entry point
├── requirements.txt
└── README.md
```

---

## Dataset Generation

The dataset is fully synthetic and built from hand-crafted Terraform HCL templates covering four AWS resource types:

| Resource | Examples |
|---|---|
| `aws_security_group` / `aws_security_group_rule` | SSH open to `0.0.0.0/0`, RDP open, DB ports exposed |
| `aws_s3_bucket` | Public ACLs, missing public-access blocks |
| `aws_iam_policy` | Wildcard `Action = "*"`, wildcard `Resource = "*"` |
| `aws_db_instance` | `publicly_accessible = true`, `storage_encrypted = false` |

**Size:** 240 rows (80 per class, balanced).  
**Labels:** `Low`, `Medium`, `High`

The `build_dataset()` function samples from 15 templates per class with cycling and shuffling to add variety without overfitting to exact templates.

---

## Feature Extraction

Features are extracted via regex pattern matching — no full HCL parser required.

| Feature | What it detects |
|---|---|
| `has_open_cidr` | `cidr_blocks = ["0.0.0.0/0"]` |
| `has_ssh_open` | `from_port = 22` |
| `has_rdp_open` | `from_port = 3389` |
| `has_db_port_open` | MySQL (3306), Postgres (5432), MSSQL (1433), Oracle (1521) |
| `has_public_database` | `publicly_accessible = true` |
| `has_encryption_disabled` | `storage_encrypted = false` |
| `has_wildcard_iam_action` | `Action = "*"` |
| `has_wildcard_iam_resource` | `Resource = "*"` |
| `has_s3_public_risk` | `acl = "public-read"` or `"public-read-write"` |
| `count_sensitive_indicators` | Sum of all binary flags above |

All features are binary (0/1) except `count_sensitive_indicators` which is an integer count.

---

## ML Models

### RandomForestClassifier (primary)
- 100 estimators, max depth 8
- Provides probability scores per class
- Generates feature importance rankings

### DecisionTreeClassifier (comparison)
- Max depth 6
- Simple, interpretable tree structure
- Useful baseline to compare against ensemble method

Both models are trained with a **75/25 train/test split** and evaluated on:
- Accuracy
- Precision, Recall, F1-score (per class)
- Confusion matrix
- Feature importance chart

---

## How to Run

### 1. Install dependencies

```bash
cd terraform-security-ml
pip install -r requirements.txt
```

### 2. Train models and generate outputs

```bash
python main.py --train
```

This will:
- Generate `data/terraform_dataset.csv` (240 rows)
- Extract features from each snippet
- Train both classifiers
- Save evaluation metrics to `outputs/evaluation_report.json`
- Save confusion matrix PNGs to `outputs/`
- Save feature importance chart to `outputs/`
- Save model files to `outputs/models/`

### 3. Run demo predictions

```bash
python main.py --predict
```

This loads the trained RandomForest model and runs it against 5 built-in example snippets, printing risk level, confidence scores, and plain-English explanation.

### 4. Train and predict in one step

```bash
python main.py --train --predict
```

---

## Sample Output

```
--- High Risk – SSH + open CIDR ---

=======================================================
  Risk Level  : High
  Confidence  : High: 94.0%  |  Low: 2.0%  |  Medium: 4.0%
  Reason      : CIDR range is open to the entire internet (0.0.0.0/0); SSH (port 22) is exposed.
  Triggered Features:
    • has_open_cidr
    • has_ssh_open
  Total Indicators: 2
=======================================================

--- Low Risk – private RDS, encrypted, multi-AZ ---

=======================================================
  Risk Level  : Low
  Confidence  : High: 1.0%  |  Low: 97.0%  |  Medium: 2.0%
  Reason      : No high-risk indicators detected.
  Triggered Features:
  Total Indicators: 0
=======================================================
```

---

## Limitations

1. **Synthetic data only** — the dataset is hand-crafted from templates, not real-world Terraform repositories. Model performance on real IaC code may differ.
2. **String matching, not parsing** — features rely on regex patterns that can miss obfuscated or dynamically generated configurations.
3. **No context awareness** — the model evaluates each snippet independently and cannot reason about cross-resource relationships (e.g., a security group's effect depends on which EC2 instance uses it).
4. **Fixed feature set** — new misconfiguration types require manual addition of regex patterns and retraining.
5. **Class imbalance ignored** — the dataset is artificially balanced; real-world IaC repositories likely have more Low-risk configurations.

---

## Future Work

- **Real dataset** — collect labeled Terraform snippets from public GitHub repositories and security audit reports.
- **HCL parsing** — use `python-hcl2` for structured feature extraction instead of regex.
- **NLP features** — apply TF-IDF or code embeddings to capture semantic patterns beyond hand-crafted features.
- **Graph-based analysis** — model resource dependencies to reason about combined misconfiguration risk.
- **CI/CD integration** — wrap the predictor as a GitHub Action or pre-commit hook.
- **Explainability** — add SHAP values for per-prediction feature attribution.
- **Feedback loop** — allow security engineers to label new snippets and retrain incrementally.

---

## Dependencies

```
scikit-learn>=1.3.0
pandas>=2.0.0
numpy>=1.24.0
matplotlib>=3.7.0
seaborn>=0.12.0
joblib>=1.3.0
```

---

*Course project — ENPM818N Spring 2026, Group 3*
