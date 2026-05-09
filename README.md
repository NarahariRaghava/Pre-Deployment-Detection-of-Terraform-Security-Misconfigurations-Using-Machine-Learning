# Pre-Deployment Detection of Terraform Security Misconfigurations Using Machine Learning

The idea is simple: instead of waiting until after deployment to find security problems in your infrastructure code, catch them before they ever reach AWS. This tool takes Terraform `.tf` files, extracts security-relevant signals from each resource block, and uses a trained classifier to label each one as Low, Medium, or High risk.

---

## The Problem

Terraform lets you define cloud infrastructure as code, which is great for automation and consistency — but it also means a single misconfiguration can get deployed everywhere at once. Common mistakes include:

- Security groups open to `0.0.0.0/0` on SSH or RDP
- RDS databases with `publicly_accessible = true` and no encryption
- IAM policies with `Action = "*"` and `Resource = "*"` (full admin access)
- S3 buckets with public-read ACLs
- EC2 instances with public IPs and unencrypted storage
- Hardcoded passwords or API tokens in Lambda environment variables
- Load balancers serving traffic over plain HTTP
- CloudTrail logging turned off

Most of these are caught by commercial scanners, but this project builds the detection pipeline from scratch using ML to explore whether a feature-based classifier can replicate that behavior.

---

## Project Structure

```
terraform-security-ml/
├── data/
│   ├── generate_dataset.py     # builds the synthetic training set
│   ├── terraform_dataset.csv   # generated at runtime
│   └── sample_tf/
│       └── example.tf          # a ready-to-scan example file
├── src/
│   ├── feature_extractor.py    # regex-based feature extraction
│   ├── model_trainer.py        # training, evaluation, chart generation
│   ├── predictor.py            # loads saved model, classifies new snippets
│   └── report_generator.py     # produces the HTML scan report
├── notebooks/
│   └── exploration.ipynb       # interactive data exploration
├── outputs/                    # everything generated at runtime goes here
│   ├── evaluation_report.json
│   ├── evaluation_report.txt
│   ├── confusion_matrix_*.png
│   ├── feature_importance_*.png
│   ├── sample_predictions.*
│   ├── scan_*.json / .txt / .html
│   └── models/
│       ├── randomforest.joblib
│       ├── decisiontree.joblib
│       └── logisticregression.joblib
├── main.py
├── requirements.txt
└── README.md
```

---

## Dataset

The training data is synthetic — 300 hand-written Terraform snippets, 100 per class. Each snippet is labeled High, Medium, or Low risk based on what it contains.

Resource types covered:

| Resource | Risk examples |
|---|---|
| `aws_security_group` / `aws_security_group_rule` | SSH/RDP open to `0.0.0.0/0`, all ports open, DB ports exposed |
| `aws_s3_bucket` | Public-read ACL, missing public access block |
| `aws_iam_policy` | `Action = "*"`, `Resource = "*"` |
| `aws_db_instance` | `publicly_accessible = true`, `storage_encrypted = false` |
| `aws_instance` | Public IP assigned, unencrypted EBS, hardcoded credentials |
| `aws_lambda_function` | Hardcoded passwords/tokens in environment variables |
| `aws_lb_listener` | `protocol = "HTTP"` with no HTTPS redirect |
| `aws_cloudtrail` | `enable_logging = false` |

The dataset is balanced by design. Real-world IaC repos skew heavily toward Low risk, which is one of the known limitations.

---

## Feature Extraction

Each snippet gets converted into 17 binary features using regex pattern matching. No HCL parser is needed.

| Feature | Detects |
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
| `has_ipv6_open_cidr` | `::/0` in cidr_blocks |
| `has_hardcoded_secret` | `password/secret/token = "literal_value"` |
| `has_variable_security_ref` | Security-sensitive value uses `var.` — unknown at scan time |
| `has_public_ip_assigned` | `associate_public_ip_address = true` |
| `has_http_listener` | `protocol = "HTTP"` on a load balancer listener |
| `has_cloudtrail_disabled` | `enable_logging = false` |
| `has_unencrypted_ebs` | `encrypted = false` on an EBS volume |
| `count_sensitive_indicators` | Sum of all flags above |

---

## Models

Three classifiers are trained and compared:

**RandomForestClassifier** — 100 trees, max depth 8. The primary model used for predictions. Outputs probability scores per class which lets you see how confident it was in each decision.

**DecisionTreeClassifier** — single tree, max depth 6. Simpler and more interpretable, used as a comparison baseline.

**LogisticRegression** — linear model, included to check whether the classification problem is linearly separable given the current feature set.

All three use `class_weight='balanced'` to account for real-world class imbalance. Training uses a 75/25 split, and 5-fold cross-validation gives a more reliable accuracy estimate than a single split.

---

## How to Run

**First time setup:**
```bash
cd ~/Desktop/terraform-security-ml
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Train the models:**
```bash
python main.py --train
```

**Run predictions on built-in demo snippets:**
```bash
python main.py --predict
```

**Scan a single Terraform file:**
```bash
python main.py --file path/to/main.tf
```

**Scan an entire Terraform project directory:**
```bash
python main.py --dir path/to/project/
```

After scanning, open the HTML report for a colour-coded view:
```bash
open outputs/scan_<filename>.html
```

---

## Sample Output

```
Resource : aws_security_group.open_ssh
Risk     : High   (High: 94%  |  Low: 2%  |  Medium: 4%)
Reason   : CIDR range is open to the entire internet (0.0.0.0/0); SSH (port 22) is exposed.

Resource : aws_db_instance.reporting_db
Risk     : Medium   (High: 13%  |  Low: 10%  |  Medium: 76%)
Reason   : the database is publicly accessible.

Resource : aws_db_instance.secure_db
Risk     : Low   (High: 1%  |  Low: 73%  |  Medium: 26%)
Reason   : No high-risk indicators detected.

Summary  :  High=3  Medium=1  Low=5
```

The HTML report shows the same information in a colour-coded table you can share or include in a write-up.

---

## Limitations

**The training data is still synthetic.** Even with 8 resource types and 300 examples, all snippets were written by hand from templates. The model has never seen a real infrastructure codebase, so performance on production Terraform may be lower than the eval numbers suggest.

**Regex is not a parser.** The feature extraction uses string matching, which means it can miss things. If a value is computed dynamically, comes from a `locals` block, or uses Terraform's `merge()` function, the feature won't fire. The `has_variable_security_ref` flag helps flag these cases but doesn't resolve them.

**No cross-resource reasoning.** Each resource block is evaluated in isolation. Whether a security group is actually dangerous depends on which EC2 instance uses it — that context is invisible to this model.

**Class balance is artificial.** The 100/100/100 split doesn't reflect reality. In most infrastructure repos, the majority of resources are probably Low risk. A model trained on this distribution may be overconfident when applied to a real codebase.

---

## What could be improved

- Collect real labeled Terraform from public GitHub repos and use that for training instead of (or alongside) the synthetic set
- Use `python-hcl2` to properly parse HCL and extract structured values rather than relying on regex
- Add graph-based analysis to reason about cross-resource relationships
- Build a GitHub Action or pre-commit hook so this runs automatically in CI
- Add SHAP values for per-prediction feature attribution instead of the current rule-based explanations
