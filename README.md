# Pre-Deployment Detection of Terraform Security Misconfigurations Using Machine Learning

A tool that scans Terraform `.tf` files and classifies each resource block as **Low**, **Medium**, or **High** security risk - before anything gets deployed.

---

## What It Does

You point it at a Terraform file or a project folder. It finds every resource block, runs it through a trained ML model, and tells you what's risky and why.

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

It also generates a colour-coded HTML report you can open in a browser.

---

## How It Works

**1. Read the file** - the tool parses the `.tf` file and splits it into individual resource blocks.

**2. Extract features** - each block gets checked against 17 security questions using regex:
- Is `0.0.0.0/0` present?
- Is port 22 or 3389 open?
- Is the database publicly accessible?
- Is encryption disabled?
- Is there a hardcoded password or token?
- ...and so on

Each answer is a 1 or 0. The block becomes a row of 17 numbers.

**3. Classify** - that row of numbers goes into a trained RandomForest model which outputs Low, Medium, or High along with a confidence score.

**4. Explain** - whichever features fired get turned into a plain English reason.

---

## Resource Types Covered

| Resource | What gets flagged |
|---|---|
| `aws_security_group` / `aws_security_group_rule` | SSH/RDP open to internet, DB ports exposed, IPv6 open |
| `aws_s3_bucket` | Public-read ACL, missing public access block |
| `aws_iam_policy` | Wildcard action or resource |
| `aws_db_instance` | Publicly accessible, storage not encrypted |
| `aws_instance` | Public IP assigned, unencrypted EBS, hardcoded credentials |
| `aws_lambda_function` | Hardcoded passwords or tokens in environment variables |
| `aws_lb_listener` | Plain HTTP with no redirect to HTTPS |
| `aws_cloudtrail` | Logging explicitly disabled |

---

## Features Extracted

| Feature | Detects |
|---|---|
| `has_open_cidr` | `cidr_blocks = ["0.0.0.0/0"]` |
| `has_ssh_open` | `from_port = 22` |
| `has_rdp_open` | `from_port = 3389` |
| `has_db_port_open` | MySQL/Postgres/MSSQL/Oracle ports |
| `has_public_database` | `publicly_accessible = true` |
| `has_encryption_disabled` | `storage_encrypted = false` |
| `has_wildcard_iam_action` | `Action = "*"` |
| `has_wildcard_iam_resource` | `Resource = "*"` |
| `has_s3_public_risk` | Public-read or public-read-write ACL |
| `has_ipv6_open_cidr` | `::/0` |
| `has_hardcoded_secret` | `password/token/secret = "literal"` |
| `has_variable_security_ref` | Security value set via `var.` — unknown at scan time |
| `has_public_ip_assigned` | `associate_public_ip_address = true` |
| `has_http_listener` | `protocol = "HTTP"` on a load balancer |
| `has_cloudtrail_disabled` | `enable_logging = false` |
| `has_unencrypted_ebs` | `encrypted = false` on EBS |
| `count_sensitive_indicators` | Total count of all flags above |

---

## Models

Three classifiers were trained and compared:

- **RandomForest** - 100 decision trees voting together. Primary model used for predictions. Outputs confidence scores per class.
- **DecisionTree** - single tree, simpler and more interpretable.
- **LogisticRegression** - linear baseline to compare against the tree-based models.

All models use `class_weight='balanced'` and are evaluated with 5-fold cross-validation.

---

## Project Structure

```
terraform-security-ml/
├── data/
│   ├── generate_dataset.py
│   ├── terraform_dataset.csv
│   └── sample_tf/
│       └── example.tf
├── src/
│   ├── feature_extractor.py
│   ├── model_trainer.py
│   ├── predictor.py
│   └── report_generator.py
├── notebooks/
│   └── exploration.ipynb
├── outputs/
│   ├── evaluation_report.json / .txt
│   ├── confusion_matrix_*.png
│   ├── feature_importance_*.png
│   ├── scan_*.json / .txt / .html
│   └── models/
├── main.py
└── requirements.txt
```

---

## Setup

```bash
cd terraform-security-ml
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

**Train the models:**
```bash
python main.py --train
```

**Run built-in demo predictions:**
```bash
python main.py --predict
```

**Scan a single file:**
```bash
python main.py --file path/to/main.tf
```

**Scan an entire project directory:**
```bash
python main.py --dir path/to/project/
```

**Open the HTML report after scanning:**
```bash
open outputs/scan_<filename>.html
```
