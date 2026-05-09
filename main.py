"""
main.py – entry point for the Terraform Security Misconfiguration Detector.

Usage
-----
  python main.py --train                   # generate dataset, train models, save outputs
  python main.py --predict                 # run demo predictions on built-in examples
  python main.py --file path/to/main.tf    # scan a single Terraform file
  python main.py --dir  path/to/project/  # scan an entire Terraform project directory
  python main.py --train --predict         # train then run demo predictions
"""

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))

OUTPUTS_DIR = os.path.join(os.path.dirname(__file__), "outputs")

from data.generate_dataset import build_dataset
from src.model_trainer import train_and_evaluate
from src.predictor import predict, print_prediction
from src.report_generator import generate_html_report


# ── Demo snippets for --predict mode ──────────────────────────────────────

DEMO_SNIPPETS = [
    {
        "label": "High Risk – SSH + open CIDR",
        "snippet": '''resource "aws_security_group" "bad_sg" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}''',
    },
    {
        "label": "High Risk – IAM wildcard",
        "snippet": '''resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}''',
    },
    {
        "label": "High Risk – Lambda hardcoded credentials",
        "snippet": '''resource "aws_lambda_function" "insecure" {
  filename      = "function.zip"
  function_name = "insecure-fn"
  role          = aws_iam_role.fn_role.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  environment {
    variables = {
      password  = "hardcoded_db_pass_123"
      api_token = "hardcoded_token_value"
    }
  }
}''',
    },
    {
        "label": "Medium Risk – RDS public but encrypted",
        "snippet": '''resource "aws_db_instance" "semi" {
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted   = true
}''',
    },
    {
        "label": "Medium Risk – EC2 public IP assigned",
        "snippet": '''resource "aws_instance" "public_ec2" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t2.micro"
  associate_public_ip_address = true
  ebs_block_device {
    device_name = "/dev/sda1"
    encrypted   = true
  }
}''',
    },
    {
        "label": "Low Risk – private RDS, encrypted, multi-AZ",
        "snippet": '''resource "aws_db_instance" "safe" {
  engine                  = "postgres"
  instance_class          = "db.m5.large"
  publicly_accessible     = false
  storage_encrypted       = true
  multi_az                = true
  deletion_protection     = true
  backup_retention_period = 30
}''',
    },
    {
        "label": "Low Risk – S3 with full public access block",
        "snippet": '''resource "aws_s3_bucket" "private" {
  bucket = "company-private-data"
}
resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.private.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}''',
    },
]


# ── Terraform file parser ──────────────────────────────────────────────────

def extract_resource_blocks(tf_text: str) -> list[dict]:
    """
    Extracts every top-level resource block from raw Terraform HCL using a
    brace counter — handles nested blocks (ingress {}, rule {}, etc.)

    Returns list of dicts: {resource_type, resource_name, snippet}
    """
    header_re = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
    blocks = []
    for match in header_re.finditer(tf_text):
        start  = match.start()
        depth  = 0
        end    = start
        for i, ch in enumerate(tf_text[start:], start=start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        blocks.append({
            "resource_type": match.group(1),
            "resource_name": match.group(2),
            "snippet":       tf_text[start:end],
        })
    return blocks


# ── Terminal colour helpers ────────────────────────────────────────────────

_RISK_COLOURS = {"High": "\033[91m", "Medium": "\033[93m", "Low": "\033[92m"}
_RESET = "\033[0m"

def _coloured(risk: str) -> str:
    return f"{_RISK_COLOURS.get(risk, '')}{risk}{_RESET}"


# ── Shared scan logic ──────────────────────────────────────────────────────

def _scan_blocks(blocks: list[dict], source_file: str) -> list[dict]:
    """Classifies a list of extracted blocks and returns result records."""
    records = []
    for block in blocks:
        result = predict(block["snippet"], model_name="RandomForest")
        records.append({
            "file":          source_file,
            "resource_type": block["resource_type"],
            "resource_name": block["resource_name"],
            "risk_level":    result["risk_level"],
            "probabilities": result["probabilities"],
            "reason":        result["reason"],
            "features":      result["features"],
        })
    return records


def _print_records(records: list[dict]):
    """Prints scan results to the terminal with colour."""
    for r in records:
        print(f"Resource : {r['resource_type']}.{r['resource_name']}")
        print(f"Risk     : {_coloured(r['risk_level'])}", end="")
        if r["probabilities"]:
            prob_str = "  |  ".join(
                f"{k}: {v:.0%}" for k, v in r["probabilities"].items()
            )
            print(f"   ({prob_str})", end="")
        print()
        if r["features"].get("has_variable_security_ref"):
            print("         ⚠ Uses variable reference — verify value manually")
        print(f"Reason   : {r['reason']}")
        print("-" * 65)


def _save_scan_outputs(records: list[dict], base_name: str, source_label: str):
    """Saves JSON, text, and HTML reports for a scan."""
    os.makedirs(OUTPUTS_DIR, exist_ok=True)

    # JSON
    json_path = os.path.join(OUTPUTS_DIR, f"scan_{base_name}.json")
    with open(json_path, "w") as f:
        json.dump({"source": source_label, "results": records}, f, indent=2)

    # Plain text
    txt_path = os.path.join(OUTPUTS_DIR, f"scan_{base_name}.txt")
    counts = {"High": 0, "Medium": 0, "Low": 0}
    with open(txt_path, "w") as f:
        f.write(f"Terraform Security Scan – {source_label}\n")
        f.write("=" * 65 + "\n\n")
        for r in records:
            counts[r["risk_level"]] += 1
            f.write(f"Resource : {r['resource_type']}.{r['resource_name']}\n")
            f.write(f"File     : {r['file']}\n")
            f.write(f"Risk     : {r['risk_level']}\n")
            if r["probabilities"]:
                prob_str = "  |  ".join(
                    f"{k}: {v:.0%}" for k, v in r["probabilities"].items()
                )
                f.write(f"Confidence: {prob_str}\n")
            f.write(f"Reason   : {r['reason']}\n")
            f.write("-" * 65 + "\n\n")
        f.write(f"Summary: High={counts['High']}  Medium={counts['Medium']}  Low={counts['Low']}\n")

    # HTML
    html_path = os.path.join(OUTPUTS_DIR, f"scan_{base_name}.html")
    generate_html_report(records, source_label, html_path)

    print(f"\nResults saved to:\n  {json_path}\n  {txt_path}\n  {html_path}")
    return counts


# ── --file mode ────────────────────────────────────────────────────────────

def run_file_scan(tf_path: str):
    if not os.path.isfile(tf_path):
        print(f"Error: file not found: {tf_path}")
        sys.exit(1)

    with open(tf_path) as f:
        tf_text = f.read()

    blocks = extract_resource_blocks(tf_text)
    if not blocks:
        print("No resource blocks found. Make sure the file contains resource \"type\" \"name\" { } blocks.")
        sys.exit(0)

    print(f"\nScanning : {tf_path}")
    print(f"Found    : {len(blocks)} resource block(s)\n")
    print("=" * 65)

    records = _scan_blocks(blocks, tf_path)
    _print_records(records)

    counts = _save_scan_outputs(
        records,
        base_name=os.path.splitext(os.path.basename(tf_path))[0],
        source_label=tf_path,
    )
    print(f"Summary  :  High={counts['High']}  Medium={counts['Medium']}  Low={counts['Low']}")


# ── --dir mode ─────────────────────────────────────────────────────────────

def run_dir_scan(dir_path: str):
    """
    Recursively finds all .tf files in dir_path, classifies every resource
    block in each file, and generates a combined HTML/JSON/text report.
    """
    if not os.path.isdir(dir_path):
        print(f"Error: directory not found: {dir_path}")
        sys.exit(1)

    # Collect all .tf files (skip .terraform cache directories)
    tf_files = []
    for root, dirs, files in os.walk(dir_path):
        dirs[:] = [d for d in dirs if d != ".terraform"]
        for fname in files:
            if fname.endswith(".tf"):
                tf_files.append(os.path.join(root, fname))

    if not tf_files:
        print(f"No .tf files found in {dir_path}")
        sys.exit(0)

    tf_files.sort()
    print(f"\nScanning directory : {dir_path}")
    print(f"Found {len(tf_files)} .tf file(s)\n")

    all_records = []
    total_blocks = 0

    for tf_path in tf_files:
        with open(tf_path) as f:
            tf_text = f.read()
        blocks = extract_resource_blocks(tf_text)
        if not blocks:
            continue

        rel_path = os.path.relpath(tf_path, dir_path)
        print(f"  {rel_path}  ({len(blocks)} resource(s))")
        records = _scan_blocks(blocks, rel_path)
        all_records.extend(records)
        total_blocks += len(blocks)

    if not all_records:
        print("No resource blocks found across all files.")
        sys.exit(0)

    print(f"\n{'='*65}")
    print(f"Total resources scanned: {total_blocks}\n")
    _print_records(all_records)

    dir_name = os.path.basename(os.path.abspath(dir_path))
    counts = _save_scan_outputs(
        all_records,
        base_name=f"dir_{dir_name}",
        source_label=dir_path,
    )
    print(f"Summary  :  High={counts['High']}  Medium={counts['Medium']}  Low={counts['Low']}")


# ── --predict mode ─────────────────────────────────────────────────────────

def run_predictions():
    print("\n" + "=" * 55)
    print("  DEMO: Predicting risk for sample Terraform snippets")
    print("=" * 55)

    saved_records = []
    for demo in DEMO_SNIPPETS:
        print(f"\n--- {demo['label']} ---")
        result = predict(demo["snippet"], model_name="RandomForest")
        print_prediction(result)
        saved_records.append({
            "demo_label":    demo["label"],
            "snippet":       demo["snippet"],
            "risk_level":    result["risk_level"],
            "probabilities": result["probabilities"],
            "reason":        result["reason"],
            "features":      result["features"],
        })

    os.makedirs(OUTPUTS_DIR, exist_ok=True)

    json_path = os.path.join(OUTPUTS_DIR, "sample_predictions.json")
    with open(json_path, "w") as f:
        json.dump(saved_records, f, indent=2)

    txt_path = os.path.join(OUTPUTS_DIR, "sample_predictions.txt")
    with open(txt_path, "w") as f:
        f.write("Terraform Security Misconfiguration Detector – Sample Predictions\n")
        f.write("=" * 65 + "\n\n")
        for rec in saved_records:
            f.write(f"Demo       : {rec['demo_label']}\n")
            f.write(f"Risk Level : {rec['risk_level']}\n")
            if rec["probabilities"]:
                prob_str = "  |  ".join(
                    f"{k}: {v:.1%}" for k, v in rec["probabilities"].items()
                )
                f.write(f"Confidence : {prob_str}\n")
            f.write(f"Reason     : {rec['reason']}\n")
            triggered = [k for k, v in rec["features"].items()
                         if k != "count_sensitive_indicators" and v]
            if triggered:
                f.write("Triggered  : " + ", ".join(triggered) + "\n")
            f.write(f"Indicators : {rec['features']['count_sensitive_indicators']}\n")
            f.write("-" * 65 + "\n\n")

    print(f"\nSample predictions saved to:\n  {json_path}\n  {txt_path}")


# ── --train mode ───────────────────────────────────────────────────────────

def run_training():
    print("\n[1/3] Generating synthetic dataset...")
    df = build_dataset(target_size=300)
    data_path = os.path.join(os.path.dirname(__file__), "data", "terraform_dataset.csv")
    df.to_csv(data_path, index=False)
    print(f"      {len(df)} rows saved to {data_path}")
    print(f"      Class distribution:\n{df['risk_label'].value_counts().to_string()}")

    print("\n[2/3] Extracting features & training models...")
    train_and_evaluate(df)

    print("\n[3/3] Training complete. Outputs written to outputs/")


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Terraform Security Misconfiguration Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python main.py --train
  python main.py --file infra/main.tf
  python main.py --dir  infra/
  python main.py --train --predict""",
    )
    parser.add_argument("--train",   action="store_true", help="Train and evaluate models")
    parser.add_argument("--predict", action="store_true", help="Run demo predictions")
    parser.add_argument("--file",    metavar="PATH",      help="Scan a single .tf file")
    parser.add_argument("--dir",     metavar="PATH",      help="Scan all .tf files in a directory")
    args = parser.parse_args()

    if not any([args.train, args.predict, args.file, args.dir]):
        parser.print_help()
        sys.exit(0)

    if args.train:
        run_training()

    if args.predict:
        run_predictions()

    if args.file:
        run_file_scan(args.file)

    if args.dir:
        run_dir_scan(args.dir)


if __name__ == "__main__":
    main()
