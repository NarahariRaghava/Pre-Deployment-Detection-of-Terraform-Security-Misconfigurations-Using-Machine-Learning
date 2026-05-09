"""
main.py – entry point for the Terraform Security Misconfiguration Detector.

Usage
-----
  python main.py --train                   # generate dataset, train models, save outputs
  python main.py --predict                 # run demo predictions on built-in examples
  python main.py --file path/to/main.tf    # scan a real Terraform file
  python main.py --train --predict         # do both in sequence
"""

import argparse
import json
import os
import re
import sys

# Make sure src/ is importable when running from the project root
sys.path.insert(0, os.path.dirname(__file__))

OUTPUTS_DIR = os.path.join(os.path.dirname(__file__), "outputs")

from data.generate_dataset import build_dataset
from src.model_trainer import train_and_evaluate
from src.predictor import predict, print_prediction


# ---------------------------------------------------------------------------
# Demo snippets for the --predict mode
# ---------------------------------------------------------------------------

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
        "label": "Medium Risk – RDS public but encrypted",
        "snippet": '''resource "aws_db_instance" "semi" {
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted   = true
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


# ---------------------------------------------------------------------------
# Terraform file parser – splits a .tf file into individual resource blocks
# ---------------------------------------------------------------------------

def extract_resource_blocks(tf_text: str) -> list[dict]:
    """
    Walks through raw Terraform HCL text and extracts each top-level
    resource block as a separate string.

    Uses a brace-counter instead of a full parser so it handles nested
    blocks (ingress {}, rule {}, etc.) correctly.

    Returns a list of dicts:
        {"resource_type": str, "resource_name": str, "snippet": str}
    """
    # Match the start of any resource block: resource "type" "name" {
    header_re = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
    blocks = []

    for match in header_re.finditer(tf_text):
        resource_type = match.group(1)
        resource_name = match.group(2)
        start = match.start()

        # Walk forward counting braces to find the matching closing brace
        depth = 0
        end = start
        for i, ch in enumerate(tf_text[start:], start=start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break

        blocks.append({
            "resource_type": resource_type,
            "resource_name": resource_name,
            "snippet":       tf_text[start:end],
        })

    return blocks


# ---------------------------------------------------------------------------
# Risk level colour labels for terminal output
# ---------------------------------------------------------------------------

_RISK_COLOURS = {"High": "\033[91m", "Medium": "\033[93m", "Low": "\033[92m"}
_RESET = "\033[0m"

def _coloured(risk: str) -> str:
    return f"{_RISK_COLOURS.get(risk, '')}{risk}{_RESET}"


# ---------------------------------------------------------------------------
# --file mode
# ---------------------------------------------------------------------------

def run_file_scan(tf_path: str):
    if not os.path.isfile(tf_path):
        print(f"Error: file not found: {tf_path}")
        sys.exit(1)

    with open(tf_path, "r") as f:
        tf_text = f.read()

    blocks = extract_resource_blocks(tf_text)

    if not blocks:
        print("No resource blocks found in the file.")
        print("Make sure the file contains  resource \"type\" \"name\" { ... }  blocks.")
        sys.exit(0)

    print(f"\nScanning: {tf_path}")
    print(f"Found {len(blocks)} resource block(s)\n")
    print("=" * 65)

    saved_records = []
    risk_counts = {"High": 0, "Medium": 0, "Low": 0}

    for block in blocks:
        result = predict(block["snippet"], model_name="RandomForest")
        risk = result["risk_level"]
        risk_counts[risk] += 1

        print(f"Resource : {block['resource_type']}.{block['resource_name']}")
        print(f"Risk     : {_coloured(risk)}", end="")
        if result["probabilities"]:
            prob_str = "  |  ".join(
                f"{k}: {v:.0%}" for k, v in result["probabilities"].items()
            )
            print(f"   ({prob_str})", end="")
        print()
        print(f"Reason   : {result['reason']}")
        print("-" * 65)

        saved_records.append({
            "resource_type": block["resource_type"],
            "resource_name": block["resource_name"],
            "risk_level":    risk,
            "probabilities": result["probabilities"],
            "reason":        result["reason"],
            "features":      result["features"],
        })

    # Summary banner
    print(f"\nSummary  :  High={risk_counts['High']}  Medium={risk_counts['Medium']}  Low={risk_counts['Low']}")

    # Save results to outputs/
    os.makedirs(OUTPUTS_DIR, exist_ok=True)
    base = os.path.splitext(os.path.basename(tf_path))[0]

    json_path = os.path.join(OUTPUTS_DIR, f"scan_{base}.json")
    with open(json_path, "w") as f:
        json.dump({"source_file": tf_path, "results": saved_records}, f, indent=2)

    txt_path = os.path.join(OUTPUTS_DIR, f"scan_{base}.txt")
    with open(txt_path, "w") as f:
        f.write(f"Terraform Security Scan – {tf_path}\n")
        f.write("=" * 65 + "\n\n")
        for rec in saved_records:
            f.write(f"Resource : {rec['resource_type']}.{rec['resource_name']}\n")
            f.write(f"Risk     : {rec['risk_level']}\n")
            if rec["probabilities"]:
                prob_str = "  |  ".join(
                    f"{k}: {v:.0%}" for k, v in rec["probabilities"].items()
                )
                f.write(f"Confidence: {prob_str}\n")
            f.write(f"Reason   : {rec['reason']}\n")
            f.write("-" * 65 + "\n\n")
        f.write(f"Summary: High={risk_counts['High']}  Medium={risk_counts['Medium']}  Low={risk_counts['Low']}\n")

    print(f"\nResults saved to:\n  {json_path}\n  {txt_path}")


# ---------------------------------------------------------------------------
# --predict mode (demo snippets)
# ---------------------------------------------------------------------------

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
            f.write(f"Demo: {rec['demo_label']}\n")
            f.write(f"Risk Level  : {rec['risk_level']}\n")
            if rec["probabilities"]:
                prob_str = "  |  ".join(
                    f"{k}: {v:.1%}" for k, v in rec["probabilities"].items()
                )
                f.write(f"Confidence  : {prob_str}\n")
            f.write(f"Reason      : {rec['reason']}\n")
            triggered = [k for k, v in rec["features"].items()
                         if k != "count_sensitive_indicators" and v]
            if triggered:
                f.write("Triggered   : " + ", ".join(triggered) + "\n")
            f.write(f"Indicators  : {rec['features']['count_sensitive_indicators']}\n")
            f.write("-" * 65 + "\n\n")

    print(f"\nSample predictions saved to:\n  {json_path}\n  {txt_path}")


# ---------------------------------------------------------------------------
# --train mode
# ---------------------------------------------------------------------------

def run_training():
    print("\n[1/3] Generating synthetic dataset...")
    df = build_dataset(target_size=240)
    data_path = os.path.join(os.path.dirname(__file__), "data", "terraform_dataset.csv")
    df.to_csv(data_path, index=False)
    print(f"      Dataset: {len(df)} rows saved to {data_path}")
    print(f"      Class distribution:\n{df['risk_label'].value_counts().to_string()}")

    print("\n[2/3] Extracting features & training models...")
    train_and_evaluate(df)

    print("\n[3/3] Training complete. Outputs written to outputs/")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Terraform Security Misconfiguration Detector"
    )
    parser.add_argument("--train",   action="store_true", help="Train and evaluate models")
    parser.add_argument("--predict", action="store_true", help="Run demo predictions on built-in examples")
    parser.add_argument("--file",    metavar="PATH",      help="Path to a .tf file to scan")
    args = parser.parse_args()

    if not args.train and not args.predict and not args.file:
        parser.print_help()
        sys.exit(0)

    if args.train:
        run_training()

    if args.predict:
        run_predictions()

    if args.file:
        run_file_scan(args.file)


if __name__ == "__main__":
    main()
