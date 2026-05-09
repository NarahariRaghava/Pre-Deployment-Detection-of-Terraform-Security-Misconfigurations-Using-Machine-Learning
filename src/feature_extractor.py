"""
Extracts security-relevant binary features from a Terraform HCL snippet
using regex and string matching. No full HCL parser required.
"""

import re
from typing import Dict


# Regex patterns for each feature
_OPEN_CIDR = re.compile(r'cidr_blocks\s*=\s*\[?"0\.0\.0\.0/0"?\]?')
_SSH_PORT   = re.compile(r'from_port\s*=\s*22\b')
_RDP_PORT   = re.compile(r'from_port\s*=\s*3389\b')
_DB_PORTS   = re.compile(r'from_port\s*=\s*(3306|5432|1433|1521)\b')
_PUBLIC_DB  = re.compile(r'publicly_accessible\s*=\s*true', re.IGNORECASE)
_NO_ENCRYPT = re.compile(r'storage_encrypted\s*=\s*false', re.IGNORECASE)
_WILD_ACTION = re.compile(r'Action\s*=\s*["\[]?\s*["\']?\*["\']?', re.IGNORECASE)
_WILD_RESOURCE = re.compile(r'Resource\s*=\s*["\[]?\s*["\']?\*["\']?', re.IGNORECASE)
# S3 public-risk indicators: public-read(-write) ACL, or missing public-access block
_S3_PUBLIC  = re.compile(r'acl\s*=\s*"public-(read|read-write)"', re.IGNORECASE)


def extract_features(snippet: str) -> Dict[str, int]:
    """
    Returns a dictionary of binary (0/1) security feature flags plus a count
    of how many sensitive indicators fired.

    Parameters
    ----------
    snippet : str
        Raw Terraform HCL text for a single resource or group of resources.

    Returns
    -------
    dict with keys:
        has_open_cidr, has_ssh_open, has_rdp_open, has_db_port_open,
        has_public_database, has_encryption_disabled, has_wildcard_iam_action,
        has_wildcard_iam_resource, has_s3_public_risk, count_sensitive_indicators
    """
    features = {
        "has_open_cidr":            int(bool(_OPEN_CIDR.search(snippet))),
        "has_ssh_open":             int(bool(_SSH_PORT.search(snippet))),
        "has_rdp_open":             int(bool(_RDP_PORT.search(snippet))),
        "has_db_port_open":         int(bool(_DB_PORTS.search(snippet))),
        "has_public_database":      int(bool(_PUBLIC_DB.search(snippet))),
        "has_encryption_disabled":  int(bool(_NO_ENCRYPT.search(snippet))),
        "has_wildcard_iam_action":  int(bool(_WILD_ACTION.search(snippet))),
        "has_wildcard_iam_resource":int(bool(_WILD_RESOURCE.search(snippet))),
        "has_s3_public_risk":       int(bool(_S3_PUBLIC.search(snippet))),
    }
    features["count_sensitive_indicators"] = sum(
        v for k, v in features.items() if k != "count_sensitive_indicators"
    )
    return features


def explain_features(features: Dict[str, int]) -> str:
    """
    Builds a human-readable sentence explaining which indicators fired.
    Returns 'No high-risk indicators detected.' if none are set.
    """
    messages = {
        "has_open_cidr":             "CIDR range is open to the entire internet (0.0.0.0/0)",
        "has_ssh_open":              "SSH (port 22) is exposed",
        "has_rdp_open":              "RDP (port 3389) is exposed",
        "has_db_port_open":          "a database port (MySQL/Postgres/MSSQL/Oracle) is exposed",
        "has_public_database":       "the database is publicly accessible",
        "has_encryption_disabled":   "storage encryption is disabled",
        "has_wildcard_iam_action":   "IAM action is a wildcard (*)",
        "has_wildcard_iam_resource": "IAM resource is a wildcard (*)",
        "has_s3_public_risk":        "S3 bucket has a public ACL",
    }
    triggered = [msg for key, msg in messages.items() if features.get(key)]
    if not triggered:
        return "No high-risk indicators detected."
    return "; ".join(triggered) + "."
