"""
Extracts security-relevant binary features from a Terraform HCL snippet
using regex and string matching. No full HCL parser required.
"""

import re
from typing import Dict

# ── Original patterns ──────────────────────────────────────────────────────
_OPEN_CIDR      = re.compile(r'cidr_blocks\s*=\s*\[?"0\.0\.0\.0/0"?\]?')
_SSH_PORT       = re.compile(r'from_port\s*=\s*22\b')
_RDP_PORT       = re.compile(r'from_port\s*=\s*3389\b')
_DB_PORTS       = re.compile(r'from_port\s*=\s*(3306|5432|1433|1521)\b')
_PUBLIC_DB      = re.compile(r'publicly_accessible\s*=\s*true',  re.IGNORECASE)
_NO_ENCRYPT_RDS = re.compile(r'storage_encrypted\s*=\s*false',   re.IGNORECASE)
_WILD_ACTION    = re.compile(r'Action\s*=\s*["\[]?\s*["\']?\*["\']?', re.IGNORECASE)
_WILD_RESOURCE  = re.compile(r'Resource\s*=\s*["\[]?\s*["\']?\*["\']?', re.IGNORECASE)
_S3_PUBLIC      = re.compile(r'acl\s*=\s*"public-(read|read-write)"', re.IGNORECASE)

# ── New patterns ───────────────────────────────────────────────────────────

# IPv6 fully open — catches both cidr_blocks and ipv6_cidr_blocks
_IPV6_OPEN = re.compile(r'::/0')

# Hardcoded secret literal: password/secret/token = "plaintext_value"
# Negative lookahead skips Terraform interpolations like "${var.x}"
_HARDCODED_SECRET = re.compile(
    r'(password|secret|token|private_key)\s*=\s*"(?!\$\{)[^"]{4,}"',
    re.IGNORECASE,
)

# Security-sensitive attribute delegated to a variable — risk unknown at scan time
_VAR_SECURITY_REF = re.compile(
    r'(cidr_blocks|publicly_accessible|storage_encrypted|encrypted)\s*=\s*\[?\s*var\.',
    re.IGNORECASE,
)

# EC2 instance with a public IP address attached
_PUBLIC_IP = re.compile(r'associate_public_ip_address\s*=\s*true', re.IGNORECASE)

# Load balancer listener using plain HTTP instead of HTTPS
_HTTP_LISTENER = re.compile(r'\bprotocol\s*=\s*"HTTP"', re.IGNORECASE)

# CloudTrail logging explicitly turned off
_CLOUDTRAIL_OFF = re.compile(r'enable_logging\s*=\s*false', re.IGNORECASE)

# EBS volume encryption disabled — \b prevents matching storage_encrypted
_UNENCRYPTED_EBS = re.compile(r'\bencrypted\s*=\s*false', re.IGNORECASE)


def extract_features(snippet: str) -> Dict[str, int]:
    """
    Returns a dict of binary (0/1) security feature flags plus a count
    of how many sensitive indicators fired.

    Parameters
    ----------
    snippet : str
        Raw Terraform HCL text for one resource or a group of resources.

    Returns
    -------
    dict with keys:
        has_open_cidr, has_ssh_open, has_rdp_open, has_db_port_open,
        has_public_database, has_encryption_disabled,
        has_wildcard_iam_action, has_wildcard_iam_resource,
        has_s3_public_risk,
        has_ipv6_open_cidr, has_hardcoded_secret,
        has_variable_security_ref, has_public_ip_assigned,
        has_http_listener, has_cloudtrail_disabled,
        has_unencrypted_ebs,
        count_sensitive_indicators
    """
    features = {
        # ── Original 9 ────────────────────────────────────────────────────
        "has_open_cidr":             int(bool(_OPEN_CIDR.search(snippet))),
        "has_ssh_open":              int(bool(_SSH_PORT.search(snippet))),
        "has_rdp_open":              int(bool(_RDP_PORT.search(snippet))),
        "has_db_port_open":          int(bool(_DB_PORTS.search(snippet))),
        "has_public_database":       int(bool(_PUBLIC_DB.search(snippet))),
        "has_encryption_disabled":   int(bool(_NO_ENCRYPT_RDS.search(snippet))),
        "has_wildcard_iam_action":   int(bool(_WILD_ACTION.search(snippet))),
        "has_wildcard_iam_resource": int(bool(_WILD_RESOURCE.search(snippet))),
        "has_s3_public_risk":        int(bool(_S3_PUBLIC.search(snippet))),
        # ── New 7 ─────────────────────────────────────────────────────────
        "has_ipv6_open_cidr":        int(bool(_IPV6_OPEN.search(snippet))),
        "has_hardcoded_secret":      int(bool(_HARDCODED_SECRET.search(snippet))),
        "has_variable_security_ref": int(bool(_VAR_SECURITY_REF.search(snippet))),
        "has_public_ip_assigned":    int(bool(_PUBLIC_IP.search(snippet))),
        "has_http_listener":         int(bool(_HTTP_LISTENER.search(snippet))),
        "has_cloudtrail_disabled":   int(bool(_CLOUDTRAIL_OFF.search(snippet))),
        "has_unencrypted_ebs":       int(bool(_UNENCRYPTED_EBS.search(snippet))),
    }
    features["count_sensitive_indicators"] = sum(
        v for k, v in features.items() if k != "count_sensitive_indicators"
    )
    return features


def explain_features(features: Dict[str, int]) -> str:
    """Human-readable sentence listing every indicator that fired."""
    messages = {
        "has_open_cidr":             "CIDR range is open to the entire internet (0.0.0.0/0)",
        "has_ssh_open":              "SSH (port 22) is exposed",
        "has_rdp_open":              "RDP (port 3389) is exposed",
        "has_db_port_open":          "a database port (MySQL/Postgres/MSSQL/Oracle) is exposed",
        "has_public_database":       "the database is publicly accessible",
        "has_encryption_disabled":   "RDS storage encryption is disabled",
        "has_wildcard_iam_action":   "IAM action is a wildcard (*)",
        "has_wildcard_iam_resource": "IAM resource is a wildcard (*)",
        "has_s3_public_risk":        "S3 bucket has a public ACL",
        "has_ipv6_open_cidr":        "IPv6 CIDR is open to the entire internet (::/0)",
        "has_hardcoded_secret":      "hardcoded secret/password detected in plain text",
        "has_variable_security_ref": "security-sensitive value uses a variable — verify value manually",
        "has_public_ip_assigned":    "EC2 instance is assigned a public IP address",
        "has_http_listener":         "load balancer listener uses plain HTTP (not HTTPS)",
        "has_cloudtrail_disabled":   "CloudTrail logging is explicitly disabled",
        "has_unencrypted_ebs":       "EBS volume encryption is disabled",
    }
    triggered = [msg for key, msg in messages.items() if features.get(key)]
    if not triggered:
        return "No high-risk indicators detected."
    return "; ".join(triggered) + "."
