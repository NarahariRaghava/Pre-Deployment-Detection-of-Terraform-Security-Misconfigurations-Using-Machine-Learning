"""
Generates a synthetic dataset of Terraform snippets labeled by security risk level.
Covers: aws_security_group, aws_s3_bucket, aws_iam_policy, aws_db_instance,
        aws_instance (EC2), aws_lambda_function, aws_lb_listener, aws_cloudtrail.
"""

import pandas as pd
import random

random.seed(42)

# ── HIGH RISK snippets ─────────────────────────────────────────────────────

HIGH_RISK_SNIPPETS = [
    # Security group – SSH open to internet
    '''resource "aws_security_group" "open_ssh" {
  name = "open-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}''',
    # Security group – RDP open to internet
    '''resource "aws_security_group" "open_rdp" {
  name = "open-rdp"
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}''',
    # Security group – all ports open
    '''resource "aws_security_group" "all_open" {
  name = "all-open"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}''',
    # RDS publicly accessible + no encryption
    '''resource "aws_db_instance" "unsafe_db" {
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted   = false
}''',
    # RDS MySQL port exposed to world
    '''resource "aws_security_group_rule" "db_open" {
  type        = "ingress"
  from_port   = 3306
  to_port     = 3306
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = aws_security_group.db_sg.id
}''',
    # IAM wildcard action + wildcard resource
    '''resource "aws_iam_policy" "admin_policy" {
  name = "admin-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}''',
    # S3 public-read-write ACL
    '''resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
}
resource "aws_s3_bucket_acl" "public_acl" {
  bucket = aws_s3_bucket.public_bucket.id
  acl    = "public-read-write"
}''',
    # SSH + MySQL both open to internet
    '''resource "aws_security_group" "web_db_open" {
  name = "web-db-open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}''',
    # RDS Postgres publicly accessible + no encryption
    '''resource "aws_db_instance" "pg_unsafe" {
  engine              = "postgres"
  instance_class      = "db.t3.small"
  publicly_accessible = true
  storage_encrypted   = false
  port                = 5432
}''',
    # IAM wildcard action on all S3
    '''resource "aws_iam_policy" "s3_wildcard" {
  name = "s3-wildcard"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}''',
    # Security group rule – RDP from internet
    '''resource "aws_security_group_rule" "rdp_rule" {
  type              = "ingress"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.example.id
}''',
    # S3 public-read ACL
    '''resource "aws_s3_bucket" "data_bucket" {
  bucket = "company-data-public"
  acl    = "public-read"
}''',
    # All traffic open on all protocols
    '''resource "aws_security_group_rule" "all_traffic" {
  type        = "ingress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = aws_security_group.sg.id
}''',
    # IAM full EC2 + S3 wildcard resource
    '''resource "aws_iam_policy" "ec2_s3_all" {
  name = "ec2-s3-all"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:*", "s3:*"]
      Resource = "*"
    }]
  })
}''',
    # RDS unencrypted, public, no multi-AZ
    '''resource "aws_db_instance" "main" {
  engine              = "mysql"
  instance_class      = "db.m5.large"
  publicly_accessible = true
  storage_encrypted   = false
  multi_az            = false
}''',
    # EC2 – public IP + unencrypted EBS volume
    '''resource "aws_instance" "public_unencrypted_ec2" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t2.micro"
  associate_public_ip_address = true

  ebs_block_device {
    device_name = "/dev/sda1"
    encrypted   = false
    volume_size = 30
  }
}''',
    # EC2 – public IP + hardcoded database password
    '''resource "aws_instance" "hardcoded_creds_ec2" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t2.micro"
  associate_public_ip_address = true

  user_data = base64encode(<<-EOF
    db_password = "SuperSecret_DB_Pass123"
    api_token   = "hardcoded_api_token_value"
  EOF
  )
}''',
    # Lambda – hardcoded password and secret in environment variables
    '''resource "aws_lambda_function" "insecure_lambda" {
  filename      = "function.zip"
  function_name = "insecure-function"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.11"

  environment {
    variables = {
      password    = "hardcoded_password_value"
      db_secret   = "my_database_secret_1234"
      api_token   = "hardcoded_api_token_abc"
    }
  }
}''',
    # Load balancer listener – plain HTTP, no redirect
    '''resource "aws_lb_listener" "http_only" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}''',
    # CloudTrail – logging explicitly disabled
    '''resource "aws_cloudtrail" "disabled_trail" {
  name                       = "disabled-trail"
  s3_bucket_name             = aws_s3_bucket.trail.id
  enable_logging             = false
  enable_log_file_validation = false
}''',
]

# ── MEDIUM RISK snippets ───────────────────────────────────────────────────

MEDIUM_RISK_SNIPPETS = [
    # SSH restricted to broad internal range
    '''resource "aws_security_group" "office_ssh" {
  name = "office-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}''',
    # RDS publicly accessible but encrypted
    '''resource "aws_db_instance" "semi_safe_db" {
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted   = true
}''',
    # S3 bucket – no public access block configured
    '''resource "aws_s3_bucket" "logs_bucket" {
  bucket = "app-logs-bucket"
}''',
    # IAM broad EC2 action on specific resource
    '''resource "aws_iam_policy" "ec2_broad" {
  name = "ec2-broad"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "ec2:*"
      Resource = "arn:aws:ec2:us-east-1:123456789012:instance/*"
    }]
  })
}''',
    # DB port open within VPC only
    '''resource "aws_security_group_rule" "db_vpc_only" {
  type        = "ingress"
  from_port   = 3306
  to_port     = 3306
  protocol    = "tcp"
  cidr_blocks = ["172.16.0.0/12"]
  security_group_id = aws_security_group.db_sg.id
}''',
    # HTTP open to all (web server without HTTPS enforcement)
    '''resource "aws_security_group" "http_open" {
  name = "http-open"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}''',
    # RDS no encryption, not public, single AZ
    '''resource "aws_db_instance" "no_encrypt_db" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  storage_encrypted   = false
  multi_az            = false
  publicly_accessible = false
}''',
    # IAM wildcard action scoped to specific bucket
    '''resource "aws_iam_policy" "s3_specific" {
  name = "s3-specific-wildcard"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "arn:aws:s3:::my-bucket/*"
    }]
  })
}''',
    # Security group – loose egress, restricted ingress
    '''resource "aws_security_group" "loose_egress" {
  name = "loose-egress"
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}''',
    # S3 encrypted but no public access block
    '''resource "aws_s3_bucket" "encrypted_no_block" {
  bucket = "encrypted-no-block"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "enc" {
  bucket = aws_s3_bucket.encrypted_no_block.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}''',
    # RDP open within internal network
    '''resource "aws_security_group_rule" "rdp_internal" {
  type        = "ingress"
  from_port   = 3389
  to_port     = 3389
  protocol    = "tcp"
  cidr_blocks = ["192.168.0.0/16"]
  security_group_id = aws_security_group.windows.id
}''',
    # IAM broad read on all S3 buckets
    '''resource "aws_iam_policy" "s3_read_all" {
  name = "s3-read-all"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = "*"
    }]
  })
}''',
    # Postgres open on internal network only
    '''resource "aws_security_group_rule" "pg_internal" {
  type        = "ingress"
  from_port   = 5432
  to_port     = 5432
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/16"]
  security_group_id = aws_security_group.app_sg.id
}''',
    # HTTP + HTTPS both open (missing HTTP→HTTPS redirect)
    '''resource "aws_security_group" "web_server" {
  name = "web-server"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}''',
    # RDS with backup disabled
    '''resource "aws_db_instance" "no_backup" {
  engine                  = "mysql"
  instance_class          = "db.t3.micro"
  backup_retention_period = 0
  storage_encrypted       = false
  publicly_accessible     = false
}''',
    # EC2 – public IP assigned but EBS encrypted
    '''resource "aws_instance" "public_ec2_encrypted" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t2.micro"
  associate_public_ip_address = true

  ebs_block_device {
    device_name = "/dev/sda1"
    encrypted   = true
    volume_size = 20
  }
}''',
    # Security group – IPv6 open CIDR (all internet via IPv6)
    '''resource "aws_security_group_rule" "ipv6_open" {
  type             = "ingress"
  from_port        = 80
  to_port          = 80
  protocol         = "tcp"
  ipv6_cidr_blocks = ["::/0"]
  security_group_id = aws_security_group.web_sg.id
}''',
    # EC2 – variable-based security settings (unknown risk at scan time)
    '''resource "aws_instance" "var_config_ec2" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  ebs_block_device {
    device_name = "/dev/sda1"
    encrypted   = var.encrypt_ebs
    volume_size = 20
  }
}''',
]

# ── LOW RISK snippets ──────────────────────────────────────────────────────

LOW_RISK_SNIPPETS = [
    # Security group – SSH restricted to single IP
    '''resource "aws_security_group" "restricted_ssh" {
  name = "restricted-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.10/32"]
  }
}''',
    # RDS fully secure
    '''resource "aws_db_instance" "safe_db" {
  engine                  = "mysql"
  instance_class          = "db.t3.micro"
  publicly_accessible     = false
  storage_encrypted       = true
  multi_az                = true
  backup_retention_period = 7
}''',
    # S3 with full public access block
    '''resource "aws_s3_bucket" "private_bucket" {
  bucket = "my-private-bucket"
}
resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.private_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}''',
    # IAM least privilege read-only
    '''resource "aws_iam_policy" "readonly_policy" {
  name = "readonly-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = "arn:aws:s3:::my-specific-bucket/*"
    }]
  })
}''',
    # Security group – HTTPS only from specific VPC range
    '''resource "aws_security_group" "https_restricted" {
  name = "https-only"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}''',
    # RDS private encrypted multi-AZ with deletion protection
    '''resource "aws_db_instance" "prod_db" {
  engine                  = "postgres"
  engine_version          = "14.5"
  instance_class          = "db.m5.large"
  publicly_accessible     = false
  storage_encrypted       = true
  multi_az                = true
  deletion_protection     = true
  backup_retention_period = 30
}''',
    # S3 with encryption and public access block
    '''resource "aws_s3_bucket" "secure_bucket" {
  bucket = "secure-data-bucket"
}
resource "aws_s3_bucket_public_access_block" "secure_block" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_enc" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}''',
    # IAM tightly scoped DynamoDB access
    '''resource "aws_iam_policy" "dynamo_scoped" {
  name = "dynamo-scoped"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"]
      Resource = "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable"
    }]
  })
}''',
    # Security group – DB access from app SG only (no CIDR range)
    '''resource "aws_security_group" "db_private" {
  name = "db-private"
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }
}''',
    # Security group – app traffic from ALB only
    '''resource "aws_security_group" "app_sg" {
  name = "app-sg"
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }
}''',
    # IAM EC2 describe-only
    '''resource "aws_iam_policy" "ec2_describe" {
  name = "ec2-describe-only"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"]
      Resource = "arn:aws:ec2:us-east-1:123456789012:instance/*"
    }]
  })
}''',
    # S3 private ACL
    '''resource "aws_s3_bucket" "internal_logs" {
  bucket = "internal-audit-logs"
}
resource "aws_s3_bucket_acl" "private_acl" {
  bucket = aws_s3_bucket.internal_logs.id
  acl    = "private"
}''',
    # RDS snapshot encrypted
    '''resource "aws_db_instance" "replica_db" {
  engine                = "mysql"
  instance_class        = "db.t3.medium"
  publicly_accessible   = false
  storage_encrypted     = true
  copy_tags_to_snapshot = true
}''',
    # Security group – egress HTTPS only
    '''resource "aws_security_group" "egress_only_https" {
  name = "egress-only-https"
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}''',
    # IAM CloudWatch logs scoped
    '''resource "aws_iam_policy" "cw_logs" {
  name = "cloudwatch-logs-write"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "arn:aws:logs:us-east-1:123456789012:log-group:/app/prod:*"
    }]
  })
}''',
    # EC2 – private, encrypted EBS, no hardcoded secrets
    '''resource "aws_instance" "secure_ec2" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.medium"
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name

  ebs_block_device {
    device_name = "/dev/sda1"
    encrypted   = true
    volume_size = 50
  }
}''',
    # Lambda – VPC config, no hardcoded secrets
    '''resource "aws_lambda_function" "secure_lambda" {
  filename      = "function.zip"
  function_name = "secure-function"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.11"

  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  environment {
    variables = {
      DB_HOST = aws_db_instance.main.address
      ENV     = "production"
    }
  }
}''',
    # LB listener – HTTPS only, HTTP redirects to HTTPS
    '''resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}''',
    # CloudTrail – logging on, encrypted, log validation enabled
    '''resource "aws_cloudtrail" "secure_trail" {
  name                          = "secure-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  enable_logging                = true
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = true
  kms_key_id                    = aws_kms_key.trail_key.arn
}''',
]


def build_dataset(target_size: int = 300) -> pd.DataFrame:
    """
    Assembles a balanced dataset by cycling through the template pools.
    target_size should be divisible by 3 for equal class distribution.
    """
    per_class = target_size // 3
    rows = []

    def sample_pool(pool, label, n):
        chosen = [pool[i % len(pool)] for i in range(n)]
        random.shuffle(chosen)
        return [{"terraform_snippet": s, "risk_label": label} for s in chosen]

    rows += sample_pool(HIGH_RISK_SNIPPETS,   "High",   per_class)
    rows += sample_pool(MEDIUM_RISK_SNIPPETS, "Medium", per_class)
    rows += sample_pool(LOW_RISK_SNIPPETS,    "Low",    per_class)

    random.shuffle(rows)
    return pd.DataFrame(rows)


if __name__ == "__main__":
    import os
    df = build_dataset(300)
    out_path = os.path.join(os.path.dirname(__file__), "terraform_dataset.csv")
    df.to_csv(out_path, index=False)
    print(f"Dataset saved to {out_path}")
    print(df["risk_label"].value_counts())
