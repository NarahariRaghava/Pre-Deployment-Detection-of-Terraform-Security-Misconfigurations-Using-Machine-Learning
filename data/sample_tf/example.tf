# Example Terraform file – mix of safe and unsafe AWS resources
# Use this to test:  python main.py --file data/sample_tf/example.tf

# HIGH RISK – SSH open to the entire internet
resource "aws_security_group" "open_ssh" {
  name        = "open-ssh-sg"
  description = "Allows SSH from anywhere"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# HIGH RISK – IAM policy with full admin wildcard
resource "aws_iam_policy" "admin_policy" {
  name        = "full-admin"
  description = "Grants all actions on all resources"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# HIGH RISK – RDS publicly accessible and unencrypted
resource "aws_db_instance" "unsafe_db" {
  identifier        = "prod-db"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
  password          = "supersecret"

  publicly_accessible = true
  storage_encrypted   = false
  multi_az            = false
}

# MEDIUM RISK – S3 bucket with no public access block configured
resource "aws_s3_bucket" "app_logs" {
  bucket = "my-app-logs-bucket"
}

# MEDIUM RISK – RDS publicly accessible but encrypted
resource "aws_db_instance" "reporting_db" {
  identifier        = "reporting-db"
  engine            = "postgres"
  instance_class    = "db.t3.small"
  allocated_storage = 50

  publicly_accessible = true
  storage_encrypted   = true
}

# LOW RISK – S3 bucket locked down with public access block
resource "aws_s3_bucket" "private_data" {
  bucket = "company-private-data"
}

resource "aws_s3_bucket_public_access_block" "private_data_block" {
  bucket                  = aws_s3_bucket.private_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# LOW RISK – Least-privilege IAM policy
resource "aws_iam_policy" "readonly_s3" {
  name        = "readonly-s3"
  description = "Read-only access to a specific S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = "arn:aws:s3:::company-private-data/*"
    }]
  })
}

# LOW RISK – Secure RDS: private, encrypted, multi-AZ, deletion protection
resource "aws_db_instance" "secure_db" {
  identifier              = "secure-prod-db"
  engine                  = "postgres"
  engine_version          = "14.5"
  instance_class          = "db.m5.large"
  allocated_storage       = 100

  publicly_accessible     = false
  storage_encrypted       = true
  multi_az                = true
  deletion_protection     = true
  backup_retention_period = 30
}
