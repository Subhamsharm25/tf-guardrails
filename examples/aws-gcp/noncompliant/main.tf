# Intentionally misconfigured: every resource here breaks at least one guardrail.
# CI plans this offline and asserts that tfguard reports exactly the expected rule IDs.

terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.80" }
    google = { source = "hashicorp/google", version = "~> 6.14" }
  }
}

# Offline planning: no credentials or API calls are needed to plan new resources.
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "offline-plan-only"
  secret_key                  = "offline-plan-only"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

provider "google" {
  project      = "example-project"
  region       = "asia-south1"
  access_token = "offline-plan-only"
}

resource "aws_s3_bucket" "logs" { # AWS-S3-001, AWS-S3-002, TAG-001
  bucket = "example-noncompliant-logs"
}

resource "aws_security_group" "bastion" { # AWS-SG-001 (SSH from anywhere)
  name = "bastion"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { owner = "platform", cost-center = "cc-100" }
}

resource "aws_vpc_security_group_ingress_rule" "rdp" { # AWS-SG-001 (RDP from anywhere)
  security_group_id = aws_security_group.bastion.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 3389
  to_port           = 3389
  tags              = { owner = "platform", cost-center = "cc-100" }
}

resource "aws_db_instance" "orders" { # AWS-RDS-001
  identifier          = "orders"
  engine              = "postgres"
  instance_class      = "db.t4g.micro"
  allocated_storage   = 20
  username            = "orders"
  password            = "offline-plan-only"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
  tags                = { owner = "payments", cost-center = "cc-200" }
}

resource "google_storage_bucket" "exports" { # GCP-GCS-001, TAG-001
  name     = "example-noncompliant-exports"
  location = "ASIA-SOUTH1"
}

resource "google_compute_firewall" "ssh" { # GCP-FW-001
  name          = "allow-ssh"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
