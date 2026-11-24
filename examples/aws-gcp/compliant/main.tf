# The same kinds of resources, configured the way the guardrails require. tfguard must pass this.

terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.80" }
    google = { source = "hashicorp/google", version = "~> 6.14" }
  }
}

locals {
  tags = { owner = "platform", cost-center = "cc-100" }
}

# Offline planning: no credentials or API calls are needed to plan new resources.
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "offline-plan-only"
  secret_key                  = "offline-plan-only"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  default_tags { tags = local.tags }
}

provider "google" {
  project        = "example-project"
  region         = "asia-south1"
  access_token   = "offline-plan-only"
  default_labels = local.tags
}

resource "aws_s3_bucket" "logs" {
  bucket = "example-compliant-logs"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_security_group" "app" {
  name = "app"
  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "SSH from the VPN range only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

resource "aws_db_instance" "orders" {
  identifier          = "orders"
  engine              = "postgres"
  instance_class      = "db.t4g.micro"
  allocated_storage   = 20
  username            = "orders"
  password            = "offline-plan-only"
  publicly_accessible = false
  storage_encrypted   = true
  skip_final_snapshot = true
}

resource "google_storage_bucket" "exports" {
  name                        = "example-compliant-exports"
  location                    = "ASIA-SOUTH1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

resource "google_compute_firewall" "iap_ssh" {
  name          = "allow-ssh-from-iap"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"] # Identity-Aware Proxy TCP forwarding
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
