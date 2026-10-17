terraform {
  required_version = ">= 1.9.0, < 2.0.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
    tls = { source = "hashicorp/tls", version = "~> 4.0" }
  }
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.expected_account_id]
  default_tags {
    tags = { Project = var.name, Environment = "pilot", ManagedBy = "terraform", Residency = "EU", Owner = var.pilot_owner, ExpiresAt = var.pilot_expires_at }
  }
}

data "aws_caller_identity" "current" {
  lifecycle {
    postcondition {
      condition     = self.account_id == var.expected_account_id
      error_message = "Control-plane credentials belong to the wrong AWS account."
    }
  }
}
data "aws_partition" "current" {}
data "aws_availability_zones" "available" { state = "available" }

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  zones      = slice(data.aws_availability_zones.available.names, 0, 2)
  purposes   = toset(["database", "raw", "audit", "signer", "execution", "cluster"])
}
