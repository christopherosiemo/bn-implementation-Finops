terraform {
  required_version = ">= 1.9.0, < 2.0.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
    tls = { source = "hashicorp/tls", version = "~> 4.0" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = var.name, Environment = "pilot", ManagedBy = "terraform", Residency = "EU" }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_availability_zones" "available" { state = "available" }

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  zones      = slice(data.aws_availability_zones.available.names, 0, 2)
  purposes   = toset(["database", "raw", "audit", "signer", "execution", "cluster"])
}
