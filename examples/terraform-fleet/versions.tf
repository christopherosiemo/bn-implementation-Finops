terraform {

  required_version = ">= 1.9.0, < 2.0.0"
  required_providers {

    aws = {
      source = "hashicorp/aws", version = "= 6.69.1"
    }

  }

}

provider "aws" {

  region              = var.region
  allowed_account_ids = [var.expected_account_id]

}

data "aws_caller_identity" "current" {

  lifecycle {

    postcondition {

      condition     = self.account_id == var.expected_account_id
      error_message = "FLEET_CALLER_ACCOUNT_MISMATCH: exact customer account required."

    }

  }

}
