terraform {
  required_version = ">= 1.9.0, < 2.0.0"
  required_providers { aws = { source = "hashicorp/aws", version = "~> 6.0" } }
}
provider "aws" {
  region              = var.region
  allowed_account_ids = [var.expected_account_id]
  default_tags {
    tags = { Project = var.name, Environment = "pilot", Owner = var.pilot_owner, ExpiresAt = var.pilot_expires_at }
  }
}
data "aws_caller_identity" "customer" {
  lifecycle {
    postcondition {
      condition     = self.account_id == var.expected_account_id
      error_message = "Customer-role credentials belong to the wrong AWS account."
    }
  }
}
data "aws_partition" "customer" {}

variable "expected_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "Provide the exact 12-digit customer account ID."
  }
}
variable "pilot_owner" {
  type = string
  validation {
    condition     = length(trimspace(var.pilot_owner)) > 0
    error_message = "An accountable pilot owner is required."
  }
}
variable "pilot_expires_at" {
  type = string
  validation {
    condition     = can(formatdate("YYYY-MM-DD", var.pilot_expires_at))
    error_message = "Use an RFC3339 expiry timestamp."
  }
}
variable "name" {
  type    = string
  default = "finops-pilot"
}
variable "region" {
  type    = string
  default = "eu-west-1"
  validation {
    condition     = var.region == "eu-west-1"
    error_message = "Customer pilot roles are restricted to eu-west-1."
  }
}
variable "read_principal_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/.+", var.read_principal_arn)) && try(split(":", var.read_principal_arn)[4], "") != var.expected_account_id
    error_message = "The trusted ingester must be an IAM role in the separate control-plane account, not this customer account."
  }
}
variable "enable_execution" {
  type        = bool
  default     = false
  description = "Opt in only after read-only acceptance. Existing execution installations must retain true until all owned restorations finish."
}
variable "hardware_read_principal_arn" {
  type    = string
  default = null
  validation {
    condition     = var.hardware_read_principal_arn == null || (can(regex("^arn:aws:iam::[0-9]{12}:role/.+", var.hardware_read_principal_arn)) && try(split(":", var.hardware_read_principal_arn)[4], "") != var.expected_account_id && var.hardware_read_principal_arn != var.read_principal_arn && var.hardware_read_principal_arn != var.execution_principal_arn)
    error_message = "Optional hardware reader must be a distinct control-plane IAM role."
  }
}
variable "execution_principal_arn" {
  type    = string
  default = null
  validation {
    condition     = !var.enable_execution || (can(regex("^arn:aws:iam::[0-9]{12}:role/.+", var.execution_principal_arn)) && try(split(":", var.execution_principal_arn)[4], "") != var.expected_account_id)
    error_message = "Execution requires an explicit executor IAM role in the separate control-plane account, not this customer account."
  }
}
variable "external_id" {
  type      = string
  sensitive = true
  validation {
    condition     = length(var.external_id) >= 32
    error_message = "Use a unique per-customer external ID of at least 32 characters."
  }
}
variable "tenant_id" {
  type = string
  validation {
    condition     = length(trimspace(var.tenant_id)) > 0
    error_message = "A non-empty customer tenant ID is required."
  }
}
variable "instance_ids" {
  type    = set(string)
  default = []
  validation {
    condition     = (!var.enable_execution || length(var.instance_ids) > 0) && alltrue([for id in var.instance_ids : can(regex("^i-([0-9a-f]{8}|[0-9a-f]{17})$", id))])
    error_message = "Execution requires an explicit allowlist of valid EC2 instance IDs."
  }
}
variable "billing_bucket_arn" {
  type        = string
  default     = null
  description = "Optional for discovery-only onboarding. No billing S3 access until configured."
  validation {
    condition     = var.billing_bucket_arn == null || can(regex("^arn:aws:s3:::[^/]+$", var.billing_bucket_arn))
    error_message = "Use a bucket ARN without an object prefix, or null for discovery only."
  }
}
variable "billing_prefix" {
  type    = string
  default = "cur/"
}
variable "billing_kms_key_arn" {
  type    = string
  default = null
}

locals {
  roles         = merge({ read = var.read_principal_arn }, var.enable_execution ? { execution = var.execution_principal_arn } : {})
  instance_arns = [for id in var.instance_ids : "arn:${data.aws_partition.customer.partition}:ec2:${var.region}:${data.aws_caller_identity.customer.account_id}:instance/${id}"]
}
resource "aws_iam_role" "customer" {
  for_each             = local.roles
  name                 = "${var.name}-${each.key}"
  max_session_duration = 3600
  lifecycle { prevent_destroy = true }
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow", Principal = { AWS = each.key == "read" ? compact([each.value, var.hardware_read_principal_arn]) : [each.value] }, Action = "sts:AssumeRole"
      Condition = { StringEquals = { "sts:ExternalId" = var.external_id } }
    }]
  })
}
resource "aws_iam_role_policy" "read" {
  role = aws_iam_role.customer["read"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      { Effect = "Allow", Action = ["ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeInstanceTypes", "ec2:DescribeInstanceTypeOfferings", "ec2:DescribeImages", "ec2:DescribeVolumes", "ec2:DescribeTags", "autoscaling:DescribeAutoScalingGroups", "autoscaling:DescribeAutoScalingInstances", "cloudwatch:GetMetricData", "cloudwatch:GetMetricStatistics", "cloudwatch:ListMetrics"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = var.region } } }
      ], flatten([for bucket in compact([var.billing_bucket_arn]) : [
        { Effect = "Allow", Action = "s3:ListBucket", Resource = bucket, Condition = { StringLike = { "s3:prefix" = "${var.billing_prefix}*" } } },
        { Effect = "Allow", Action = ["s3:GetBucketVersioning", "s3:GetBucketPolicy", "s3:GetBucketLocation"], Resource = bucket },
        { Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion"], Resource = "${bucket}/${var.billing_prefix}*" }
    ]]))
  })
}
resource "aws_iam_role_policy" "billing_decrypt" {
  count  = var.billing_kms_key_arn != null && var.billing_bucket_arn != null ? 1 : 0
  role   = aws_iam_role.customer["read"].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = ["kms:Decrypt", "kms:DescribeKey"], Resource = var.billing_kms_key_arn }] })
}
resource "aws_iam_role_policy" "execution" {
  count = var.enable_execution ? 1 : 0
  role  = aws_iam_role.customer["execution"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeInstanceAttribute", "ec2:DescribeInstanceTypes"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = var.region } } },
      {
        Effect = "Allow", Action = ["ec2:StopInstances"], Resource = local.instance_arns
        Condition = { StringEquals = {
          "aws:RequestedRegion"                = var.region
          "ec2:ResourceTag/finops:tenant"      = var.tenant_id
          "ec2:ResourceTag/finops:autopilot"   = "enabled"
          "ec2:ResourceTag/finops:environment" = "NON_PRODUCTION"
        } }
      },
      {
        Effect = "Allow", Action = ["ec2:StartInstances"], Resource = local.instance_arns
        Condition = { StringEquals = {
          "aws:RequestedRegion"                = var.region
          "ec2:ResourceTag/finops:tenant"      = var.tenant_id
          "ec2:ResourceTag/finops:environment" = "NON_PRODUCTION"
        } }
      },
      { Effect = "Deny", Action = ["ec2:TerminateInstances", "ec2:CreateTags", "ec2:DeleteTags", "ec2:ModifyInstanceAttribute", "iam:*", "organizations:*"], Resource = "*" }
    ]
  })
}
moved {
  from = aws_iam_role_policy.execution
  to   = aws_iam_role_policy.execution[0]
}
output "read_role_arn" { value = aws_iam_role.customer["read"].arn }
output "execution_role_arn" { value = var.enable_execution ? aws_iam_role.customer["execution"].arn : null }
