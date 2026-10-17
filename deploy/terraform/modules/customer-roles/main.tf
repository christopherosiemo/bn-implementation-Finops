terraform {
  required_version = ">= 1.9.0, < 2.0.0"
  required_providers { aws = { source = "hashicorp/aws", version = "~> 6.0" } }
}
data "aws_caller_identity" "customer" {}
data "aws_partition" "customer" {}

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
variable "read_principal_arn" { type = string }
variable "execution_principal_arn" { type = string }
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
  type = set(string)
  validation {
    condition     = length(var.instance_ids) > 0 && alltrue([for id in var.instance_ids : can(regex("^i-[0-9a-f]{8,17}$", id))])
    error_message = "Provide an explicit allowlist of EC2 instance IDs."
  }
}
variable "billing_bucket_arn" { type = string }
variable "billing_prefix" {
  type    = string
  default = "cur/"
}
variable "billing_kms_key_arn" {
  type    = string
  default = null
}

locals {
  roles         = { read = var.read_principal_arn, execution = var.execution_principal_arn }
  instance_arns = [for id in var.instance_ids : "arn:${data.aws_partition.customer.partition}:ec2:${var.region}:${data.aws_caller_identity.customer.account_id}:instance/${id}"]
}
resource "aws_iam_role" "customer" {
  for_each             = local.roles
  name                 = "${var.name}-${each.key}"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow", Principal = { AWS = each.value }, Action = "sts:AssumeRole"
      Condition = { StringEquals = { "sts:ExternalId" = var.external_id } }
    }]
  })
}
resource "aws_iam_role_policy" "read" {
  role = aws_iam_role.customer["read"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeVolumes", "ec2:DescribeTags", "ec2:DescribeReservedInstances", "savingsplans:DescribeSavingsPlans", "cloudwatch:GetMetricData", "cloudwatch:GetMetricStatistics", "cloudwatch:ListMetrics"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = var.region } } },
      { Effect = "Allow", Action = "s3:ListBucket", Resource = var.billing_bucket_arn, Condition = { StringLike = { "s3:prefix" = "${var.billing_prefix}*" } } },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion"], Resource = "${var.billing_bucket_arn}/${var.billing_prefix}*" }
    ]
  })
}
resource "aws_iam_role_policy" "billing_decrypt" {
  count  = var.billing_kms_key_arn != null ? 1 : 0
  role   = aws_iam_role.customer["read"].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = ["kms:Decrypt", "kms:DescribeKey"], Resource = var.billing_kms_key_arn }] })
}
resource "aws_iam_role_policy" "execution" {
  role = aws_iam_role.customer["execution"].id
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
output "read_role_arn" { value = aws_iam_role.customer["read"].arn }
output "execution_role_arn" { value = aws_iam_role.customer["execution"].arn }
