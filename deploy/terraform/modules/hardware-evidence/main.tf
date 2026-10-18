terraform {
  required_version = ">= 1.9.0, < 2.0.0"
  required_providers { aws = { source = "hashicorp/aws", version = "~> 6.0" } }
}
variable "tenant_id" {
  type = string
  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", var.tenant_id))
    error_message = "Hardware storage requires an exact safe tenant prefix."
  }
}
variable "name" { type = string }
variable "namespace" { type = string }
variable "region" {
  type = string
  validation {
    condition     = var.region == "eu-west-1"
    error_message = "Hardware evidence must remain in eu-west-1."
  }
}
variable "oidc_provider_arn" { type = string }
variable "oidc_host" { type = string }
variable "raw_bucket_arn" { type = string }
variable "raw_key_arn" { type = string }
variable "customer_read_role_arns" {
  type = list(string)
  validation {
    condition     = length(toset(var.customer_read_role_arns)) == length(var.customer_read_role_arns) && alltrue([for arn in var.customer_read_role_arns : can(regex("^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", arn)) && try(split(":", arn)[4], "") != try(split(":", var.oidc_provider_arn)[4], "")])
    error_message = "Only distinct exact roles in separate workload accounts may be assumed."
  }
}
resource "aws_iam_role" "reader" {
  name = "${var.name}-hardware-reader"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Federated = var.oidc_provider_arn }, Action = "sts:AssumeRoleWithWebIdentity"
    Condition = { StringEquals = {
      "${var.oidc_host}:aud" = "sts.amazonaws.com"
      "${var.oidc_host}:sub" = "system:serviceaccount:${var.namespace}:finops-hardware-reader"
    } }
  }] })
}
resource "aws_iam_role_policy" "archive" {
  name = "tenant-hardware-versioned-evidence"
  role = aws_iam_role.reader.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["s3:PutObject", "s3:GetObjectVersion"], Resource = "${var.raw_bucket_arn}/tenant/${var.tenant_id}/hardware/*" },
    { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"], Resource = var.raw_key_arn,
    Condition = { StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" } } }
  ] })
}
resource "aws_iam_role_policy" "assume_read" {
  count = length(var.customer_read_role_arns) > 0 ? 1 : 0
  name  = "explicit-hardware-customer-read-roles"
  role  = aws_iam_role.reader.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = "sts:AssumeRole", Resource = var.customer_read_role_arns }
  ] })
}
output "role_arn" { value = aws_iam_role.reader.arn }
