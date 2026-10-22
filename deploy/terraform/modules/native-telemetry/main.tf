terraform {
  required_version = ">= 1.9.0, < 2.0.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}
variable "tenant_id" {
  type = string
  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", var.tenant_id))
    error_message = "An exact safe tenant prefix is required."
  }
}
variable "name" { type = string }
variable "namespace" { type = string }
variable "region" { type = string }
variable "oidc_provider_arn" { type = string }
variable "oidc_host" { type = string }
variable "raw_bucket_arn" { type = string }
variable "raw_key_arn" { type = string }
locals { roles = toset(["telemetry-reader", "telemetry-ingress"]) }
resource "aws_iam_role" "transport" {
  for_each = local.roles
  name     = "${var.name}-${each.key}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = var.oidc_provider_arn }, Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${var.oidc_host}:aud" = "sts.amazonaws.com"
        "${var.oidc_host}:sub" = "system:serviceaccount:${var.namespace}:finops-${each.key}"
      } }
    }]
  })
}
resource "aws_iam_role_policy" "write" {
  for_each = local.roles
  name     = "tenant-native-evidence-write"
  role     = aws_iam_role.transport[each.key].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["s3:PutObject"], Resource = "${var.raw_bucket_arn}/tenant/${var.tenant_id}/native/*" },
    { Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:DescribeKey"], Resource = var.raw_key_arn }
  ] })
}
resource "aws_iam_role_policy" "read" {
  name = "tenant-native-versioned-read"
  role = aws_iam_role.transport["telemetry-reader"].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["s3:GetObjectVersion"], Resource = "${var.raw_bucket_arn}/tenant/${var.tenant_id}/native/*" },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = var.raw_key_arn, Condition = { StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" } } }
  ] })
}
output "role_arns" { value = { for role, value in aws_iam_role.transport : role => value.arn } }
