# Optional source-read capability only. This module does not create/update a
# Data Export or customer billing bucket, and never purchases commitments.
variable "billing_export_arns" {
  type        = set(string)
  default     = []
  description = "One existing payer CUR2 Data Export for the configured billing prefix. Empty preserves discovery-only defaults."
  validation {
    condition     = length(var.billing_export_arns) <= 1 && alltrue([for arn in var.billing_export_arns : can(regex("^arn:aws:bcm-data-exports:us-east-1:${var.expected_account_id}:export/[^*?]+$", arn))]) && (length(var.billing_export_arns) == 0 || var.billing_bucket_arn != null)
    error_message = "Trusted billing requires one exact payer-scoped us-east-1 export ARN and a configured bucket."
  }
}
variable "enable_commitment_inventory" {
  type        = bool
  default     = false
  description = "Explicitly allow read-only EC2 RI inventory in every enabled region and global Savings Plans/Organizations inventory. Enable separately in every linked-account read role."
}
variable "enable_commitment_quotes" {
  type        = bool
  default     = false
  description = "Optional read-only native SP rates and NoUpfront offering quotes. This never permits purchase or modification."
  validation {
    condition     = !var.enable_commitment_quotes || var.enable_commitment_inventory
    error_message = "Commitment quotes require separately approved complete inventory access."
  }
}

resource "aws_iam_role_policy" "trusted_billing" {
  count = length(var.billing_export_arns) > 0 ? 1 : 0
  role  = aws_iam_role.customer["read"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["bcm-data-exports:GetExecution", "bcm-data-exports:ListExecutions"], Resource = var.billing_export_arns, Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1" } } },
      # Invoicing does not support invoice/account resource ARNs. The assumed
      # payer role and API AccountId selector supply the account boundary.
      { Effect = "Allow", Action = ["invoicing:ListInvoiceSummaries"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1" } } }
    ]
  })
}
resource "aws_iam_role_policy" "commitment_inventory" {
  count = var.enable_commitment_inventory ? 1 : 0
  role  = aws_iam_role.customer["read"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      { Effect = "Allow", Action = ["ec2:DescribeRegions", "ec2:DescribeReservedInstances"], Resource = "*" },
      { Effect = "Allow", Action = ["savingsplans:DescribeSavingsPlans", "organizations:DescribeOrganization", "organizations:ListAccounts"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1" } } }
      ], var.enable_commitment_quotes ? [
      { Effect = "Allow", Action = ["savingsplans:DescribeSavingsPlanRates"], Resource = "arn:aws:savingsplans::${var.expected_account_id}:savingsplan/*", Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1" } } },
      { Effect = "Allow", Action = ["savingsplans:DescribeSavingsPlansOfferings", "savingsplans:DescribeSavingsPlansOfferingRates"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1" } } }
    ] : [])
  })
}

# Review and merge this output into the EXISTING customer bucket policy. It is
# an output only: no provisioning or customer policy mutation occurs here.
output "billing_writer_boundary_policy" {
  value = length(var.billing_export_arns) == 1 && var.billing_bucket_arn != null ? jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      { Sid = "ExactDataExportBucketRead", Effect = "Allow", Principal = { Service = "bcm-data-exports.amazonaws.com" }, Action = ["s3:GetBucketPolicy"], Resource = var.billing_bucket_arn, Condition = { StringEquals = { "aws:SourceAccount" = var.expected_account_id, "aws:SourceArn" = one(var.billing_export_arns) } } },
      { Sid = "ExactDataExportWriter", Effect = "Allow", Principal = { Service = "bcm-data-exports.amazonaws.com" }, Action = ["s3:PutObject"], Resource = "${var.billing_bucket_arn}/${var.billing_prefix}*", Condition = { StringEquals = { "aws:SourceAccount" = var.expected_account_id, "aws:SourceArn" = one(var.billing_export_arns) } } }
      ], [for condition, expected in {
        "aws:PrincipalServiceName" = "bcm-data-exports.amazonaws.com"
        "aws:SourceAccount"        = var.expected_account_id
        "aws:SourceArn"            = one(var.billing_export_arns)
        } : {
        Effect = "Deny", Principal = "*", Action = ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"], Resource = "${var.billing_bucket_arn}/${var.billing_prefix}*", Condition = { StringNotEqualsIfExists = { (condition) = expected } }
    }])
  }) : null
}
