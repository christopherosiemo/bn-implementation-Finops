# Existing buckets/reports only. This module never creates S3 Inventory,
# logging, lifecycle rules, objects, retention changes or paid telemetry.
variable "enable_s3_readonly" {
  type        = bool
  default     = false
  description = "Optional S3 configuration and multipart metadata inspection; no customer object payload or mutation permissions."
}
variable "s3_bucket_arns" {
  type        = list(string)
  default     = []
  description = "Exact approved general-purpose bucket ARNs. Empty grants no bucket metadata permissions."
  validation {
    condition     = length(var.s3_bucket_arns) <= 256 && alltrue([for arn in var.s3_bucket_arns : can(regex("^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", arn))])
    error_message = "Use at most 256 literal general-purpose S3 bucket ARNs."
  }
}
variable "s3_read_regions" {
  type        = list(string)
  default     = ["eu-west-1"]
  description = "Explicit customer read regions; product processing and retained evidence remain in Ireland."
  validation {
    condition     = length(var.s3_read_regions) > 0 && length(var.s3_read_regions) <= 16 && alltrue([for region in var.s3_read_regions : can(regex("^[a-z]{2}-[a-z]+-[0-9]$", region)) && !startswith(region, "cn-")])
    error_message = "Use explicitly approved commercial AWS regions."
  }
}
variable "s3_report_reads" {
  type = list(object({
    bucket_arn       = string
    owner_account_id = string
    region           = string
    prefix           = string
    kms_key_arn      = optional(string)
  }))
  default     = []
  description = "Existing versioned Inventory/analysis/Lens destination prefixes only. These permissions never cover workload object payload."
  validation {
    condition = length(var.s3_report_reads) <= 16 && alltrue([for source in var.s3_report_reads :
      can(regex("^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", source.bucket_arn)) &&
      can(regex("^[0-9]{12}$", source.owner_account_id)) && contains(var.s3_read_regions, source.region) &&
      length(source.prefix) > 0 && length(source.prefix) <= 1024 && endswith(source.prefix, "/") &&
      !startswith(source.prefix, "/") && length(regexall("[?*\\\\\\r\\n]|\\.\\.|//", source.prefix)) == 0 &&
      (source.kms_key_arn == null || can(regex("^arn:aws:kms:${source.region}:${source.owner_account_id}:key/[a-f0-9-]+$", source.kms_key_arn)))
    ])
    error_message = "Use exact approved report prefixes, owners, regions and optional report-encryption KMS keys."
  }
}
variable "s3_storage_lens_arns" {
  type        = list(string)
  default     = []
  description = "Optional existing Storage Lens configurations; this creates no Lens configuration or export."
  validation {
    condition     = length(var.s3_storage_lens_arns) <= 16 && alltrue([for arn in var.s3_storage_lens_arns : can(regex("^arn:aws:s3:[a-z]{2}-[a-z]+-[0-9]:${var.expected_account_id}:storage-lens/[A-Za-z0-9_.-]+$", arn))])
    error_message = "Use exact same-account Storage Lens configuration ARNs."
  }
}
resource "aws_iam_role_policy" "s3_readonly" {
  count = var.enable_s3_readonly ? 1 : 0
  role  = aws_iam_role.customer["read"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{ Effect = "Allow", Action = ["s3:ListAllMyBuckets"], Resource = "*" },
      { Effect = "Allow", Action = ["pricing:GetProducts"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1" } } }],
      length(var.s3_bucket_arns) == 0 ? [] : [{
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration",
          "s3:GetBucketObjectLockConfiguration", "s3:GetLifecycleConfiguration", "s3:GetReplicationConfiguration",
          "s3:GetIntelligentTieringConfiguration", "s3:GetInventoryConfiguration", "s3:GetAnalyticsConfiguration",
          "s3:GetMetricsConfiguration", "s3:GetBucketPublicAccessBlock", "s3:GetBucketTagging",
          "s3:GetBucketLogging", "s3:GetBucketOwnershipControls", "s3:ListBucketMultipartUploads"
        ]
        Resource  = var.s3_bucket_arns
        Condition = { StringEquals = { "s3:ResourceAccount" = var.expected_account_id, "aws:RequestedRegion" = var.s3_read_regions } }
        }, {
        Effect    = "Allow"
        Action    = ["s3:ListMultipartUploadParts"]
        Resource  = [for arn in var.s3_bucket_arns : "${arn}/*"]
        Condition = { StringEquals = { "s3:ResourceAccount" = var.expected_account_id, "aws:RequestedRegion" = var.s3_read_regions } }
      }],
      flatten([for source in var.s3_report_reads : [
        { Effect = "Allow", Action = ["s3:GetBucketVersioning", "s3:GetBucketPolicy", "s3:GetBucketLocation"], Resource = source.bucket_arn, Condition = { StringEquals = { "s3:ResourceAccount" = source.owner_account_id, "aws:RequestedRegion" = source.region } } },
        { Effect = "Allow", Action = ["s3:ListBucket"], Resource = source.bucket_arn, Condition = { StringEquals = { "s3:ResourceAccount" = source.owner_account_id, "aws:RequestedRegion" = source.region }, StringLike = { "s3:prefix" = "${source.prefix}*" } } },
        { Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion"], Resource = "${source.bucket_arn}/${source.prefix}*", Condition = { StringEquals = { "s3:ResourceAccount" = source.owner_account_id, "aws:RequestedRegion" = source.region } } }
      ]]),
      [for source in var.s3_report_reads : {
        Effect    = "Allow", Action = ["kms:Decrypt"], Resource = source.kms_key_arn,
        Condition = { StringEquals = { "kms:ViaService" = "s3.${source.region}.amazonaws.com" }, StringLike = { "kms:EncryptionContext:aws:s3:arn" = ["${source.bucket_arn}/${source.prefix}*", source.bucket_arn] } }
      } if source.kms_key_arn != null],
      length(var.s3_storage_lens_arns) == 0 ? [] : [
        { Effect = "Allow", Action = ["s3:ListStorageLensConfigurations"], Resource = ["*"] },
        { Effect = "Allow", Action = ["s3:GetStorageLensConfiguration"], Resource = var.s3_storage_lens_arns }
      ]
    )
  })
}
