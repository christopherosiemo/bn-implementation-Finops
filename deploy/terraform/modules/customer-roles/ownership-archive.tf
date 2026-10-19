# Optional existing source only. No bucket, historical record, key, export or
# ownership assertion is created. Review the external identity mapping and key
# custody separately before commissioning the private source registration.
variable "ownership_archive_reads" {
  type = list(object({
    bucket_arn  = string
    prefix      = string
    kms_key_arn = optional(string)
  }))
  default     = []
  description = "At most four existing same-account Ireland ownership archive prefixes. Empty grants no archive read permissions."
  validation {
    condition = length(var.ownership_archive_reads) <= 4 && alltrue([for source in var.ownership_archive_reads :
      can(regex("^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", source.bucket_arn)) &&
      length(source.prefix) > 0 && length(source.prefix) <= 1024 && endswith(source.prefix, "/") &&
      !startswith(source.prefix, "/") && length(regexall("[?*\\\\\r\n]|\\.\\.|//", source.prefix)) == 0 &&
      (source.kms_key_arn == null || can(regex("^arn:aws:kms:eu-west-1:${var.expected_account_id}:key/[a-f0-9-]+$", source.kms_key_arn)))
    ])
    error_message = "Use bounded literal S3 prefixes and optional exact same-account Ireland KMS keys. Wildcards and parent paths are not accepted."
  }
}

resource "aws_iam_role_policy" "ownership_archive_read" {
  count = length(var.ownership_archive_reads) > 0 ? 1 : 0
  role  = aws_iam_role.customer["read"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(flatten([for source in var.ownership_archive_reads : [
      { Effect = "Allow", Action = ["s3:GetBucketVersioning", "s3:GetBucketPolicy", "s3:GetBucketLocation"], Resource = source.bucket_arn, Condition = { StringEquals = { "s3:ResourceAccount" = var.expected_account_id } } },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion"], Resource = "${source.bucket_arn}/${source.prefix}*", Condition = { StringEquals = { "s3:ResourceAccount" = var.expected_account_id } } }
      ]]), [for source in var.ownership_archive_reads :
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:DescribeKey"], Resource = source.kms_key_arn } if source.kms_key_arn != null
    ])
  })
}
