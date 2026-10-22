resource "aws_s3_bucket" "evidence" {
  for_each            = toset(["raw", "audit"])
  bucket              = "${var.name}-${local.account_id}-${var.region}-${each.key}"
  force_destroy       = false
  object_lock_enabled = true
  lifecycle { prevent_destroy = true }
}
resource "aws_s3_bucket_versioning" "evidence" {
  for_each = aws_s3_bucket.evidence
  bucket   = each.value.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  for_each = aws_s3_bucket.evidence
  bucket   = each.value.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = each.key == "raw" ? var.raw_retention_days : var.audit_retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.evidence]
}
resource "aws_s3_bucket_public_access_block" "evidence" {
  for_each                = aws_s3_bucket.evidence
  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_ownership_controls" "evidence" {
  for_each = aws_s3_bucket.evidence
  bucket   = each.value.id
  rule { object_ownership = "BucketOwnerEnforced" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  for_each = aws_s3_bucket.evidence
  bucket   = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.purpose[each.key].arn
    }
    bucket_key_enabled = true
  }
}
resource "aws_s3_bucket_policy" "evidence" {
  for_each = aws_s3_bucket.evidence
  bucket   = each.value.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = "s3:*"
        Resource  = [each.value.arn, "${each.value.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyApplicationDeletion", Effect = "Deny", Principal = "*"
        Action    = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention"]
        Resource  = "${each.value.arn}/*"
        Condition = { ArnEquals = { "aws:PrincipalArn" = [for role in aws_iam_role.workload : role.arn] } }
      }
    ]
  })
}
