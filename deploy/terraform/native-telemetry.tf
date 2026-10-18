# Optional isolated native telemetry identities. Null preserves existing plans.
variable "telemetry_tenant_id" {
  type        = string
  default     = null
  nullable    = true
  description = "Exact tenant prefix for optional native telemetry storage roles. Terraform never supplies application credentials."
  validation {
    condition     = var.telemetry_tenant_id == null ? true : can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", var.telemetry_tenant_id))
    error_message = "Provide an exact safe tenant ID or null; wildcards and path separators are forbidden."
  }
}
module "native_telemetry" {
  count             = var.telemetry_tenant_id == null ? 0 : 1
  source            = "./modules/native-telemetry"
  tenant_id         = var.telemetry_tenant_id
  name              = var.name
  namespace         = var.namespace
  region            = var.region
  oidc_provider_arn = aws_iam_openid_connect_provider.cluster.arn
  oidc_host         = local.oidc_host
  raw_bucket_arn    = aws_s3_bucket.evidence["raw"].arn
  raw_key_arn       = aws_kms_key.purpose["raw"].arn
}
output "native_telemetry_role_arns" {
  value = var.telemetry_tenant_id == null ? {} : module.native_telemetry[0].role_arns
}
