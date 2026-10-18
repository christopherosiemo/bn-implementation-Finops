# Optional evidence reader only. Empty defaults provision no additional role.
variable "hardware_tenant_id" {
  type    = string
  default = ""
  validation {
    condition     = var.hardware_tenant_id == "" || can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", var.hardware_tenant_id))
    error_message = "Hardware evidence requires one exact safe tenant prefix."
  }
}
module "hardware_reader" {
  count                   = var.hardware_tenant_id == "" ? 0 : 1
  source                  = "./modules/hardware-evidence"
  tenant_id               = var.hardware_tenant_id
  name                    = var.name
  namespace               = var.namespace
  region                  = var.region
  oidc_provider_arn       = aws_iam_openid_connect_provider.cluster.arn
  oidc_host               = local.oidc_host
  raw_bucket_arn          = aws_s3_bucket.evidence["raw"].arn
  raw_key_arn             = aws_kms_key.purpose["raw"].arn
  customer_read_role_arns = var.customer_read_role_arns
}
output "hardware_reader_role_arn" { value = try(module.hardware_reader[0].role_arn, null) }
