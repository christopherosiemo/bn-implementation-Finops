# Mock-only plans/state: never contacts AWS.
mock_provider "aws" {
  mock_resource "aws_iam_role" { defaults = { arn = "arn:aws:iam::123456789012:role/mock-native-test" } }
  mock_resource "aws_kms_key" { defaults = { arn = "arn:aws:kms:eu-west-1:123456789012:key/01234567-89ab-cdef-0123-456789abcdef" } }
  mock_resource "aws_s3_bucket" { defaults = { arn = "arn:aws:s3:::mock-native-raw" } }
  mock_data "aws_caller_identity" { defaults = { account_id = "123456789012" } }
  mock_data "aws_partition" { defaults = { partition = "aws" } }
  mock_data "aws_availability_zones" { defaults = { names = ["eu-west-1a", "eu-west-1b"] } }
  mock_resource "aws_eks_cluster" { defaults = { identity = [{ oidc = [{ issuer = "https://oidc.eks.eu-west-1.amazonaws.com/id/test" }] }] } }
  mock_resource "aws_db_instance" { defaults = { master_user_secret = [{ secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:test", kms_key_id = "test", secret_status = "active" }] } }
}
mock_provider "tls" {
  mock_data "tls_certificate" { defaults = { certificates = [{ sha1_fingerprint = "0000000000000000000000000000000000000000" }] } }
}
variables {
  expected_account_id        = "123456789012"
  pilot_owner                = "test-native-operator"
  pilot_expires_at           = "2099-01-01T00:00:00Z"
  monthly_budget_usd         = 100
  budget_notification_emails = ["test@example.invalid"]
  cluster_admin_role_arn     = "arn:aws:iam::123456789012:role/operator"
  operator_cidrs             = ["203.0.113.10/32"]
}
run "native_roles_unprovisioned_by_default" {
  command = plan
  assert {
    condition     = length(module.native_telemetry) == 0
    error_message = "An unset native tenant must not create storage identities."
  }
}
run "native_tenant_path_wildcard_is_rejected" {
  command = plan
  variables { telemetry_tenant_id = "tenant/*" }
  expect_failures = [var.telemetry_tenant_id]
}
run "hardware_identity_is_absent_by_default" {
  command = plan
  assert {
    condition     = length(module.hardware_reader) == 0 && output.hardware_reader_role_arn == null
    error_message = "Read-only bootstrap must not provision an unrequested hardware principal."
  }
}
run "hardware_identity_has_only_tenant_evidence_and_explicit_read_roles" {
  command = plan
  variables {
    hardware_tenant_id      = "tenant-hardware-test"
    customer_read_role_arns = ["arn:aws:iam::111122223333:role/customer-read"]
  }
  assert {
    condition     = length(module.hardware_reader) == 1 && length(aws_iam_role_policy.assume_execution) == 0
    error_message = "Hardware must not acquire execution, audit or unscoped object privileges."
  }
}
run "hardware_wildcard_tenant_rejected" {
  command = plan
  variables { hardware_tenant_id = "tenant/*" }
  expect_failures = [var.hardware_tenant_id]
}
