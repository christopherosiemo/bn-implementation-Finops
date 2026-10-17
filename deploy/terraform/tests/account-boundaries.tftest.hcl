mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_availability_zones" {
    defaults = { names = ["eu-west-1a", "eu-west-1b"] }
  }
  mock_resource "aws_eks_cluster" {
    defaults = { identity = [{ oidc = [{ issuer = "https://oidc.eks.eu-west-1.amazonaws.com/id/test" }] }] }
  }
  mock_resource "aws_db_instance" {
    defaults = { master_user_secret = [{ secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:test", kms_key_id = "test", secret_status = "active" }] }
  }
}
mock_provider "tls" {
  mock_data "tls_certificate" {
    defaults = { certificates = [{ sha1_fingerprint = "0000000000000000000000000000000000000000" }] }
  }
}
variables {
  expected_account_id        = "123456789012"
  pilot_owner                = "test-operator"
  pilot_expires_at           = "2099-01-01T00:00:00Z"
  monthly_budget_usd         = 100
  budget_notification_emails = ["test@example.invalid"]
  cluster_admin_role_arn     = "arn:aws:iam::123456789012:role/operator"
  operator_cidrs             = ["203.0.113.10/32"]
}
run "empty_customer_allowlists_bootstrap_safely" {
  command = plan
  assert {
    condition     = length(aws_iam_role_policy.assume_read) == 0 && length(aws_iam_role_policy.assume_execution) == 0
    error_message = "Initial bootstrap must not grant customer role assumption."
  }
}
run "separate_customer_reader_is_allowed" {
  command = plan
  variables { customer_read_role_arns = ["arn:aws:iam::111122223333:role/reader"] }
  assert {
    condition     = length(aws_iam_role_policy.assume_read) == 1 && length(aws_iam_role_policy.assume_execution) == 0
    error_message = "Cross-account read-only trust must not grant execution."
  }
}
run "same_account_customer_reader_rejected" {
  command = plan
  variables { customer_read_role_arns = ["arn:aws:iam::123456789012:role/reader"] }
  expect_failures = [var.customer_read_role_arns]
}
run "same_account_customer_executor_rejected" {
  command = plan
  variables { customer_execution_role_arns = ["arn:aws:iam::123456789012:role/executor"] }
  expect_failures = [var.customer_execution_role_arns]
}
