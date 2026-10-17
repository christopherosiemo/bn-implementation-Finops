mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
}
variables {
  expected_account_id = "111122223333"
  pilot_owner         = "test-operator"
  pilot_expires_at    = "2099-01-01T00:00:00Z"
  read_principal_arn  = "arn:aws:iam::123456789012:role/reader"
  external_id         = "test-external-id-more-than-32-characters"
  tenant_id           = "tenant-test"
  billing_bucket_arn  = "arn:aws:s3:::test-billing"
}
run "read_only_creates_no_execution_identity" {
  command = plan
  assert {
    condition     = length(aws_iam_role.customer) == 1 && contains(keys(aws_iam_role.customer), "read") && length(aws_iam_role_policy.execution) == 0 && output.execution_role_arn == null
    error_message = "Fresh read-only onboarding must create no execution role or mutation policy."
  }
}
run "execution_is_explicit_and_scoped" {
  command = plan
  variables {
    enable_execution        = true
    execution_principal_arn = "arn:aws:iam::123456789012:role/executor"
    instance_ids            = ["i-0123456789abcdef0"]
  }
  assert {
    condition     = length(aws_iam_role.customer) == 2 && length(aws_iam_role_policy.execution) == 1 && strcontains(aws_iam_role_policy.execution[0].policy, "instance/i-0123456789abcdef0")
    error_message = "Enabled execution must remain scoped to the explicit instance."
  }
}
run "execution_rejects_missing_inputs" {
  command = plan
  variables { enable_execution = true }
  expect_failures = [var.execution_principal_arn, var.instance_ids]
}
run "discovery_without_billing_permissions" {
  command = plan
  variables { billing_bucket_arn = null }
  assert {
    condition     = !strcontains(aws_iam_role_policy.read.policy, "s3:") && length(aws_iam_role_policy.billing_decrypt) == 0
    error_message = "Discovery-only identity must not require billing-bucket permissions."
  }
}
run "wrong_account_rejected" {
  command = plan
  variables { expected_account_id = "999988887777" }
  expect_failures = [data.aws_caller_identity.customer]
}
run "same_account_reader_rejected" {
  command = plan
  variables { read_principal_arn = "arn:aws:iam::111122223333:role/reader" }
  expect_failures = [var.read_principal_arn]
}
run "same_account_executor_rejected" {
  command = plan
  variables {
    enable_execution        = true
    execution_principal_arn = "arn:aws:iam::111122223333:role/executor"
    instance_ids            = ["i-0123456789abcdef0"]
  }
  expect_failures = [var.execution_principal_arn]
}
