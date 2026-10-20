mock_provider "aws" {
  mock_data "aws_caller_identity" { defaults = { account_id = "111122223333" } }
  mock_data "aws_partition" { defaults = { partition = "aws" } }
}
variables {
  expected_account_id = "111122223333"
  pilot_owner         = "test-operator"
  pilot_expires_at    = "2099-01-01T00:00:00Z"
  read_principal_arn  = "arn:aws:iam::123456789012:role/reader"
  external_id         = "test-external-id-more-than-32-characters"
  tenant_id           = "tenant-test"
  billing_bucket_arn  = null
}
run "lambda_default_off" {
  command = plan
  assert {
    condition     = length(aws_iam_role_policy.lambda_readonly) == 0 && length(aws_iam_role_policy.execution) == 0 && output.execution_role_arn == null
    error_message = "Ordinary read-only installations must not grant Lambda/log or execution permissions."
  }
}
run "lambda_existing_metadata_only" {
  command = plan
  variables { enable_lambda_readonly = true }
  assert {
    condition     = length(aws_iam_role_policy.execution) == 0 && alltrue([for statement in jsondecode(aws_iam_role_policy.lambda_readonly[0].policy).Statement : alltrue([for action in statement.Action : startswith(action, "lambda:List") || contains(["lambda:GetFunctionConfiguration", "lambda:GetFunctionConcurrency", "lambda:GetAccountSettings", "lambda:GetPolicy", "cloudwatch:GetMetricStatistics", "compute-optimizer:GetLambdaFunctionRecommendations"], action)])])
    error_message = "Lambda reads must not grant function, alias, concurrency, package download or logging mutations."
  }
}
run "lambda_logs_explicitly_commissioned" {
  command = plan
  variables {
    enable_lambda_readonly = true
    lambda_log_group_arns  = ["arn:aws:logs:eu-west-1:111122223333:log-group:/aws/lambda/approved-function"]
  }
  assert {
    condition     = alltrue([for statement in jsondecode(aws_iam_role_policy.lambda_readonly[0].policy).Statement : !contains(statement.Action, "logs:FilterLogEvents") || statement.Resource == ["arn:aws:logs:eu-west-1:111122223333:log-group:/aws/lambda/approved-function:*"]])
    error_message = "Log reads must be restricted to commissioned group ARNs."
  }
}
run "lambda_foreign_log_refused" {
  command = plan
  variables {
    enable_lambda_readonly = true
    lambda_log_group_arns  = ["arn:aws:logs:eu-west-1:999900001111:log-group:/aws/lambda/foreign"]
  }
  expect_failures = [var.lambda_log_group_arns]
}
