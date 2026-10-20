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
run "s3_reader_defaults_uncommissioned" {
  command = plan
  assert {
    condition     = length(aws_iam_role_policy.s3_readonly) == 0 && length(aws_iam_role_policy.execution) == 0 && output.execution_role_arn == null
    error_message = "Fresh read-only installations must not commission S3 report reads or customer mutations."
  }
}
run "s3_exact_metadata_and_report_prefix_only" {
  command = plan
  variables {
    enable_s3_readonly = true
    s3_bucket_arns     = ["arn:aws:s3:::approved-workload"]
    s3_report_reads = [{
      bucket_arn       = "arn:aws:s3:::approved-reports"
      owner_account_id = "111122223333"
      region           = "eu-west-1"
      prefix           = "inventory/"
    }]
  }
  assert {
    condition = (
      length(aws_iam_role_policy.execution) == 0 &&
      alltrue([for statement in jsondecode(aws_iam_role_policy.s3_readonly[0].policy).Statement :
        alltrue([for action in statement.Action : !startswith(action, "s3:Put") && !startswith(action, "s3:Delete") && !startswith(action, "s3:Restore") && !startswith(action, "s3:Abort") && !startswith(action, "s3:Create")])
      ]) &&
      alltrue([for statement in jsondecode(aws_iam_role_policy.s3_readonly[0].policy).Statement :
        !contains(statement.Action, "s3:GetObject") || statement.Resource == "arn:aws:s3:::approved-reports/inventory/*"
      ])
    )
    error_message = "S3 authority must remain observational and payload reads limited to exact approved report prefixes."
  }
}
