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
run "network_default_off" {
  command = plan
  assert {
    condition     = length(aws_iam_role_policy.network_readonly) == 0 && length(aws_iam_role_policy.execution) == 0 && output.execution_role_arn == null
    error_message = "New read-only installations have no network policy, execution credentials or resources."
  }
}
run "network_readonly_registered_logs" {
  command = plan
  variables {
    enable_network_readonly = true
    network_flow_log_reads = [{
      bucket_arn       = "arn:aws:s3:::network-commissioned-reports"
      owner_account_id = "111122223333"
      region           = "eu-west-1"
      prefix           = "AWSLogs/111122223333/vpcflowlogs/eu-west-1/"
    }]
  }
  assert {
    condition = length(aws_iam_role_policy.execution) == 0 && alltrue([for statement in jsondecode(aws_iam_role_policy.network_readonly[0].policy).Statement :
      alltrue([for action in statement.Action : startswith(action, "ec2:Describe") || action == "elasticloadbalancing:DescribeLoadBalancers" || action == "cloudwatch:GetMetricStatistics" || action == "pricing:GetProducts" || contains(["s3:GetBucketVersioning", "s3:GetBucketPolicy", "s3:GetBucketLocation", "s3:ListBucket", "s3:GetObject", "s3:GetObjectVersion"], action)])
      ]) && alltrue([for statement in jsondecode(aws_iam_role_policy.network_readonly[0].policy).Statement :
      !contains(statement.Action, "s3:GetObject") || statement.Resource == "arn:aws:s3:::network-commissioned-reports/AWSLogs/111122223333/vpcflowlogs/eu-west-1/*"
    ])
    error_message = "Network path reads must not grant mutations or workload payload reads."
  }
}
