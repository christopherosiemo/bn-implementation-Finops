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
run "ebs_reader_defaults_uncommissioned" {
  command = plan
  assert {
    condition     = length(aws_iam_role_policy.ebs_readonly) == 0 && length(aws_iam_role_policy.execution) == 0
    error_message = "EBS inventory must not add execution or be implicitly commissioned."
  }
}
run "ebs_reader_exact_region_bound_reads" {
  command = plan
  variables { enable_ebs_readonly = true }
  assert {
    condition = (
      toset(jsondecode(aws_iam_role_policy.ebs_readonly[0].policy).Statement[0].Action) == toset(["ec2:DescribeVolumes", "ec2:DescribeSnapshots", "ec2:DescribeImages", "ec2:DescribeFastSnapshotRestores", "ec2:DescribeSnapshotTierStatus", "ec2:DescribeLockedSnapshots", "ec2:DescribeSnapshotAttribute", "ec2:DescribeVolumesModifications", "ec2:DescribeVolumeStatus", "ec2:DescribeInstances", "ec2:DescribeInstanceTypes", "cloudwatch:GetMetricStatistics", "config:GetResourceConfigHistory", "config:DescribeConfigurationRecorders", "config:DescribeConfigurationRecorderStatus", "cloudtrail:LookupEvents"]) &&
      jsondecode(aws_iam_role_policy.ebs_readonly[0].policy).Statement[0].Condition.StringEquals["aws:RequestedRegion"] == var.region &&
      length(aws_iam_role_policy.execution) == 0 && output.execution_role_arn == null
    )
    error_message = "EBS reader must have only exact read operations and retain the regional fence."
  }
}
