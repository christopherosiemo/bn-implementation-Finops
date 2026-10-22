# Read-only RDS/Aurora is separately commissioned. These mock plans make no
# provider calls and create no resources.
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
run "database_reader_defaults_are_uncommissioned" {
  command = plan
  assert {
    condition     = length(aws_iam_role_policy.rds_readonly) == 0 && length(aws_iam_role_policy.database_savings_plan_inventory) == 0 && length(aws_iam_role_policy.rds_compute_optimizer) == 0 && length(aws_iam_role_policy.execution) == 0
    error_message = "Database reads and all execution authority must remain opt-in."
  }
}
run "database_reader_has_only_enumerated_region_bound_reads" {
  command = plan
  variables { enable_rds_readonly = true }
  assert {
    condition = (
      toset(flatten([for s in jsondecode(aws_iam_role_policy.rds_readonly[0].policy).Statement : s.Action])) == toset([
        "rds:DescribeDBInstances", "rds:DescribeDBClusters", "rds:DescribeReservedDBInstances", "rds:DescribeOrderableDBInstanceOptions", "rds:DescribeDBParameters", "rds:DescribeDBClusterParameters", "rds:DescribeValidDBInstanceModifications", "pricing:GetProducts"
      ]) &&
      jsondecode(aws_iam_role_policy.rds_readonly[0].policy).Statement[0].Condition.StringEquals["aws:RequestedRegion"] == var.region &&
      jsondecode(aws_iam_role_policy.rds_readonly[0].policy).Statement[1].Condition.StringEquals["aws:RequestedRegion"] == "us-east-1" &&
      length(aws_iam_role_policy.database_savings_plan_inventory) == 0 && length(aws_iam_role_policy.rds_compute_optimizer) == 0 && length(aws_iam_role_policy.execution) == 0 && output.execution_role_arn == null
    )
    error_message = "Database discovery may not add mutation, purchase, optional advice or execution capabilities."
  }
}
run "database_exposure_and_optimizer_are_separate_exact_reads" {
  command = plan
  variables {
    enable_rds_readonly                    = true
    enable_database_savings_plan_inventory = true
    enable_rds_compute_optimizer           = true
  }
  assert {
    condition = (
      toset(jsondecode(aws_iam_role_policy.database_savings_plan_inventory[0].policy).Statement[0].Action) == toset(["savingsplans:DescribeSavingsPlans"]) &&
      jsondecode(aws_iam_role_policy.database_savings_plan_inventory[0].policy).Statement[0].Condition.StringEquals["aws:RequestedRegion"] == "us-east-1" &&
      toset(jsondecode(aws_iam_role_policy.rds_compute_optimizer[0].policy).Statement[0].Action) == toset(["compute-optimizer:GetRDSDatabaseRecommendations"]) &&
      jsondecode(aws_iam_role_policy.rds_compute_optimizer[0].policy).Statement[0].Condition.StringEquals["aws:RequestedRegion"] == var.region && length(aws_iam_role_policy.execution) == 0
    )
    error_message = "Optional account exposure/advice must never add purchase, enrollment or modify APIs."
  }
}
run "database_exposure_requires_commissioned_database_reader" {
  command = plan
  variables { enable_database_savings_plan_inventory = true }
  expect_failures = [var.enable_database_savings_plan_inventory]
}
run "database_optimizer_requires_commissioned_database_reader" {
  command = plan
  variables { enable_rds_compute_optimizer = true }
  expect_failures = [var.enable_rds_compute_optimizer]
}
