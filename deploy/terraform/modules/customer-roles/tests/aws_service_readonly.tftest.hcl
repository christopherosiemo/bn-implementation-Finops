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
run "service_metadata_disabled_by_default" {
  command = plan
  assert {
    condition     = length(aws_iam_role_policy.aws_service_readonly) == 0 && length(aws_iam_role.customer) == 1 && length(aws_iam_role_policy.execution) == 0 && output.execution_role_arn == null
    error_message = "Read-only defaults must grant no optional service permissions or execution identity."
  }
}
run "service_metadata_reads_only_with_explicit_opt_in" {
  command = plan
  variables {
    enable_ecs_readonly           = true
    enable_eks_readonly           = true
    enable_elasticache_readonly   = true
    enable_dynamodb_readonly      = true
    enable_load_balancer_readonly = true
  }
  assert {
    condition     = length(aws_iam_role_policy.aws_service_readonly) == 5 && length(aws_iam_role_policy.execution) == 0 && alltrue(flatten([for policy in aws_iam_role_policy.aws_service_readonly : [for statement in jsondecode(policy.policy).Statement : alltrue([for action in statement.Action : can(regex("^[a-z-]+:(List|Describe)[A-Za-z]+$", action))])]]))
    error_message = "Optional service readers must enumerate metadata List/Describe actions without mutations, payload reads, authentication or decryption."
  }
  assert {
    condition     = alltrue(flatten([for policy in aws_iam_role_policy.aws_service_readonly : [for statement in jsondecode(policy.policy).Statement : statement.Condition.StringEquals["aws:RequestedRegion"] == ["eu-west-1"] && statement.Effect == "Allow"]]))
    error_message = "Every optional service metadata grant must retain explicit approved-region scope."
  }
}
run "service_family_opt_ins_are_independent" {
  command = plan
  variables { enable_dynamodb_readonly = true }
  assert {
    condition     = keys(aws_iam_role_policy.aws_service_readonly) == ["dynamodb"] && !strcontains(aws_iam_role_policy.aws_service_readonly["dynamodb"].policy, "dynamodb:GetItem") && !strcontains(aws_iam_role_policy.aws_service_readonly["dynamodb"].policy, "dynamodb:Scan") && !strcontains(aws_iam_role_policy.aws_service_readonly["dynamodb"].policy, "dynamodb:GetRecords")
    error_message = "Selecting DynamoDB metadata must not grant other service families or table/stream payload reads."
  }
}
run "service_customer_read_regions_are_explicit" {
  command = plan
  variables {
    enable_ecs_readonly      = true
    aws_service_read_regions = ["eu-west-1", "eu-central-1"]
  }
  assert {
    condition     = jsondecode(aws_iam_role_policy.aws_service_readonly["ecs"].policy).Statement[0].Condition.StringEquals["aws:RequestedRegion"] == ["eu-west-1", "eu-central-1"] && length(aws_iam_role_policy.execution) == 0
    error_message = "Authorised metadata regions must not alter product region or enable customer execution."
  }
}
run "service_wildcard_regions_refused" {
  command = plan
  variables { aws_service_read_regions = ["*"] }
  expect_failures = [var.aws_service_read_regions]
}
