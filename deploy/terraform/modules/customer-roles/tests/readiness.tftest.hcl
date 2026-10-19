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
run "trusted_billing_permissions_are_opt_in" {
  command = plan
  assert {
    condition     = length(aws_iam_role_policy.trusted_billing) == 0 && length(aws_iam_role_policy.commitment_inventory) == 0 && output.billing_writer_boundary_policy == null
    error_message = "Discovery defaults must not grant global financial-source capabilities."
  }
}
run "trusted_billing_remains_read_only" {
  command = plan
  variables {
    billing_export_arns         = ["arn:aws:bcm-data-exports:us-east-1:111122223333:export/registered-export"]
    enable_commitment_inventory = true
  }
  assert {
    condition     = length(aws_iam_role_policy.trusted_billing) == 1 && strcontains(aws_iam_role_policy.trusted_billing[0].policy, "bcm-data-exports:GetExecution") && !strcontains(aws_iam_role_policy.trusted_billing[0].policy, "CreateExport") && strcontains(aws_iam_role_policy.commitment_inventory[0].policy, "ec2:DescribeRegions") && !strcontains(aws_iam_role_policy.commitment_inventory[0].policy, "Purchase") && strcontains(output.billing_writer_boundary_policy, "StringNotEqualsIfExists") && length(aws_iam_role_policy.execution) == 0
    error_message = "Billing must bind the exact existing export and complete read-only scope without adding mutation authority."
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
run "hardware_reader_is_optional_and_has_no_customer_mutation_role" {
  command = plan
  variables { hardware_read_principal_arn = "arn:aws:iam::123456789012:role/hardware-reader" }
  assert {
    condition     = length(aws_iam_role.customer) == 1 && length(aws_iam_role_policy.execution) == 0 && strcontains(aws_iam_role.customer["read"].assume_role_policy, "role/hardware-reader") && strcontains(aws_iam_role_policy.read.policy, "ec2:DescribeImages") && strcontains(aws_iam_role_policy.read.policy, "ec2:DescribeInstanceTypeOfferings") && !strcontains(aws_iam_role_policy.read.policy, "StopInstances")
    error_message = "Additional hardware trust must remain explicit and read-only."
  }
}
run "hardware_reader_cannot_borrow_main_ingester_principal" {
  command = plan
  variables { hardware_read_principal_arn = "arn:aws:iam::123456789012:role/reader" }
  expect_failures = [var.hardware_read_principal_arn]
}

# Mock plans only: no AWS API, provisioning, credentials, bucket or key creation.
run "decision_source_defaults_add_no_quote_archive_or_execution_authority" {
  command = plan
  assert {
    condition = (
      length(aws_iam_role.customer) == 1 &&
      length(aws_iam_role_policy.execution) == 0 &&
      length(aws_iam_role_policy.commitment_inventory) == 0 &&
      length(aws_iam_role_policy.ownership_archive_read) == 0 &&
      output.execution_role_arn == null &&
      !strcontains(aws_iam_role_policy.read.policy, "savingsplans:") &&
      strcontains(aws_iam_role_policy.read.policy, "autoscaling:DescribeAutoScalingInstances") &&
      strcontains(aws_iam_role_policy.read.policy, "aws:RequestedRegion") &&
      length(regexall(":(Create|Put|Delete|Modify|Purchase|Update|Start|Stop|Terminate)", aws_iam_role_policy.read.policy)) == 0
    )
    error_message = "Default discovery may read native ASG membership but must not gain quotes, private archives or any customer mutation."
  }
}

run "quote_lookup_requires_separate_complete_inventory_approval" {
  command = plan
  variables { enable_commitment_quotes = true }
  expect_failures = [var.enable_commitment_quotes]
}

run "controller_discovery_rejects_a_different_target_region" {
  command = plan
  variables { region = "us-east-1" }
  expect_failures = [var.region]
}

run "quote_lookup_adds_only_exact_native_read_actions" {
  command = plan
  variables {
    enable_commitment_inventory = true
    enable_commitment_quotes    = true
  }
  assert {
    condition = (
      toset(flatten([for statement in jsondecode(aws_iam_role_policy.commitment_inventory[0].policy).Statement : statement.Action])) == toset([
        "ec2:DescribeRegions", "ec2:DescribeReservedInstances",
        "savingsplans:DescribeSavingsPlans", "organizations:DescribeOrganization", "organizations:ListAccounts",
        "savingsplans:DescribeSavingsPlanRates", "savingsplans:DescribeSavingsPlansOfferings", "savingsplans:DescribeSavingsPlansOfferingRates"
      ]) &&
      jsondecode(aws_iam_role_policy.commitment_inventory[0].policy).Statement[2].Resource == "arn:aws:savingsplans::111122223333:savingsplan/*" &&
      jsondecode(aws_iam_role_policy.commitment_inventory[0].policy).Statement[2].Condition.StringEquals["aws:RequestedRegion"] == "us-east-1" &&
      jsondecode(aws_iam_role_policy.commitment_inventory[0].policy).Statement[3].Condition.StringEquals["aws:RequestedRegion"] == "us-east-1" &&
      length(aws_iam_role_policy.execution) == 0 && output.execution_role_arn == null
    )
    error_message = "Quotes must remain native Describe calls, with account-bound held-plan rates and no purchase/mutation role."
  }
}

run "ownership_archive_is_exact_existing_prefix_read_only" {
  command = plan
  variables {
    billing_bucket_arn = null
    ownership_archive_reads = [{
      bucket_arn  = "arn:aws:s3:::ownership-source"
      prefix      = "tenant-one/history/"
      kms_key_arn = "arn:aws:kms:eu-west-1:111122223333:key/00000000-0000-4000-8000-000000000001"
    }]
  }
  assert {
    condition = (
      length(aws_iam_role_policy.ownership_archive_read) == 1 &&
      length(jsondecode(aws_iam_role_policy.ownership_archive_read[0].policy).Statement) == 3 &&
      toset(flatten([for statement in jsondecode(aws_iam_role_policy.ownership_archive_read[0].policy).Statement : statement.Action])) == toset([
        "s3:GetBucketVersioning", "s3:GetBucketPolicy", "s3:GetBucketLocation", "s3:GetObject", "s3:GetObjectVersion", "kms:Decrypt", "kms:DescribeKey"
      ]) &&
      jsondecode(aws_iam_role_policy.ownership_archive_read[0].policy).Statement[0].Resource == "arn:aws:s3:::ownership-source" &&
      jsondecode(aws_iam_role_policy.ownership_archive_read[0].policy).Statement[1].Resource == "arn:aws:s3:::ownership-source/tenant-one/history/*" &&
      jsondecode(aws_iam_role_policy.ownership_archive_read[0].policy).Statement[0].Condition.StringEquals["s3:ResourceAccount"] == "111122223333" &&
      jsondecode(aws_iam_role_policy.ownership_archive_read[0].policy).Statement[1].Condition.StringEquals["s3:ResourceAccount"] == "111122223333" &&
      jsondecode(aws_iam_role_policy.ownership_archive_read[0].policy).Statement[2].Resource == "arn:aws:kms:eu-west-1:111122223333:key/00000000-0000-4000-8000-000000000001" &&
      length(aws_iam_role_policy.execution) == 0 && output.execution_role_arn == null
    )
    error_message = "Existing original archives may only be read at the exact registered prefix/account/key; no writes, ownership assertion or execution are provisioned."
  }
}

run "ownership_archive_without_kms_has_no_decrypt_grant" {
  command = plan
  variables { ownership_archive_reads = [{ bucket_arn = "arn:aws:s3:::ownership-source", prefix = "tenant-one/history/" }] }
  assert {
    condition     = length(jsondecode(aws_iam_role_policy.ownership_archive_read[0].policy).Statement) == 2 && !strcontains(aws_iam_role_policy.ownership_archive_read[0].policy, "kms:")
    error_message = "A source without an explicitly registered KMS key must not acquire KMS permissions."
  }
}

run "ownership_archive_rejects_wildcard_prefix" {
  command = plan
  variables { ownership_archive_reads = [{ bucket_arn = "arn:aws:s3:::ownership-source", prefix = "tenant-*/history/" }] }
  expect_failures = [var.ownership_archive_reads]
}
run "ownership_archive_rejects_parent_path" {
  command = plan
  variables { ownership_archive_reads = [{ bucket_arn = "arn:aws:s3:::ownership-source", prefix = "tenant-one/../history/" }] }
  expect_failures = [var.ownership_archive_reads]
}
run "ownership_archive_rejects_bucket_object_arn" {
  command = plan
  variables { ownership_archive_reads = [{ bucket_arn = "arn:aws:s3:::ownership-source/arbitrary-object", prefix = "tenant-one/history/" }] }
  expect_failures = [var.ownership_archive_reads]
}
run "ownership_archive_rejects_wrong_key_account" {
  command = plan
  variables { ownership_archive_reads = [{ bucket_arn = "arn:aws:s3:::ownership-source", prefix = "tenant-one/history/", kms_key_arn = "arn:aws:kms:eu-west-1:999988887777:key/00000000-0000-4000-8000-000000000001" }] }
  expect_failures = [var.ownership_archive_reads]
}
run "ownership_archive_rejects_wrong_key_region" {
  command = plan
  variables { ownership_archive_reads = [{ bucket_arn = "arn:aws:s3:::ownership-source", prefix = "tenant-one/history/", kms_key_arn = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-4000-8000-000000000001" }] }
  expect_failures = [var.ownership_archive_reads]
}
run "ownership_archive_rejects_unbounded_source_list" {
  command = plan
  variables {
    ownership_archive_reads = [
      { bucket_arn = "arn:aws:s3:::ownership-source", prefix = "one/" },
      { bucket_arn = "arn:aws:s3:::ownership-source", prefix = "two/" },
      { bucket_arn = "arn:aws:s3:::ownership-source", prefix = "three/" },
      { bucket_arn = "arn:aws:s3:::ownership-source", prefix = "four/" },
      { bucket_arn = "arn:aws:s3:::ownership-source", prefix = "five/" }
    ]
  }
  expect_failures = [var.ownership_archive_reads]
}
