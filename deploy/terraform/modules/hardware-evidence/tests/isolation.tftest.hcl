# Native provider schema + mocked plans only; no provider credentials or apply.
mock_provider "aws" {}
variables {
  tenant_id               = "tenant-hardware-test"
  name                    = "finops-hardware-test"
  namespace               = "finops"
  region                  = "eu-west-1"
  oidc_provider_arn       = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/test"
  oidc_host               = "oidc.eks.eu-west-1.amazonaws.com/id/test"
  raw_bucket_arn          = "arn:aws:s3:::finops-raw"
  raw_key_arn             = "arn:aws:kms:eu-west-1:123456789012:key/01234567-89ab-cdef-0123-456789abcdef"
  customer_read_role_arns = ["arn:aws:iam::111122223333:role/customer-read"]
}
run "only_exact_identity_tenant_versions_and_read_targets" {
  command = plan
  assert {
    condition     = jsondecode(aws_iam_role.reader.assume_role_policy).Statement[0].Condition.StringEquals["oidc.eks.eu-west-1.amazonaws.com/id/test:sub"] == "system:serviceaccount:finops:finops-hardware-reader"
    error_message = "IRSA must bind only the dedicated hardware ServiceAccount."
  }
  assert {
    condition     = jsondecode(aws_iam_role_policy.archive.policy).Statement[0].Action == ["s3:PutObject", "s3:GetObjectVersion"] && jsondecode(aws_iam_role_policy.archive.policy).Statement[0].Resource == "arn:aws:s3:::finops-raw/tenant/tenant-hardware-test/hardware/*" && jsondecode(aws_iam_role_policy.archive.policy).Statement[1].Resource == var.raw_key_arn && jsondecode(aws_iam_role_policy.archive.policy).Statement[1].Condition.StringEquals["kms:ViaService"] == "s3.eu-west-1.amazonaws.com"
    error_message = "Hardware must not gain audit, cross-tenant, unversioned read, deletion or another encryption key."
  }
  assert {
    condition     = length(jsondecode(aws_iam_role_policy.assume_read[0].policy).Statement) == 1 && jsondecode(aws_iam_role_policy.assume_read[0].policy).Statement[0].Action == "sts:AssumeRole" && jsondecode(aws_iam_role_policy.assume_read[0].policy).Statement[0].Effect == "Allow" && toset(jsondecode(aws_iam_role_policy.assume_read[0].policy).Statement[0].Resource) == toset(var.customer_read_role_arns)
    error_message = "Only the explicit customer read roles may be assumed."
  }
}
run "no_customer_trust_without_explicit_targets" {
  command = plan
  variables { customer_read_role_arns = [] }
  assert {
    condition     = length(aws_iam_role_policy.assume_read) == 0
    error_message = "Empty read targets must confer no cross-account assumption permission."
  }
}
run "wildcard_tenant_rejected" {
  command = plan
  variables { tenant_id = "tenant/*" }
  expect_failures = [var.tenant_id]
}
run "non_irish_region_rejected" {
  command = plan
  variables { region = "us-east-1" }
  expect_failures = [var.region]
}
run "wildcard_customer_trust_rejected" {
  command = plan
  variables { customer_read_role_arns = ["arn:aws:iam::111122223333:role/*"] }
  expect_failures = [var.customer_read_role_arns]
}
run "same_account_customer_trust_rejected" {
  command = plan
  variables { customer_read_role_arns = ["arn:aws:iam::123456789012:role/customer-read"] }
  expect_failures = [var.customer_read_role_arns]
}
