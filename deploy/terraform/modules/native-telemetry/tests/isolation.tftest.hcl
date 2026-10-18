mock_provider "aws" {}
variables {
  tenant_id         = "tenant-native-pilot"
  name              = "finops-test"
  namespace         = "finops"
  region            = "eu-west-1"
  oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/test"
  oidc_host         = "oidc.eks.eu-west-1.amazonaws.com/id/test"
  raw_bucket_arn    = "arn:aws:s3:::finops-native-raw"
  raw_key_arn       = "arn:aws:kms:eu-west-1:123456789012:key/01234567-89ab-cdef-0123-456789abcdef"
}
run "isolated_native_storage" {
  command = plan
  assert {
    condition     = length(aws_iam_role.transport) == 2 && length(aws_iam_role_policy.write) == 2
    error_message = "Each native transport needs a distinct role."
  }
  assert {
    condition     = alltrue([for role, policy in aws_iam_role_policy.write : jsondecode(policy.policy).Statement[0].Action == ["s3:PutObject"] && jsondecode(policy.policy).Statement[0].Resource == "arn:aws:s3:::finops-native-raw/tenant/tenant-native-pilot/native/*"])
    error_message = "Native writers must not gain reads, compute mutation, cross-tenant paths or signing capability."
  }
  assert {
    condition     = jsondecode(aws_iam_role_policy.read.policy).Statement[0].Action == ["s3:GetObjectVersion"] && jsondecode(aws_iam_role_policy.read.policy).Statement[1].Action == ["kms:Decrypt"]
    error_message = "Only the reader gets version-pinned S3 access with constrained raw-key decryption."
  }
  assert {
    condition     = alltrue([for role, value in aws_iam_role.transport : jsondecode(value.assume_role_policy).Statement[0].Condition.StringEquals["oidc.eks.eu-west-1.amazonaws.com/id/test:sub"] == "system:serviceaccount:finops:finops-${role}"])
    error_message = "IRSA must bind each exact service account."
  }
}
run "wildcard_tenant_denied" {
  command = plan
  variables { tenant_id = "tenant/*" }
  expect_failures = [var.tenant_id]
}
