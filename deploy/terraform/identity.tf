data "tls_certificate" "oidc" { url = aws_eks_cluster.pilot.identity[0].oidc[0].issuer }
resource "aws_iam_openid_connect_provider" "cluster" {
  url             = aws_eks_cluster.pilot.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.oidc.certificates[0].sha1_fingerprint]
}
locals { oidc_host = replace(aws_iam_openid_connect_provider.cluster.url, "https://", "") }

resource "aws_iam_role" "workload" {
  for_each = toset(["ingester", "signer", "executor"])
  name     = "${var.name}-${each.key}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.cluster.arn }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${local.oidc_host}:aud" = "sts.amazonaws.com"
        "${local.oidc_host}:sub" = "system:serviceaccount:${var.namespace}:finops-${each.key}"
      } }
    }]
  })
}
resource "aws_iam_role_policy" "ingester_evidence" {
  name = "evidence-ingestion"
  role = aws_iam_role.workload["ingester"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = aws_s3_bucket.evidence["raw"].arn },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"], Resource = "${aws_s3_bucket.evidence["raw"].arn}/*" },
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = "${aws_s3_bucket.evidence["audit"].arn}/*" },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"], Resource = aws_kms_key.purpose["raw"].arn },
      { Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:DescribeKey"], Resource = aws_kms_key.purpose["audit"].arn }
    ]
  })
}
resource "aws_iam_role_policy" "assume_read" {
  count = length(var.customer_read_role_arns) > 0 ? 1 : 0
  name  = "explicit-customer-read-roles"
  role  = aws_iam_role.workload["ingester"].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Resource = var.customer_read_role_arns }]
  })
}
resource "aws_iam_role_policy" "assume_execution" {
  count = length(var.customer_execution_role_arns) > 0 ? 1 : 0
  name  = "explicit-customer-execution-roles"
  role  = aws_iam_role.workload["executor"].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Resource = var.customer_execution_role_arns }]
  })
}
resource "aws_iam_role_policy" "signer_secret" {
  count = var.signer_secret_arn != null ? 1 : 0
  name  = "isolated-signing-key-secret"
  role  = aws_iam_role.workload["signer"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "secretsmanager:GetSecretValue", Resource = var.signer_secret_arn },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:DescribeKey"], Resource = aws_kms_key.purpose["signer"].arn,
      Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" } } }
    ]
  })
}
resource "aws_iam_role_policy" "execution_secret" {
  count = var.execution_secret_arn != null ? 1 : 0
  name  = "isolated-execution-secret"
  role  = aws_iam_role.workload["executor"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "secretsmanager:GetSecretValue", Resource = var.execution_secret_arn },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:DescribeKey"], Resource = aws_kms_key.purpose["execution"].arn,
      Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" } } }
    ]
  })
}

# Regional encrypted block storage for ClickHouse/Temporal pilot StatefulSets.
resource "aws_iam_role" "ebs_csi" {
  name = "${var.name}-ebs-csi"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.cluster.arn }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${local.oidc_host}:aud" = "sts.amazonaws.com"
        "${local.oidc_host}:sub" = "system:serviceaccount:kube-system:ebs-csi-controller-sa"
      } }
    }]
  })
}
resource "aws_iam_role_policy_attachment" "ebs_csi" {
  role       = aws_iam_role.ebs_csi.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}
resource "aws_eks_addon" "ebs_csi" {
  cluster_name             = aws_eks_cluster.pilot.name
  addon_name               = "aws-ebs-csi-driver"
  service_account_role_arn = aws_iam_role.ebs_csi.arn
  depends_on               = [aws_eks_node_group.private, aws_iam_role_policy_attachment.ebs_csi]
}
