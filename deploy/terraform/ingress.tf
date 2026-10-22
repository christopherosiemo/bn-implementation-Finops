# Vendored upstream v3.6.0 policy; source/hash recorded in docs/deployment.md.
# Kept on a distinct controller identity, never on an application/node role.
resource "aws_iam_role" "load_balancer_controller" {
  name = "${var.name}-load-balancer-controller"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.cluster.arn }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${local.oidc_host}:aud" = "sts.amazonaws.com"
        "${local.oidc_host}:sub" = "system:serviceaccount:kube-system:aws-load-balancer-controller"
      } }
    }]
  })
}
resource "aws_iam_role_policy" "load_balancer_controller" {
  name   = "controller-v3-6-0"
  role   = aws_iam_role.load_balancer_controller.id
  policy = file("${path.module}/policies/aws-load-balancer-controller-v3.6.0.json")
}
resource "aws_iam_role_policy" "load_balancer_region" {
  name = "eu-west-1-regional-boundary"
  role = aws_iam_role.load_balancer_controller.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Deny", Action = ["ec2:*", "elasticloadbalancing:*", "acm:*"], Resource = "*"
      Condition = { StringNotEquals = { "aws:RequestedRegion" = var.region } }
    }]
  })
}
