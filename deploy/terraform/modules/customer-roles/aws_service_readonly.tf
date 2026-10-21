# Optional native metadata readers. These attach only to the existing read role.
# No task payloads, table items, Kubernetes authentication or secret decryption.
variable "enable_ecs_readonly" {
  type        = bool
  default     = false
  description = "Read existing ECS/Fargate inventory and service autoscaling metadata."
}
variable "enable_eks_readonly" {
  type        = bool
  default     = false
  description = "Read existing EKS infrastructure metadata; grants no Kubernetes API access."
}
variable "enable_elasticache_readonly" {
  type        = bool
  default     = false
  description = "Read existing ElastiCache topology and configuration; grants no cache data access."
}
variable "enable_dynamodb_readonly" {
  type        = bool
  default     = false
  description = "Read existing DynamoDB table/index configuration; grants no item or stream payload reads."
}
variable "enable_load_balancer_readonly" {
  type        = bool
  default     = false
  description = "Read existing ALB/NLB/Classic ELB metadata, target health and relationships."
}
variable "aws_service_read_regions" {
  type        = list(string)
  default     = ["eu-west-1"]
  description = "Explicit authorised customer metadata regions. Product processing remains in Ireland."
  validation {
    condition     = length(var.aws_service_read_regions) > 0 && length(var.aws_service_read_regions) <= 16 && alltrue([for region in var.aws_service_read_regions : can(regex("^[a-z]{2}-[a-z]+-[0-9]$", region)) && !startswith(region, "cn-") && !startswith(region, "us-gov-")])
    error_message = "Use explicit approved commercial customer regions."
  }
}
locals {
  aws_service_read_actions = {
    ecs = var.enable_ecs_readonly ? [
      "ecs:ListClusters", "ecs:DescribeClusters", "ecs:ListServices", "ecs:DescribeServices",
      "ecs:ListTaskDefinitions", "ecs:DescribeTaskDefinition",
      "ecs:ListTasks", "ecs:DescribeTasks", "ecs:DescribeCapacityProviders",
      "ecs:ListContainerInstances", "ecs:DescribeContainerInstances", "ecs:ListTagsForResource",
      "application-autoscaling:DescribeScalableTargets", "application-autoscaling:DescribeScalingPolicies", "application-autoscaling:DescribeScheduledActions"
    ] : []
    eks = var.enable_eks_readonly ? [
      "eks:ListClusters", "eks:DescribeCluster", "eks:ListNodegroups", "eks:DescribeNodegroup",
      "eks:ListFargateProfiles", "eks:DescribeFargateProfile", "eks:ListAddons", "eks:DescribeAddon", "eks:ListTagsForResource",
      "autoscaling:DescribeAutoScalingGroups", "ec2:DescribeInstances"
    ] : []
    elasticache = var.enable_elasticache_readonly ? [
      "elasticache:DescribeReplicationGroups", "elasticache:DescribeCacheClusters", "elasticache:DescribeServerlessCaches",
      "elasticache:DescribeCacheSubnetGroups", "elasticache:DescribeCacheParameterGroups", "elasticache:DescribeCacheParameters",
      "elasticache:DescribeSnapshots", "elasticache:DescribeServerlessCacheSnapshots", "elasticache:ListTagsForResource",
      "application-autoscaling:DescribeScalableTargets", "application-autoscaling:DescribeScalingPolicies", "application-autoscaling:DescribeScheduledActions"
    ] : []
    dynamodb = var.enable_dynamodb_readonly ? [
      "dynamodb:ListTables", "dynamodb:DescribeTable", "dynamodb:ListTagsOfResource", "dynamodb:DescribeContinuousBackups",
      "dynamodb:DescribeTimeToLive", "dynamodb:DescribeTableReplicaAutoScaling", "dynamodb:ListBackups",
      "application-autoscaling:DescribeScalableTargets", "application-autoscaling:DescribeScalingPolicies", "application-autoscaling:DescribeScheduledActions"
    ] : []
    load_balancer = var.enable_load_balancer_readonly ? [
      "elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeListeners", "elasticloadbalancing:DescribeRules",
      "elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTargetGroupAttributes", "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:DescribeTags", "elasticloadbalancing:DescribeInstanceHealth",
      "elasticloadbalancing:DescribeLoadBalancerPolicies"
    ] : []
  }
}
resource "aws_iam_role_policy" "aws_service_readonly" {
  for_each = { for family, actions in local.aws_service_read_actions : family => actions if length(actions) > 0 }
  role     = aws_iam_role.customer["read"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = each.value
      Resource = "*"
      Condition = { StringEquals = {
        "aws:RequestedRegion" = var.aws_service_read_regions
      } }
    }]
  })
}
