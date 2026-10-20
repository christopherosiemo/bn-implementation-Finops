# Existing network topology and commissioned logs only. This creates no network
# resources, flow logs, telemetry, endpoints or execution credentials.
variable "enable_network_readonly" {
  type        = bool
  default     = false
  description = "Optional network Observe/Recommend metadata and existing Flow Log reads. No mutations."
}
variable "network_read_regions" {
  type    = list(string)
  default = ["eu-west-1"]
  validation {
    condition     = length(var.network_read_regions) > 0 && length(var.network_read_regions) <= 16 && alltrue([for region in var.network_read_regions : can(regex("^[a-z]{2}-[a-z]+-[0-9]$", region)) && !startswith(region, "cn-") && !startswith(region, "us-gov-")])
    error_message = "Use exact approved commercial customer read regions. Processing and evidence remain in Ireland."
  }
}
variable "network_flow_log_reads" {
  type = list(object({
    bucket_arn       = string
    owner_account_id = string
    region           = string
    prefix           = string
    kms_key_arn      = optional(string)
  }))
  default = []
  validation {
    condition = length(var.network_flow_log_reads) <= 16 && alltrue([for source in var.network_flow_log_reads :
      can(regex("^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", source.bucket_arn)) &&
      can(regex("^[0-9]{12}$", source.owner_account_id)) && contains(var.network_read_regions, source.region) &&
      length(source.prefix) > 0 && length(source.prefix) <= 1024 && endswith(source.prefix, "/") &&
      !startswith(source.prefix, "/") && length(regexall("[?*\\\\\\r\\n]|\\.\\.|//", source.prefix)) == 0 &&
      (source.kms_key_arn == null || can(regex("^arn:aws:kms:${source.region}:${source.owner_account_id}:key/[a-f0-9-]+$", source.kms_key_arn)))
    ])
    error_message = "Use exact already commissioned report owners, regions, prefixes and optional KMS keys."
  }
}
resource "aws_iam_role_policy" "network_readonly" {
  count = var.enable_network_readonly ? 1 : 0
  role  = aws_iam_role.customer["read"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      { Effect = "Allow", Resource = "*", Action = [
        "ec2:DescribeVpcs", "ec2:DescribeSubnets", "ec2:DescribeAvailabilityZones", "ec2:DescribeRouteTables",
        "ec2:DescribeNatGateways", "ec2:DescribeAddresses", "ec2:DescribeInternetGateways", "ec2:DescribeEgressOnlyInternetGateways",
        "ec2:DescribeNetworkInterfaces", "ec2:DescribeSecurityGroups", "ec2:DescribeVpcEndpoints", "ec2:DescribeVpcEndpointServices",
        "ec2:DescribeVpcPeeringConnections", "ec2:DescribeTransitGatewayAttachments", "ec2:DescribeFlowLogs", "ec2:DescribePrefixLists",
        "elasticloadbalancing:DescribeLoadBalancers", "cloudwatch:GetMetricStatistics"
      ], Condition = { StringEquals = { "aws:RequestedRegion" = var.network_read_regions } } },
      { Effect = "Allow", Resource = "*", Action = ["pricing:GetProducts"], Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1" } } }
      ], flatten([for source in var.network_flow_log_reads : [
        { Effect = "Allow", Action = ["s3:GetBucketVersioning", "s3:GetBucketPolicy", "s3:GetBucketLocation"], Resource = source.bucket_arn, Condition = { StringEquals = { "s3:ResourceAccount" = source.owner_account_id, "aws:RequestedRegion" = source.region } } },
        { Effect = "Allow", Action = ["s3:ListBucket"], Resource = source.bucket_arn, Condition = { StringEquals = { "s3:ResourceAccount" = source.owner_account_id, "aws:RequestedRegion" = source.region }, StringLike = { "s3:prefix" = "${source.prefix}*" } } },
        { Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion"], Resource = "${source.bucket_arn}/${source.prefix}*", Condition = { StringEquals = { "s3:ResourceAccount" = source.owner_account_id, "aws:RequestedRegion" = source.region } } }
        ]]), [for source in var.network_flow_log_reads : {
        Effect    = "Allow", Action = ["kms:Decrypt"], Resource = source.kms_key_arn,
        Condition = { StringEquals = { "kms:ViaService" = "s3.${source.region}.amazonaws.com" }, StringLike = { "kms:EncryptionContext:aws:s3:arn" = ["${source.bucket_arn}/${source.prefix}*", source.bucket_arn] } }
    } if source.kms_key_arn != null])
  })
}
