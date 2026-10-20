# Optional EBS observational inventory/dependency reads. No volume, snapshot,
# retention, attachment, IAM, purchase or execution mutation is granted.
variable "enable_ebs_readonly" {
  type        = bool
  default     = false
  description = "Read EBS volume/snapshot dependencies and native modification state; no mutation or deletion authority."
}
resource "aws_iam_role_policy" "ebs_readonly" {
  count = var.enable_ebs_readonly ? 1 : 0
  role  = aws_iam_role.customer["read"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = ["ec2:DescribeVolumes", "ec2:DescribeSnapshots", "ec2:DescribeImages", "ec2:DescribeFastSnapshotRestores", "ec2:DescribeSnapshotTierStatus", "ec2:DescribeLockedSnapshots", "ec2:DescribeSnapshotAttribute", "ec2:DescribeVolumesModifications", "ec2:DescribeVolumeStatus", "ec2:DescribeInstances", "ec2:DescribeInstanceTypes", "cloudwatch:GetMetricStatistics", "config:GetResourceConfigHistory", "config:DescribeConfigurationRecorders", "config:DescribeConfigurationRecorderStatus", "cloudtrail:LookupEvents"]
      Resource  = "*"
      Condition = { StringEquals = { "aws:RequestedRegion" = var.region } }
    }]
  })
}
