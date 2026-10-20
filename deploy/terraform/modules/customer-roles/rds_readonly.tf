# Optional observational RDS/Aurora vertical. Existing schedules/executors and
# customer configuration authority are unchanged. This grants no AWS mutation.
variable "enable_rds_readonly" {
  type        = bool
  default     = false
  description = "Read native RDS/Aurora inventory, orderable options, parameter values and regional reserved DB instances; no modify/purchase operations."
}
variable "enable_database_savings_plan_inventory" {
  type        = bool
  default     = false
  description = "Separately commissioned account-level Database Savings Plans inventory. Does not assert complete payer/linked-account portfolio coverage."
  validation {
    condition     = !var.enable_database_savings_plan_inventory || var.enable_rds_readonly
    error_message = "Database Savings Plans inventory requires the RDS observational reader."
  }
}
resource "aws_iam_role_policy" "rds_readonly" {
  count = var.enable_rds_readonly ? 1 : 0
  role  = aws_iam_role.customer["read"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["rds:DescribeDBInstances", "rds:DescribeDBClusters", "rds:DescribeReservedDBInstances", "rds:DescribeOrderableDBInstanceOptions", "rds:DescribeDBParameters", "rds:DescribeDBClusterParameters", "rds:DescribeValidDBInstanceModifications"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = var.region } } },
      # Pricing catalog is used only for published instance capacities. No list
      # rate is a customer NET/marginal price or verified saving.
      { Effect = "Allow", Action = ["pricing:GetProducts"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1" } } }
    ]
  })
}
resource "aws_iam_role_policy" "database_savings_plan_inventory" {
  count = var.enable_database_savings_plan_inventory ? 1 : 0
  role  = aws_iam_role.customer["read"].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["savingsplans:DescribeSavingsPlans"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = "us-east-1" } } }]
  })
}

variable "enable_rds_compute_optimizer" {
  type        = bool
  default     = false
  description = "Optional existing opt-in Compute Optimizer RDS recommendations. No enrollment or modification permission; provider monetary estimates are not customer NET cost."
  validation {
    condition     = !var.enable_rds_compute_optimizer || var.enable_rds_readonly
    error_message = "Optional Compute Optimizer reads require the RDS observational reader."
  }
}
resource "aws_iam_role_policy" "rds_compute_optimizer" {
  count = var.enable_rds_compute_optimizer ? 1 : 0
  role  = aws_iam_role.customer["read"].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["compute-optimizer:GetRDSDatabaseRecommendations"], Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = var.region } } }]
  })
}


