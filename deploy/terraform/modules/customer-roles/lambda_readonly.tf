# Existing Lambda configuration and explicitly commissioned logs only.
variable "enable_lambda_readonly" {
  type        = bool
  default     = false
  description = "Optional Lambda Observe/Recommend reads. No function, alias, concurrency or deployment mutation."
}
variable "lambda_read_regions" {
  type    = list(string)
  default = ["eu-west-1"]
  validation {
    condition     = length(var.lambda_read_regions) > 0 && length(var.lambda_read_regions) <= 16 && alltrue([for region in var.lambda_read_regions : can(regex("^[a-z]{2}-[a-z]+-[0-9]$", region)) && !startswith(region, "cn-") && !startswith(region, "us-gov-")])
    error_message = "Use explicit approved commercial customer read regions. Processing remains in Ireland."
  }
}
variable "lambda_log_group_arns" {
  type        = list(string)
  default     = []
  description = "Already commissioned Lambda log group ARNs without a wildcard or stream suffix. Empty grants no log access."
  validation {
    condition     = length(var.lambda_log_group_arns) <= 64 && alltrue([for arn in var.lambda_log_group_arns : can(regex("^arn:aws:logs:[a-z0-9-]+:[0-9]{12}:log-group:/aws/lambda/[A-Za-z0-9_./-]+$", arn)) && anytrue([for region in var.lambda_read_regions : startswith(arn, "arn:aws:logs:${region}:${var.expected_account_id}:log-group:")])])
    error_message = "Use exact existing Lambda log groups in the expected account and approved regions."
  }
}
resource "aws_iam_role_policy" "lambda_readonly" {
  count = var.enable_lambda_readonly ? 1 : 0
  role  = aws_iam_role.customer["read"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      { Effect = "Allow", Resource = "*", Action = ["lambda:ListFunctions", "lambda:ListEventSourceMappings", "lambda:GetAccountSettings", "cloudwatch:GetMetricStatistics", "compute-optimizer:GetLambdaFunctionRecommendations"], Condition = { StringEquals = { "aws:RequestedRegion" = var.lambda_read_regions } } },
      { Effect = "Allow", Resource = [for region in var.lambda_read_regions : "arn:aws:lambda:${region}:${var.expected_account_id}:function:*"], Action = ["lambda:GetFunctionConfiguration", "lambda:ListVersionsByFunction", "lambda:ListAliases", "lambda:GetFunctionConcurrency", "lambda:ListProvisionedConcurrencyConfigs", "lambda:ListFunctionEventInvokeConfigs", "lambda:ListFunctionUrlConfigs", "lambda:ListTags", "lambda:GetPolicy"], Condition = { StringEquals = { "aws:RequestedRegion" = var.lambda_read_regions } } }
      ], length(var.lambda_log_group_arns) == 0 ? [] : [
      { Effect = "Allow", Resource = [for arn in var.lambda_log_group_arns : "${arn}:*"], Action = ["logs:FilterLogEvents"], Condition = { StringEquals = { "aws:RequestedRegion" = var.lambda_read_regions } } }
    ])
  })
}
