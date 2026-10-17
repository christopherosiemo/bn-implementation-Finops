variable "region" {
  type    = string
  default = "eu-west-1"
  validation {
    condition     = var.region == "eu-west-1"
    error_message = "This pilot is restricted to eu-west-1. Review residency before extending it."
  }
}

variable "name" {
  type    = string
  default = "finops-pilot"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,23}$", var.name))
    error_message = "Use 3-24 lowercase letters, numbers, and hyphens, starting with a letter."
  }
}

variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/16"
}
variable "kubernetes_version" {
  type    = string
  default = "1.35"
}
variable "namespace" {
  type    = string
  default = "finops"
}
variable "cluster_admin_role_arn" {
  type        = string
  description = "Existing operator IAM role granted EKS administrator access. Do not use an IAM user."
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/", var.cluster_admin_role_arn))
    error_message = "Provide an existing AWS IAM role ARN."
  }
}
variable "operator_cidrs" {
  type        = list(string)
  description = "Operator/VPN public CIDRs allowed to the EKS API; no world-open endpoint."
  validation {
    condition     = length(var.operator_cidrs) > 0 && alltrue([for cidr in var.operator_cidrs : can(cidrhost(cidr, 0)) && !contains(["0.0.0.0/0", "::/0"], cidr)])
    error_message = "Provide specific operator or VPN CIDRs; 0.0.0.0/0 and ::/0 are forbidden."
  }
}
variable "node_instance_types" {
  type    = list(string)
  default = ["m6i.large"]
}
variable "node_desired_size" {
  type    = number
  default = 2
}
variable "node_min_size" {
  type    = number
  default = 2
}
variable "node_max_size" {
  type    = number
  default = 4
}
variable "database_instance_class" {
  type    = string
  default = "db.t4g.medium"
}
variable "database_multi_az" {
  type    = bool
  default = true
}
variable "raw_retention_days" {
  type    = number
  default = 90
}
variable "audit_retention_days" {
  type    = number
  default = 365
}
variable "customer_read_role_arns" {
  type        = list(string)
  default     = []
  description = "Explicit customer read roles the isolated ingester may assume."
}
variable "customer_execution_role_arns" {
  type        = list(string)
  default     = []
  description = "Explicit customer execution roles the isolated executor may assume."
}
variable "signer_secret_arn" {
  type        = string
  default     = null
  description = "Existing Secrets Manager Ed25519 private-key secret, encrypted with the signer KMS key. Terraform never creates its value."
}
variable "execution_secret_arn" {
  type        = string
  default     = null
  description = "Existing execution service secret encrypted with the execution KMS key."
}
