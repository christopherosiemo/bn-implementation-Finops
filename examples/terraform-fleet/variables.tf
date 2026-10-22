variable "expected_account_id" {

  type = string
  validation {

    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "An exact twelve-digit AWS customer account is required."

  }

}
variable "region" {

  type    = string
  default = "eu-west-1"
  validation {

    condition     = var.region == "eu-west-1"
    error_message = "This bounded fleet reference supports eu-west-1 only."

  }

}
variable "runtime_updates_enabled" {

  type        = bool
  default     = false
  description = "Accidental-run guard only. True is neither an import receipt, human approval, signed child plan nor permission to apply."

}
variable "tenant_id" {

  type = string
  validation {

    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", var.tenant_id))
    error_message = "A non-wildcard tenant identity is required."

  }

}
variable "owner" {

  type = string
  validation {

    condition     = length(trimspace(var.owner)) > 0 && length(var.owner) <= 128
    error_message = "An explicit workload owner is required."

  }

}
variable "old" {

  type = object({

    asg_name                = string
    launch_template_name    = string
    launch_template_id      = string
    launch_template_version = number
    instance_type           = string
    target_group_arn        = string

  })
  validation {

    condition     = can(regex("^lt-[a-f0-9]{8}([a-f0-9]{9})?$", var.old.launch_template_id)) && var.old.launch_template_version >= 1 && floor(var.old.launch_template_version) == var.old.launch_template_version
    error_message = "The old launch template must exist and use a concrete positive integer version."

  }

}
variable "candidate" {

  type = object({

    asg_name                = string
    launch_template_name    = string
    launch_template_id      = string
    launch_template_version = number
    instance_type           = string
    target_group_arn        = string

  })
  validation {

    condition     = can(regex("^lt-[a-f0-9]{8}([a-f0-9]{9})?$", var.candidate.launch_template_id)) && var.candidate.launch_template_version >= 1 && floor(var.candidate.launch_template_version) == var.candidate.launch_template_version
    error_message = "The candidate template must already exist at a concrete reviewed version; $Latest and $Default are unsupported."

  }

}
variable "old_desired_capacity" {

  type    = number
  default = 20
  validation {

    condition     = var.old_desired_capacity >= 0 && var.old_desired_capacity <= 20 && floor(var.old_desired_capacity) == var.old_desired_capacity
    error_message = "Old capacity must be an integer from zero to the twenty-member baseline."

  }

}
variable "candidate_desired_capacity" {

  type    = number
  default = 0
  validation {

    condition     = var.candidate_desired_capacity >= 0 && var.candidate_desired_capacity <= 20 && floor(var.candidate_desired_capacity) == var.candidate_desired_capacity
    error_message = "Candidate capacity must be an integer from zero to the twenty-member surge ceiling."

  }

}
variable "candidate_traffic_percent" {

  type    = number
  default = 0
  validation {

    condition     = contains([0, 10, 25, 50, 100], var.candidate_traffic_percent)
    error_message = "Traffic must use the reviewed 0/10/25/50/100 percent milestones."

  }

}
variable "application_ami_id" {

  type = string
  validation {

    condition     = can(regex("^ami-[a-f0-9]{8}([a-f0-9]{9})?$", var.application_ami_id))
    error_message = "An exact reviewed application AMI is required; no most-recent lookup is supported."

  }

}
variable "image_owner_account_id" {

  type = string
  validation {

    condition     = can(regex("^[0-9]{12}$", var.image_owner_account_id)) && var.image_owner_account_id == var.expected_account_id
    error_message = "This bounded reference requires a customer-owned application AMI in the exact AWS account."

  }

}
variable "vpc_id" {

  type = string
  validation {

    condition     = can(regex("^vpc-[a-f0-9]{8}([a-f0-9]{9})?$", var.vpc_id))
    error_message = "An existing private VPC is required."

  }

}
variable "private_subnet_ids" {

  type = set(string)
  validation {

    condition     = length(var.private_subnet_ids) >= 2 && alltrue([for id in var.private_subnet_ids : can(regex("^subnet-[a-f0-9]{8}([a-f0-9]{9})?$", id))])
    error_message = "At least two distinct existing private subnets are required."

  }

}
variable "security_group_ids" {

  type = set(string)
  validation {

    condition     = length(var.security_group_ids) >= 1 && alltrue([for id in var.security_group_ids : can(regex("^sg-[a-f0-9]{8}([a-f0-9]{9})?$", id))])
    error_message = "Existing application security groups are required."

  }

}
variable "instance_profile_arn" {
  type = string
}
variable "root_kms_key_arn" {
  type = string
}
variable "root_volume_gib" {

  type    = number
  default = 20
  validation {

    condition     = var.root_volume_gib >= 8 && var.root_volume_gib <= 1024 && floor(var.root_volume_gib) == var.root_volume_gib
    error_message = "Root EBS size must be a reviewed integer from 8 to 1024 GiB."

  }

}
variable "user_data_base64" {

  type        = string
  default     = null
  nullable    = true
  sensitive   = true
  description = "Exact existing launch-template application bootstrap, if any. Never put credentials in user data."
  validation {

    condition     = var.user_data_base64 == null ? true : can(base64decode(var.user_data_base64))
    error_message = "User data must be an exact base64 string or null."

  }

}
variable "listener_arn" {
  type = string
}
variable "listener_rule_arn" {
  type = string
}
variable "listener_priority" {

  type = number
  validation {

    condition     = var.listener_priority >= 1 && var.listener_priority <= 50000 && floor(var.listener_priority) == var.listener_priority
    error_message = "Use the exact existing listener-rule priority."

  }

}
variable "host_header" {

  type = string
  validation {

    condition     = can(regex("^[a-z0-9][a-z0-9.-]+$", var.host_header))
    error_message = "An exact existing hostname without wildcard routing is required."

  }

}
