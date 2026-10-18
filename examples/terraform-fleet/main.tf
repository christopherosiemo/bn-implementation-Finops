locals {

  suspended_processes = ["ReplaceUnhealthy", "AZRebalance", "InstanceRefresh", "ScheduledActions", "AlarmNotification"]
  tags = {

    "finops:tenant"            = var.tenant_id
    "finops:environment"       = "NON_PRODUCTION"
    "finops:stateless"         = "true"
    "finops:fleet-rightsizing" = "true"
    "finops:managed-by"        = "terraform"
    "finops:owner"             = var.owner

  }
  target_prefix = "arn:aws:elasticloadbalancing:${var.region}:${var.expected_account_id}:"

}

data "aws_ami" "application" {

  most_recent = false
  owners      = [var.image_owner_account_id]
  filter {
    name   = "image-id"
    values = [var.application_ami_id]
  }
  lifecycle {

    postcondition {

      condition     = self.id == var.application_ami_id && self.root_device_type == "ebs" && self.architecture == "x86_64" && self.virtualization_type == "hvm" && length(self.block_device_mappings) == 1 && alltrue([for mapping in self.block_device_mappings : mapping.device_name == self.root_device_name])
      error_message = "The exact EBS-backed x86_64 HVM application image is required."

    }

  }

}
data "aws_subnet" "private" {

  for_each = var.private_subnet_ids
  id       = each.value
  lifecycle {

    postcondition {

      condition     = self.vpc_id == var.vpc_id && self.owner_id == var.expected_account_id && !self.map_public_ip_on_launch && startswith(self.availability_zone, "eu-west-1")
      error_message = "Subnets must belong to the exact account/VPC in eu-west-1 and disable automatic public IPs."

    }

  }

}
data "aws_security_group" "application" {

  for_each = var.security_group_ids
  id       = each.value
  lifecycle {

    postcondition {

      condition     = self.vpc_id == var.vpc_id && self.arn == "arn:aws:ec2:${var.region}:${var.expected_account_id}:security-group/${each.value}"
      error_message = "Security groups must belong to the exact customer account and VPC."

    }

  }

}
data "aws_lb_listener" "existing" {
  arn = var.listener_arn
}
data "aws_lb_target_group" "old" {
  arn = var.old.target_group_arn
}
data "aws_lb_target_group" "candidate" {
  arn = var.candidate.target_group_arn
}

# Both templates and both ASGs must already exist in imported customer state.
# Resource creation/import/update is NOT authorized by this reference or its tests.
resource "aws_launch_template" "old" {

  name            = var.old.launch_template_name
  image_id        = data.aws_ami.application.id
  instance_type   = var.old.instance_type
  default_version = var.old.launch_template_version
  user_data       = var.user_data_base64
  iam_instance_profile {
    arn = var.instance_profile_arn
  }
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }
  network_interfaces {
    device_index                = 0
    associate_public_ip_address = false
    delete_on_termination       = true
    security_groups             = var.security_group_ids
  }
  block_device_mappings {

    device_name = data.aws_ami.application.root_device_name
    ebs {
      volume_type           = "gp3"
      volume_size           = var.root_volume_gib
      encrypted             = true
      kms_key_id            = var.root_kms_key_arn
      delete_on_termination = true
    }

  }
  tag_specifications {
    resource_type = "instance"
    tags          = local.tags
  }
  tag_specifications {
    resource_type = "volume"
    tags          = local.tags
  }
  tags = local.tags
  lifecycle {

    prevent_destroy = true
    precondition {
      condition     = var.runtime_updates_enabled
      error_message = "FLEET_RUNTIME_DISABLED: customer commissioning and signed pipeline authority are required."
    }
    postcondition {
      condition     = self.id == var.old.launch_template_id && self.latest_version == var.old.launch_template_version
      error_message = "The imported old template ID and concrete latest version must match; no template mutations are delegated."
    }
    precondition {
      condition     = startswith(var.instance_profile_arn, "arn:aws:iam::${var.expected_account_id}:instance-profile/") && startswith(var.root_kms_key_arn, "arn:aws:kms:${var.region}:${var.expected_account_id}:key/")
      error_message = "Instance profile and root-volume key must belong to the exact customer account and region."
    }

  }

}
resource "aws_launch_template" "candidate" {

  name            = var.candidate.launch_template_name
  image_id        = data.aws_ami.application.id
  instance_type   = var.candidate.instance_type
  default_version = var.candidate.launch_template_version
  user_data       = var.user_data_base64
  iam_instance_profile {
    arn = var.instance_profile_arn
  }
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }
  network_interfaces {
    device_index                = 0
    associate_public_ip_address = false
    delete_on_termination       = true
    security_groups             = var.security_group_ids
  }
  block_device_mappings {

    device_name = data.aws_ami.application.root_device_name
    ebs {
      volume_type           = "gp3"
      volume_size           = var.root_volume_gib
      encrypted             = true
      kms_key_id            = var.root_kms_key_arn
      delete_on_termination = true
    }

  }
  tag_specifications {
    resource_type = "instance"
    tags          = local.tags
  }
  tag_specifications {
    resource_type = "volume"
    tags          = local.tags
  }
  tags = local.tags
  lifecycle {

    prevent_destroy = true
    precondition {
      condition     = var.runtime_updates_enabled
      error_message = "FLEET_RUNTIME_DISABLED: customer commissioning and signed pipeline authority are required."
    }
    precondition {
      condition     = var.old.launch_template_id != var.candidate.launch_template_id && var.old.asg_name != var.candidate.asg_name
      error_message = "Old and candidate cohorts must be distinct physical groups and templates."
    }
    postcondition {
      condition     = self.id == var.candidate.launch_template_id && self.latest_version == var.candidate.launch_template_version
      error_message = "Candidate template must already exist at the reviewed concrete latest version."
    }

  }

}

resource "aws_autoscaling_group" "old" {

  name                      = var.old.asg_name
  desired_capacity          = var.old_desired_capacity
  min_size                  = var.old_desired_capacity
  max_size                  = var.old_desired_capacity
  desired_capacity_type     = "units"
  capacity_rebalance        = false
  protect_from_scale_in     = false
  force_delete              = false
  max_instance_lifetime     = 0
  vpc_zone_identifier       = var.private_subnet_ids
  target_group_arns         = [data.aws_lb_target_group.old.arn]
  health_check_type         = "ELB"
  health_check_grace_period = 300
  suspended_processes       = local.suspended_processes
  wait_for_capacity_timeout = "15m"
  wait_for_elb_capacity     = var.old_desired_capacity
  launch_template {
    id      = aws_launch_template.old.id
    version = tostring(var.old.launch_template_version)
  }
  dynamic "tag" {
    for_each = local.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
  lifecycle {

    prevent_destroy = true
    precondition {
      condition     = var.runtime_updates_enabled
      error_message = "FLEET_RUNTIME_DISABLED: no runtime updates are enabled by default."
    }
    precondition {
      condition     = length(toset([for s in data.aws_subnet.private : s.availability_zone])) >= 2
      error_message = "Existing private subnets must cover at least two eu-west-1 availability zones."
    }
    precondition {
      condition     = var.old_desired_capacity == 20 || (var.candidate_desired_capacity == 20 && var.candidate_traffic_percent == 100)
      error_message = "Old capacity is retained until the full candidate cohort serves all traffic and cleanup is separately approved."
    }

  }

}
resource "aws_autoscaling_group" "candidate" {

  name                      = var.candidate.asg_name
  desired_capacity          = var.candidate_desired_capacity
  min_size                  = var.candidate_desired_capacity
  max_size                  = var.candidate_desired_capacity
  desired_capacity_type     = "units"
  capacity_rebalance        = false
  protect_from_scale_in     = false
  force_delete              = false
  max_instance_lifetime     = 0
  vpc_zone_identifier       = var.private_subnet_ids
  target_group_arns         = [data.aws_lb_target_group.candidate.arn]
  health_check_type         = "ELB"
  health_check_grace_period = 300
  suspended_processes       = local.suspended_processes
  wait_for_capacity_timeout = "15m"
  wait_for_elb_capacity     = var.candidate_desired_capacity
  launch_template {
    id      = aws_launch_template.candidate.id
    version = tostring(var.candidate.launch_template_version)
  }
  dynamic "tag" {
    for_each = local.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
  lifecycle {

    prevent_destroy = true
    precondition {
      condition     = var.runtime_updates_enabled
      error_message = "FLEET_RUNTIME_DISABLED: no runtime updates are enabled by default."
    }

  }

}

resource "aws_lb_listener_rule" "app" {

  listener_arn = data.aws_lb_listener.existing.arn
  priority     = var.listener_priority
  action {

    type = "forward"
    forward {

      target_group {
        arn    = data.aws_lb_target_group.old.arn
        weight = 100 - var.candidate_traffic_percent
      }
      target_group {
        arn    = data.aws_lb_target_group.candidate.arn
        weight = var.candidate_traffic_percent
      }
      stickiness {
        enabled  = false
        duration = 1
      }

    }

  }
  condition {
    host_header {
      values = [var.host_header]
    }
  }
  lifecycle {

    prevent_destroy = true
    precondition {
      condition     = var.runtime_updates_enabled
      error_message = "FLEET_RUNTIME_DISABLED: no customer listener changes are enabled by default."
    }
    precondition {

      condition     = alltrue([for arn in [var.listener_arn, var.listener_rule_arn, var.old.target_group_arn, var.candidate.target_group_arn] : startswith(arn, local.target_prefix)]) && var.old.target_group_arn != var.candidate.target_group_arn
      error_message = "Listener, rule and two distinct target groups must belong to the exact account and eu-west-1."

    }
    precondition {

      condition     = data.aws_lb_listener.existing.protocol == "HTTPS" && alltrue([for tg in [data.aws_lb_target_group.old, data.aws_lb_target_group.candidate] : tg.target_type == "instance" && tg.vpc_id == var.vpc_id && contains(["HTTP", "HTTPS"], tg.protocol)])
      error_message = "Existing HTTPS application listener and HTTP(S) instance target groups in the exact VPC are required."

    }
    precondition {
      condition     = var.candidate_traffic_percent <= var.candidate_desired_capacity * 5
      error_message = "Candidate traffic cannot exceed its fraction of the twenty-member baseline; health and observation evidence are additional signed gates."
    }
    postcondition {
      condition     = self.arn == var.listener_rule_arn
      error_message = "Only the exact imported listener rule is in scope."
    }

  }

}

output "fleet_reference" {

  value = {

    schema_version = "4"
    provider       = "AWS"
    account_id     = var.expected_account_id
    region         = var.region
    environment    = "NON_PRODUCTION"
    initial_capacity = {
      old = 20, candidate = 0
    }
    old = {
      id = var.old.asg_name, asg_address = "aws_autoscaling_group.old", launch_template_address = "aws_launch_template.old", launch_template_version = var.old.launch_template_version, instance_type = var.old.instance_type, desired_count = var.old_desired_capacity
    }
    candidate = {
      id = var.candidate.asg_name, asg_address = "aws_autoscaling_group.candidate", launch_template_address = "aws_launch_template.candidate", launch_template_version = var.candidate.launch_template_version, instance_type = var.candidate.instance_type, desired_count = var.candidate_desired_capacity
    }
    traffic = {
      authority = "CUSTOMER_TERRAFORM_PIPELINE", address = "aws_lb_listener_rule.app", old_target_group_arn = var.old.target_group_arn, candidate_target_group_arn = var.candidate.target_group_arn, candidate_percent = var.candidate_traffic_percent
    }
    artifact_kind = "UNATTESTED_CONFIGURATION_REFERENCE"
    note          = "Reference configuration only; no approval, signed plan, pipeline receipt, live health or financial proof is implied."

  }

}
