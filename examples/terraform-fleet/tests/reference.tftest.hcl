# Every run is a mocked provider PLAN. There is no apply, AWS identity, network
# provisioning or customer pipeline receipt in this acceptance.
mock_provider "aws" {

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111122223333"
    }
  }
  mock_data "aws_ami" {

    defaults = {

      id                    = "ami-0123456789abcdef0"
      root_device_type      = "ebs"
      root_device_name      = "/dev/xvda"
      architecture          = "x86_64"
      virtualization_type   = "hvm"
      block_device_mappings = [{ device_name = "/dev/xvda" }]

    }

  }
  mock_data "aws_security_group" {
    defaults = {
      arn = "arn:aws:ec2:eu-west-1:111122223333:security-group/sg-0123456789abcdef0", vpc_id = "vpc-0123456789abcdef0"
    }
  }
  mock_data "aws_lb_listener" {
    defaults = {
      protocol = "HTTPS"
    }
  }
  mock_data "aws_lb_target_group" {
    defaults = {
      vpc_id = "vpc-0123456789abcdef0", target_type = "instance", protocol = "HTTP"
    }
  }

}
override_data {

  target = data.aws_subnet.private["subnet-0123456789abcdef0"]
  values = {
    owner_id = "111122223333", vpc_id = "vpc-0123456789abcdef0", availability_zone = "eu-west-1a", map_public_ip_on_launch = false
  }

}
override_data {

  target = data.aws_subnet.private["subnet-1123456789abcdef0"]
  values = {
    owner_id = "111122223333", vpc_id = "vpc-0123456789abcdef0", availability_zone = "eu-west-1b", map_public_ip_on_launch = false
  }

}
override_resource {

  target = aws_launch_template.old
  values = {
    id = "lt-0123456789abcdef0", latest_version = 1
  }

}
override_resource {

  target = aws_launch_template.candidate
  values = {
    id = "lt-1123456789abcdef0", latest_version = 2
  }

}
override_resource {

  target = aws_lb_listener_rule.app
  values = {
    arn = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:listener-rule/app/reference/0123456789abcdef/1123456789abcdef/2123456789abcdef"
  }

}
variables {

  expected_account_id = "111122223333"
  tenant_id           = "tenant-reference"
  owner               = "reference-operator"
  old = {

    asg_name                = "fleet-reference-old"
    launch_template_name    = "fleet-reference-old"
    launch_template_id      = "lt-0123456789abcdef0"
    launch_template_version = 1
    instance_type           = "m6i.4xlarge"
    target_group_arn        = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/old/0123456789abcdef"

  }
  candidate = {

    asg_name                = "fleet-reference-candidate"
    launch_template_name    = "fleet-reference-candidate"
    launch_template_id      = "lt-1123456789abcdef0"
    launch_template_version = 2
    instance_type           = "m6i.2xlarge"
    target_group_arn        = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/candidate/1123456789abcdef"

  }
  application_ami_id     = "ami-0123456789abcdef0"
  image_owner_account_id = "111122223333"
  vpc_id                 = "vpc-0123456789abcdef0"
  private_subnet_ids     = ["subnet-0123456789abcdef0", "subnet-1123456789abcdef0"]
  security_group_ids     = ["sg-0123456789abcdef0"]
  instance_profile_arn   = "arn:aws:iam::111122223333:instance-profile/reference"
  root_kms_key_arn       = "arn:aws:kms:eu-west-1:111122223333:key/01234567-89ab-cdef-0123-456789abcdef"
  listener_arn           = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:listener/app/reference/0123456789abcdef/1123456789abcdef"
  listener_rule_arn      = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:listener-rule/app/reference/0123456789abcdef/1123456789abcdef/2123456789abcdef"
  listener_priority      = 100
  host_header            = "fleet.example.invalid"

}
run "disabled_by_default" {

  command = plan
  # ASGs depend on the blocked templates, so Terraform intentionally does not
  # reach their independent preconditions after these upstream failures.
  expect_failures = [aws_launch_template.old, aws_launch_template.candidate, aws_lb_listener_rule.app]

}
run "initial_imported_cohort_shape" {

  command = plan
  variables {
    runtime_updates_enabled = true
  }
  assert {

    condition     = aws_autoscaling_group.old.desired_capacity == 20 && aws_autoscaling_group.candidate.desired_capacity == 0 && aws_autoscaling_group.old.min_size == 20 && aws_autoscaling_group.old.max_size == 20 && aws_autoscaling_group.candidate.min_size == 0 && aws_autoscaling_group.candidate.max_size == 0
    error_message = "The explicit initial groups must be old=20 and candidate=0, with min=max=desired."

  }
  assert {

    condition     = aws_autoscaling_group.old.launch_template[0].version == "1" && aws_autoscaling_group.candidate.launch_template[0].version == "2" && aws_launch_template.candidate.instance_type == "m6i.2xlarge"
    error_message = "Launch template versions and candidate type must remain concrete."

  }
  assert {

    condition     = alltrue([for group in [aws_autoscaling_group.old, aws_autoscaling_group.candidate] : toset(group.suspended_processes) == toset(["ReplaceUnhealthy", "AZRebalance", "InstanceRefresh", "ScheduledActions", "AlarmNotification"]) && group.desired_capacity_type == "units" && !group.capacity_rebalance && !group.protect_from_scale_in && length(group.instance_refresh) == 0 && length(group.mixed_instances_policy) == 0])
    error_message = "No independent replacement/refresh/rebalance/scaling controller may conflict with the custom pipeline. Launch and Terminate must remain enabled."

  }
  assert {

    condition = alltrue([for group in [aws_autoscaling_group.old, aws_autoscaling_group.candidate] : alltrue([for tag in group.tag : tag.propagate_at_launch]) && {
      for tag in group.tag : tag.key => tag.value
      }["finops:tenant"] == "tenant-reference" && {
      for tag in group.tag : tag.key => tag.value
      }["finops:environment"] == "NON_PRODUCTION" && {
      for tag in group.tag : tag.key => tag.value
      }["finops:stateless"] == "true" && {
      for tag in group.tag : tag.key => tag.value
      }["finops:fleet-rightsizing"] == "true" && {
      for tag in group.tag : tag.key => tag.value
    }["finops:managed-by"] == "terraform"])
    error_message = "Exact native membership tags must propagate to every instance."

  }
  assert {

    condition = {
      for group in aws_lb_listener_rule.app.action[0].forward[0].target_group : group.arn => group.weight
      }[var.old.target_group_arn] == 100 && {
      for group in aws_lb_listener_rule.app.action[0].forward[0].target_group : group.arn => group.weight
    }[var.candidate.target_group_arn] == 0 && !aws_lb_listener_rule.app.action[0].forward[0].stickiness[0].enabled
    error_message = "The two explicit target groups must initially route old=100/candidate=0 without stickiness."

  }

}
run "warm_canary_before_traffic" {

  command = plan
  variables {
    runtime_updates_enabled    = true
    candidate_desired_capacity = 2
  }
  assert {

    condition     = aws_autoscaling_group.candidate.min_size == 2 && aws_autoscaling_group.candidate.max_size == 2 && aws_autoscaling_group.candidate.desired_capacity == 2 && output.fleet_reference.traffic.candidate_percent == 0
    error_message = "Warm two instances while keeping all customer traffic on the old cohort."

  }

}
run "canary_traffic_after_independent_health" {

  command = plan
  variables {
    runtime_updates_enabled    = true
    candidate_desired_capacity = 2
    candidate_traffic_percent  = 10
  }
  assert {

    condition     = output.fleet_reference.traffic.candidate_percent == 10 && output.fleet_reference.old.desired_count == 20 && output.fleet_reference.candidate.desired_count == 2
    error_message = "The configuration must express the separately authorized ten-percent canary."

  }

}
run "old_cleanup_requires_full_candidate" {

  command = plan
  variables {
    runtime_updates_enabled    = true
    old_desired_capacity       = 18
    candidate_desired_capacity = 2
    candidate_traffic_percent  = 10
  }
  expect_failures = [aws_autoscaling_group.old]

}
run "traffic_ahead_of_capacity_rejected" {

  command = plan
  variables {
    runtime_updates_enabled    = true
    candidate_desired_capacity = 2
    candidate_traffic_percent  = 25
  }
  expect_failures = [aws_lb_listener_rule.app]

}
run "wrong_caller_account_rejected" {

  command = plan
  variables {
    runtime_updates_enabled = true
  }
  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "999900001111"
    }
  }
  expect_failures = [data.aws_caller_identity.current]

}
run "wrong_region_rejected" {

  command = plan
  variables {
    runtime_updates_enabled = true
    region                  = "us-east-1"
  }
  expect_failures = [var.region]

}
