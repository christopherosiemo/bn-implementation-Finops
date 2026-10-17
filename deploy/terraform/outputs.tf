output "cluster_name" { value = aws_eks_cluster.pilot.name }
output "database_address" { value = aws_db_instance.pilot.address }
output "database_master_secret_arn" { value = aws_db_instance.pilot.master_user_secret[0].secret_arn }
output "raw_bucket" { value = aws_s3_bucket.evidence["raw"].id }
output "audit_bucket" { value = aws_s3_bucket.evidence["audit"].id }
output "workload_role_arns" { value = { for role, value in aws_iam_role.workload : role => value.arn } }
output "kms_key_arns" { value = { for purpose, value in aws_kms_key.purpose : purpose => value.arn } }
output "residency" { value = "eu-west-1 / EU pilot" }
output "vpc_id" { value = aws_vpc.pilot.id }
output "load_balancer_controller_role_arn" { value = aws_iam_role.load_balancer_controller.arn }
