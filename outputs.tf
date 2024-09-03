output "vpc_id" {
  value       = aws_vpc.doublecloud.id
  description = "ID of the created VPC. DoubleCloud resources will be created in this VPC."
}

output "iam_role_arn" {
  value       = aws_iam_role.doublecloud.arn
  description = "ARN of the IAM Role that has permissions to create resources in the VPC."

  depends_on = [time_sleep.sleep_to_avoid_iam_race]
}

output "region_id" {
  value       = local.region
  description = "AWS Region where resources will be created."
}

output "account_id" {
  value       = local.account_id
  description = "AWS Account ID where resources will be created."
}
