output "lambda_function_name" {
  description = "Name of the remediator Lambda function."
  value       = aws_lambda_function.remediator.function_name
}

output "lambda_function_arn" {
  description = "ARN of the remediator Lambda function."
  value       = aws_lambda_function.remediator.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic that receives remediation notifications."
  value       = aws_sns_topic.remediation_alerts.arn
}

output "log_group_name" {
  description = "CloudWatch Logs group for the remediator Lambda."
  value       = aws_cloudwatch_log_group.remediator.name
}

output "event_rule_names" {
  description = "Names of the EventBridge rules that trigger the remediator."
  value       = { for key, rule in local.event_rules : key => rule.name }
}

output "demo_bucket_name" {
  description = "Name of the optional demo bucket, if created."
  value       = var.create_demo_bucket ? aws_s3_bucket.demo[0].id : null
}
