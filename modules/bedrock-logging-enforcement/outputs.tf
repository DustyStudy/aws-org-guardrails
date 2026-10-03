output "lambda_function_arn" {
  description = "ARN of the enforcement Lambda function."
  value       = aws_lambda_function.enforcement.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic used for drift notifications."
  value       = aws_sns_topic.enforcement.arn
}

output "bedrock_log_bucket_name" {
  description = "Name of the S3 bucket Bedrock delivers invocation logs to."
  value       = aws_s3_bucket.bedrock_logs.id
}

output "bedrock_log_group_name" {
  description = "Name of the CloudWatch Logs group Bedrock delivers invocation logs to."
  value       = aws_cloudwatch_log_group.bedrock_logs.name
}
