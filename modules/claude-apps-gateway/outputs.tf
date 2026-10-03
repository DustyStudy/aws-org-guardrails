output "ecr_repository_url" {
  description = "Push your built gateway image here before the first full apply (see README)."
  value       = aws_ecr_repository.gateway.repository_url
}

output "load_balancer_dns_name" {
  description = "Internal ALB DNS name - alias your gateway hostname to this in your private hosted zone."
  value       = aws_lb.gateway.dns_name
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster."
  value       = aws_ecs_cluster.gateway.name
}

output "ecs_service_name" {
  description = "Name of the ECS service."
  value       = aws_ecs_service.gateway.name
}

output "task_definition_arn" {
  description = "ARN of the registered task definition."
  value       = aws_ecs_task_definition.gateway.arn
}

output "jwt_secret_arn" {
  description = "ARN of the JWT signing key secret."
  value       = aws_secretsmanager_secret.jwt.arn
}

output "oidc_client_secret_arn" {
  description = "ARN of the OIDC client secret."
  value       = aws_secretsmanager_secret.oidc_client_secret.arn
}

output "postgres_url_secret_arn" {
  description = "ARN of the Postgres connection string secret."
  value       = aws_secretsmanager_secret.postgres_url.arn
}

output "database_endpoint" {
  description = "RDS endpoint address (already embedded in postgres_url_secret_arn's value - exposed here for reference/troubleshooting)."
  value       = aws_db_instance.gateway.address
}

output "kms_key_arn" {
  description = "ARN of the KMS key encrypting secrets, the ECR repository, and the log group."
  value       = aws_kms_key.gateway.arn
}

output "alb_logs_bucket_name" {
  description = "Name of the S3 bucket holding ALB access logs."
  value       = aws_s3_bucket.alb_logs.id
}
