# Reference deployment of the Claude apps gateway on AWS. Mirrors
# https://code.claude.com/docs/en/claude-apps-gateway-on-aws as Terraform.
# A working example for customer-managed infrastructure, not a supported
# production deployment - review and adapt before relying on it.
#
# Two-phase apply: the ECS service needs a real image in ECR before it can
# start, so:
#
#   terraform apply -target=aws_ecr_repository.gateway
#   # build and push your image using the printed repository_url
#   terraform apply
#
# The second apply is a no-op for the repository and creates everything
# else, including the ECS service.

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_elb_service_account" "main" {}

# ---------------------------------------------------------------------
# KMS - one customer-managed key for Secrets Manager, ECR, and the
# gateway's CloudWatch log group.
# ---------------------------------------------------------------------
resource "aws_kms_key" "gateway" {
  description         = "Encrypts the ${var.name_prefix} gateway's secrets, ECR repository, and log group."
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogsUseOfKey"
        Effect    = "Allow"
        Principal = { Service = "logs.${data.aws_region.current.region}.amazonaws.com" }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*",
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/ecs/${var.name_prefix}"
          }
        }
      },
    ]
  })
}

resource "aws_kms_alias" "gateway" {
  name          = "alias/${var.name_prefix}"
  target_key_id = aws_kms_key.gateway.key_id
}

# ---------------------------------------------------------------------
# Security groups - chain the traffic path: corporate CIDR -> ALB:443 ->
# gateway:8080 -> Postgres:5432. Egress is scoped to exactly what each
# tier needs, not a blanket allow-all.
# ---------------------------------------------------------------------
resource "aws_security_group" "alb" {
  name_prefix = "${var.name_prefix}-alb-"
  description = "Claude apps gateway ALB - HTTPS from the corporate network only."
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from corporate network"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.corporate_cidr]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "alb_to_gateway" {
  description              = "Forward to the gateway service"
  type                     = "egress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  security_group_id        = aws_security_group.alb.id
  source_security_group_id = aws_security_group.gateway.id
}

resource "aws_security_group" "gateway" {
  name_prefix = "${var.name_prefix}-svc-"
  description = "Claude apps gateway ECS service - reachable from the ALB only."
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "gateway_from_alb" {
  description              = "Accept traffic forwarded by the ALB"
  type                     = "ingress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  security_group_id        = aws_security_group.gateway.id
  source_security_group_id = aws_security_group.alb.id
}

#trivy:ignore:AWS-0104 HTTPS to the IdP and AWS APIs, whose addresses aren't fixed; port-scoped.
resource "aws_security_group_rule" "gateway_egress_https" {
  # Bedrock (if not using the VPC endpoint), the IdP, ECR, Secrets
  # Manager, and CloudWatch Logs are all reached over HTTPS to
  # destinations that aren't knowable in advance, so this is scoped to
  # the port, not the destination.
  description       = "HTTPS to Bedrock/IdP/ECR/Secrets Manager/CloudWatch Logs"
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.gateway.id
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "gateway_to_db" {
  description              = "Postgres to the gateway store"
  type                     = "egress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.gateway.id
  source_security_group_id = aws_security_group.db.id
}

resource "aws_security_group" "db" {
  name_prefix = "${var.name_prefix}-db-"
  description = "Claude apps gateway RDS for PostgreSQL - reachable from the gateway service only."
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "db_from_gateway" {
  description              = "Postgres from the gateway service"
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.db.id
  source_security_group_id = aws_security_group.gateway.id
}

resource "aws_security_group" "bedrock_endpoint" {
  # checkov:skip=CKV2_AWS_5: Attached via security_group_ids on
  # aws_vpc_endpoint.bedrock_runtime below - Checkov's static analysis
  # doesn't resolve the count-conditional index reference used there.
  count = var.create_bedrock_vpc_endpoint ? 1 : 0

  name_prefix = "${var.name_prefix}-bedrock-endpoint-"
  description = "Claude apps gateway Bedrock VPC endpoint - reachable from the gateway service only."
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "bedrock_endpoint_from_gateway" {
  count = var.create_bedrock_vpc_endpoint ? 1 : 0

  description              = "HTTPS from the gateway service"
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.bedrock_endpoint[0].id
  source_security_group_id = aws_security_group.gateway.id
}

resource "aws_vpc_endpoint" "bedrock_runtime" {
  count = var.create_bedrock_vpc_endpoint ? 1 : 0

  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.bedrock_endpoint[0].id]
  private_dns_enabled = true
}

# ---------------------------------------------------------------------
# IAM - two distinct roles. The task role is what the gateway's AWS SDK
# uses at runtime to call Bedrock; the execution role is what the ECS
# agent itself uses to pull the image and inject secrets.
# ---------------------------------------------------------------------
resource "aws_iam_role" "task" {
  name = "${var.name_prefix}-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_invoke" {
  name = "${var.name_prefix}-bedrock-invoke"
  role = aws_iam_role.task.id

  # Both ARN families are required: the built-in model catalog resolves
  # every Claude model to a cross-region inference profile, which itself
  # invokes the underlying foundation model.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
      Resource = [
        "arn:${data.aws_partition.current.partition}:bedrock:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:inference-profile/us.anthropic.*",
        # GovCloud's cross-region inference profiles use a us-gov. prefix
        # instead; this never matches in other partitions.
        "arn:${data.aws_partition.current.partition}:bedrock:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:inference-profile/us-gov.anthropic.*",
        "arn:${data.aws_partition.current.partition}:bedrock:*::foundation-model/anthropic.*",
      ]
    }]
  })
}

resource "aws_iam_role" "execution" {
  name = "${var.name_prefix}-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "read_gateway_secrets" {
  # Named by exact ARN, not a "gateway-*" wildcard - in a shared account
  # a prefix glob would also match unrelated secrets.
  name = "${var.name_prefix}-read-secrets"
  role = aws_iam_role.execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = [
          aws_secretsmanager_secret.jwt.arn,
          aws_secretsmanager_secret.oidc_client_secret.arn,
          aws_secretsmanager_secret.postgres_url.arn,
        ]
      },
      {
        # Needed both to decrypt the secrets above and to pull the
        # KMS-encrypted ECR image at task start.
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource = aws_kms_key.gateway.arn
      },
    ]
  })
}

resource "aws_iam_role" "rds_enhanced_monitoring" {
  name = "${var.name_prefix}-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  role       = aws_iam_role.rds_enhanced_monitoring.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# ---------------------------------------------------------------------
# Secrets Manager - three secrets the gateway resolves at boot via
# ${VAR} expansion in gateway.yaml.
# ---------------------------------------------------------------------
resource "random_password" "db_master" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "db_master_password" {
  # checkov:skip=CKV2_AWS_57: Automatic rotation isn't wired up in this
  # reference deployment - rotating this secret would need the
  # AWS-provided RDS single-user rotation Lambda deployed alongside a
  # VPC-reachable network path to the database. See this module's
  # README for how to add it.
  name        = "${var.name_prefix}-db-master-password"
  description = "Auto-generated master password for the gateway's RDS instance."
  kms_key_id  = aws_kms_key.gateway.id
}

resource "aws_secretsmanager_secret_version" "db_master_password" {
  secret_id     = aws_secretsmanager_secret.db_master_password.id
  secret_string = random_password.db_master.result
}

resource "random_password" "jwt_secret" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "jwt" {
  # checkov:skip=CKV2_AWS_57: This secret has no third-party rotation
  # story - it's an opaque HMAC key, not a credential a managed rotation
  # Lambda understands. Rotate manually by generating a new value and
  # forcing a new ECS deployment; see this module's README.
  name        = "${var.name_prefix}-jwt-secret"
  description = "Signing key for gateway session JWTs (session.jwt_secret in gateway.yaml)."
  kms_key_id  = aws_kms_key.gateway.id
}

resource "aws_secretsmanager_secret_version" "jwt" {
  secret_id     = aws_secretsmanager_secret.jwt.id
  secret_string = random_password.jwt_secret.result
}

resource "aws_secretsmanager_secret" "oidc_client_secret" {
  # checkov:skip=CKV2_AWS_57: This value is issued by your IdP, not AWS -
  # automatic rotation would require coordinating a secret change with
  # the identity provider's own admin console/API, which is outside what
  # a Secrets Manager rotation Lambda can do unattended.
  name        = "${var.name_prefix}-oidc-client-secret"
  description = "OAuth client secret from the IdP's gateway app registration (oidc.client_secret in gateway.yaml)."
  kms_key_id  = aws_kms_key.gateway.id
}

resource "aws_secretsmanager_secret_version" "oidc_client_secret" {
  secret_id     = aws_secretsmanager_secret.oidc_client_secret.id
  secret_string = var.oidc_client_secret_value
}

resource "aws_secretsmanager_secret" "postgres_url" {
  # checkov:skip=CKV2_AWS_57: A derived composite string (embeds
  # db_master_password), not a standalone rotatable credential - it
  # should be regenerated whenever the master password rotates, which
  # this reference deployment doesn't automate. See this module's README.
  name        = "${var.name_prefix}-postgres-url"
  description = "Full connection string for the gateway's store (store.postgres_url in gateway.yaml)."
  kms_key_id  = aws_kms_key.gateway.id
}

resource "aws_secretsmanager_secret_version" "postgres_url" {
  secret_id     = aws_secretsmanager_secret.postgres_url.id
  secret_string = "postgres://gateway:${random_password.db_master.result}@${aws_db_instance.gateway.address}:5432/claude_gateway?sslmode=verify-full"
}

# ---------------------------------------------------------------------
# RDS for PostgreSQL - private, encrypted, TLS-only.
# ---------------------------------------------------------------------
resource "aws_db_subnet_group" "gateway" {
  name       = "${var.name_prefix}-db"
  subnet_ids = var.private_subnet_ids
}

resource "aws_db_parameter_group" "gateway" {
  name        = "${var.name_prefix}-db"
  family      = "postgres16"
  description = "${var.name_prefix} - require TLS on every connection"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_db_instance" "gateway" {
  # checkov:skip=CKV_AWS_157: Multi-AZ is exposed as a toggle
  # (var.enable_multi_az, default false) rather than forced on -
  # roughly doubles RDS cost, which doesn't match this reference
  # deployment's db.t4g.micro sizing. Set the variable true for
  # production.
  identifier        = "${var.name_prefix}-db"
  engine            = "postgres"
  engine_version    = "16.13"
  instance_class    = var.db_instance_class
  allocated_storage = var.db_allocated_storage_gb
  db_name           = "claude_gateway"
  username          = "gateway"
  password          = random_password.db_master.result

  db_subnet_group_name   = aws_db_subnet_group.gateway.name
  parameter_group_name   = aws_db_parameter_group.gateway.name
  vpc_security_group_ids = [aws_security_group.db.id]

  storage_encrypted       = true
  publicly_accessible     = false
  backup_retention_period = 7
  copy_tags_to_snapshot   = true
  deletion_protection     = var.enable_deletion_protection
  # Always snapshot on destroy. Deletion protection has to be turned off
  # before a destroy is possible, so tying the snapshot to it meant the
  # snapshot was skipped in exactly the case it was meant to protect.
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name_prefix}-db-final"

  auto_minor_version_upgrade          = true
  multi_az                            = var.enable_multi_az
  iam_database_authentication_enabled = true
  # The gateway itself connects with the password in store.postgres_url,
  # not IAM tokens - this only makes IAM auth available as an
  # additional option, it doesn't change current behavior.
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.gateway.arn
  performance_insights_retention_period = 7
  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]
  monitoring_interval                   = 60
  monitoring_role_arn                   = aws_iam_role.rds_enhanced_monitoring.arn
}

# ---------------------------------------------------------------------
# ECR - immutable tags so a deployed tag can't be silently re-pointed.
# This is the resource to `-target` on the first apply.
# ---------------------------------------------------------------------
resource "aws_ecr_repository" "gateway" {
  name                 = var.name_prefix
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.gateway.arn
  }
}

# ---------------------------------------------------------------------
# S3 bucket for ALB access logs
# ---------------------------------------------------------------------
#trivy:ignore:AWS-0089 This is the access-log destination; logging it would be recursive.
resource "aws_s3_bucket" "alb_logs" {
  # checkov:skip=CKV_AWS_18: This IS an access-log destination bucket -
  # giving it its own access logs would be recursive.
  # checkov:skip=CKV_AWS_144: Cross-region replication omitted for this
  # starter template - add if your compliance regime requires geographic
  # redundancy.
  # checkov:skip=CKV_AWS_145: ALB access log delivery only supports
  # SSE-S3 for the destination bucket, not SSE-KMS - a documented AWS
  # limitation, not an oversight.
  # checkov:skip=CKV2_AWS_62: Pure write-once access-log target - nothing
  # downstream consumes events from it, so notifications add no value here.
  # checkov:skip=CKV_AWS_19: Encryption IS configured, via the separate
  # aws_s3_bucket_server_side_encryption_configuration resource below (the
  # syntax the AWS provider v4+ requires). This is a known, long-standing
  # Checkov limitation with detecting the split-resource S3 pattern
  # (bridgecrewio/checkov issues #3277, #3847, #4624, among others).
  # checkov:skip=CKV_AWS_21: Same root cause as CKV_AWS_19 above -
  # versioning IS enabled, via the separate aws_s3_bucket_versioning
  # resource below; Checkov's split-resource detection doesn't reliably
  # associate it with this bucket.
  bucket = "${var.name_prefix}-alb-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

#trivy:ignore:AWS-0132 ALB access logs support only SSE-S3 (AWS docs: enable-access-logging).
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "ExpireAccessLogs"
    status = "Enabled"

    expiration {
      days = 365
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowElbAccountAccessLogDelivery"
        Effect    = "Allow"
        Principal = { AWS = data.aws_elb_service_account.main.arn }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.alb_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
      },
      {
        Sid       = "AllowElbLogDeliveryServicePrincipal"
        Effect    = "Allow"
        Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.alb_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      },
    ]
  })
}

# ---------------------------------------------------------------------
# ECS Fargate
# ---------------------------------------------------------------------
resource "aws_ecs_cluster" "gateway" {
  name = var.name_prefix

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "gateway" {
  # The gateway's stderr carries both its audit events and its
  # operational logs - align this retention with your audit policy.
  name              = "/ecs/${var.name_prefix}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.gateway.arn
}

resource "aws_ecs_task_definition" "gateway" {
  family                   = var.name_prefix
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    cpu_architecture        = "X86_64"
    operating_system_family = "LINUX"
  }

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([{
    name                   = "gateway"
    image                  = "${aws_ecr_repository.gateway.repository_url}:${var.container_image_tag}"
    readonlyRootFilesystem = true
    portMappings = [{
      containerPort = 8080
    }]
    mountPoints = [{
      sourceVolume  = "tmp"
      containerPath = "/tmp"
      readOnly      = false
    }]
    secrets = [
      { name = "GATEWAY_JWT_SECRET", valueFrom = aws_secretsmanager_secret.jwt.arn },
      { name = "OIDC_CLIENT_SECRET", valueFrom = aws_secretsmanager_secret.oidc_client_secret.arn },
      { name = "GATEWAY_POSTGRES_URL", valueFrom = aws_secretsmanager_secret.postgres_url.arn },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.gateway.name
        "awslogs-region"        = data.aws_region.current.region
        "awslogs-stream-prefix" = "gateway"
      }
    }
  }])
}

resource "aws_lb" "gateway" {
  name               = var.name_prefix
  internal           = true
  load_balancer_type = "application"
  ip_address_type    = "ipv4"
  # ipv4-only matters: a dual-stack internal ALB publishes public-range
  # AAAA records, which Claude Code's private-network check at /login
  # rejects even though the A record is private.
  subnets         = var.private_subnet_ids
  security_groups = [aws_security_group.alb.id]

  idle_timeout = 3600
  # A stream that goes quiet during long prompt processing or extended
  # thinking with no streamed output is cut mid-response at the ALB's
  # 60-second default.

  enable_deletion_protection = var.enable_deletion_protection
  drop_invalid_header_fields = true

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    enabled = true
  }

  depends_on = [aws_s3_bucket_policy.alb_logs]
}

resource "aws_lb_target_group" "gateway" {
  name        = var.name_prefix
  vpc_id      = var.vpc_id
  protocol    = "HTTP"
  port        = 8080
  target_type = "ip"

  health_check {
    path = "/readyz"
    # /readyz verifies the store is reachable, so a task that can't
    # reach Postgres never enters rotation.
  }
}

resource "aws_lb_listener" "https" {
  # checkov:skip=CKV_AWS_103: ELBSecurityPolicy-TLS13-1-2-2021-06 is AWS's
  # own current default and recommended policy, with a TLS 1.2 floor and
  # TLS 1.3 support - it satisfies "at least TLS 1.2" and then some. This
  # is a known, long-standing Checkov limitation (bridgecrewio/checkov
  # issues #3570, #4962) where the check doesn't recognize TLS
  # 1.3-labeled policies as meeting a TLS 1.2 minimum. Downgrading to a
  # TLS-1.2-only policy just to satisfy the linter would be a real
  # security regression to fix a false positive.
  load_balancer_arn = aws_lb.gateway.arn
  protocol          = "HTTPS"
  port              = 443
  # Pinned explicitly - the default ELBSecurityPolicy-2016-08 still
  # accepts TLS 1.0/1.1.
  ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway.arn
  }
}

resource "aws_ecs_service" "gateway" {
  name            = var.name_prefix
  cluster         = aws_ecs_cluster.gateway.id
  task_definition = aws_ecs_task_definition.gateway.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
    # Rolls a deployment whose tasks keep failing (bad image, an
    # unbootable config) back to the last steady state instead of
    # relaunching failing tasks forever.
  }

  health_check_grace_period_seconds = 60

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.gateway.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.gateway.arn
    container_name   = "gateway"
    container_port   = 8080
  }

  depends_on = [aws_lb_listener.https]
}
