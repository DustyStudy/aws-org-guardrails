data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/audit_ai_agent_iam_roles.py"
  output_path = "${path.module}/build/lambda.zip"
}

resource "aws_sns_topic" "audit" {
  name              = "${var.name_prefix}-ai-agent-iam-audit"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.audit.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_kms_key" "log_encryption" {
  description         = "Encrypts the ${var.name_prefix} AI agent IAM auditor Lambda's log group, DLQ, and environment variables."
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
            "kms:EncryptionContext:aws:logs:arn" = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-audit-ai-agent-iam"
          }
        }
      },
      {
        Sid       = "AllowSQSUseOfKey"
        Effect    = "Allow"
        Principal = { Service = "sqs.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource  = "*"
        Condition = {
          StringEquals = { "kms:CallerAccount" = data.aws_caller_identity.current.account_id }
        }
      },
    ]
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-audit-dlq"
  kms_master_key_id         = aws_kms_key.log_encryption.arn
  message_retention_seconds = 1209600
}

resource "aws_iam_role" "lambda_exec" {
  name = "${var.name_prefix}-ai-agent-auditor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_exec" {
  name = "${var.name_prefix}-ai-agent-auditor-policy"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        # checkov:skip=CKV_AWS_355: ListRoles has no resource-level
        # support in IAM - must be "*".
        Effect   = "Allow"
        Action   = ["iam:ListRoles"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:ListAttachedRolePolicies",
          "iam:ListRolePolicies",
          "iam:GetRolePolicy",
          "iam:GetRole",
        ]
        Resource = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/*"
      },
      {
        # Covers AWS managed policies, which is what's typically attached
        # to roles this auditor inspects. If your org also attaches
        # customer-managed policies to AI/agent roles, add
        # arn:...:iam::<account_id>:policy/* to this Resource list.
        Effect   = "Allow"
        Action   = ["iam:GetPolicy", "iam:GetPolicyVersion"]
        Resource = "arn:${data.aws_partition.current.partition}:iam::aws:policy/*"
      },
      {
        # checkov:skip=CKV_AWS_355: Discovers Bedrock Agent action groups
        # so their Lambda execution roles can be audited too - these APIs
        # don't support resource-level scoping to a specific agent.
        Effect = "Allow"
        Action = [
          "bedrock:ListAgents",
          "bedrock:ListAgentActionGroups",
          "bedrock:GetAgentActionGroup",
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["lambda:GetFunction"]
        Resource = "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:function:*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.audit.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.dlq.arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource = aws_kms_key.log_encryption.arn
      },
      {
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
        Resource = "*"
      },
    ]
  })
}

resource "aws_lambda_function" "audit" {
  # checkov:skip=CKV_AWS_117: Control-plane only Lambda (IAM/SNS/SQS APIs
  # over public AWS endpoints) - no customer VPC resources touched.
  function_name                  = "${var.name_prefix}-audit-ai-agent-iam"
  description                    = "Detects over-permissioned IAM roles trusted by AI/agent services."
  role                           = aws_iam_role.lambda_exec.arn
  handler                        = "audit_ai_agent_iam_roles.lambda_handler"
  runtime                        = "python3.12"
  timeout                        = 120
  memory_size                    = 256
  reserved_concurrent_executions = 2
  filename                       = data.archive_file.lambda_zip.output_path
  source_code_hash               = data.archive_file.lambda_zip.output_base64sha256
  kms_key_arn                    = aws_kms_key.log_encryption.arn
  code_signing_config_arn        = var.code_signing_config_arn

  tracing_config {
    mode = "Active"
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  environment {
    variables = {
      SNS_TOPIC_ARN                     = aws_sns_topic.audit.arn
      AI_SERVICE_PRINCIPALS             = join(",", var.ai_service_principals)
      SENSITIVE_WILDCARD_SERVICES       = join(",", var.sensitive_wildcard_services)
      CHECK_BEDROCK_AGENT_ACTION_GROUPS = tostring(var.check_bedrock_agent_action_groups)
    }
  }
}

resource "aws_cloudwatch_log_group" "audit" {
  name              = "/aws/lambda/${aws_lambda_function.audit.function_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.log_encryption.arn
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.name_prefix}-schedule"
  description         = "Triggers the AI agent IAM audit on a schedule."
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "audit" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.audit.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.audit.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
