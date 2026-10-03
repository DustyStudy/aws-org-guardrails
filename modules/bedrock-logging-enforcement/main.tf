data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/enforce_bedrock_logging.py"
  output_path = "${path.module}/build/lambda.zip"
}

resource "aws_sns_topic" "enforcement" {
  name              = "${var.name_prefix}-bedrock-logging-drift"
  kms_master_key_id = aws_kms_key.log_encryption.arn
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.enforcement.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_kms_key" "log_encryption" {
  description         = "Encrypts the ${var.name_prefix} Bedrock logging enforcement Lambda's log group, DLQ, SNS topic, environment variables, and both Bedrock log destinations."
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
            "kms:EncryptionContext:aws:logs:arn" = [
              "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-enforce-bedrock-logging",
              "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:${var.name_prefix}-bedrock-invocation-logs",
            ]
          }
        }
      },
      {
        # Bedrock writes invocation logs to the SSE-KMS bucket below.
        # https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
        Sid       = "AllowBedrockLogDeliveryToS3"
        Effect    = "Allow"
        Principal = { Service = "bedrock.amazonaws.com" }
        Action    = "kms:GenerateDataKey"
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
          ArnLike      = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:bedrock:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:*" }
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
  name                      = "${var.name_prefix}-enforcement-dlq"
  kms_master_key_id         = aws_kms_key.log_encryption.arn
  message_retention_seconds = 1209600
}

resource "aws_s3_bucket" "bedrock_logs" {
  # checkov:skip=CKV_AWS_18: Server access logging omitted for this
  # starter template - add an access-log bucket like the one in
  # fedramp-terraform-library's org-cloudtrail module if required.
  # checkov:skip=CKV_AWS_144: Cross-region replication omitted for this
  # starter template - add if your compliance regime requires geographic
  # redundancy.
  # checkov:skip=CKV_AWS_19: Encryption IS configured, via the separate
  # aws_s3_bucket_server_side_encryption_configuration resource below (the
  # syntax the AWS provider v4+ requires). This is a known, long-standing
  # Checkov limitation with detecting the split-resource S3 pattern
  # (bridgecrewio/checkov issues #3277, #3847, #4624, among others).
  # checkov:skip=CKV_AWS_21: Same root cause as CKV_AWS_19 above -
  # versioning IS enabled, via the separate aws_s3_bucket_versioning
  # resource below; Checkov's split-resource detection doesn't reliably
  # associate it with this bucket.
  bucket = "${var.name_prefix}-bedrock-invocation-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_notification" "bedrock_logs" {
  bucket      = aws_s3_bucket.bedrock_logs.id
  eventbridge = true
}

resource "aws_s3_bucket_public_access_block" "bedrock_logs" {
  bucket                  = aws_s3_bucket.bedrock_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "bedrock_logs" {
  bucket = aws_s3_bucket.bedrock_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bedrock_logs" {
  bucket = aws_s3_bucket.bedrock_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.log_encryption.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "bedrock_logs" {
  bucket = aws_s3_bucket.bedrock_logs.id

  rule {
    id     = "ExpireOldLogs"
    status = "Enabled"

    expiration {
      days = 365
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "bedrock_logs" {
  bucket = aws_s3_bucket.bedrock_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowBedrockLogDelivery"
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.bedrock_logs.arn}/*"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:bedrock:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:*" }
      }
    }]
  })
}

resource "aws_cloudwatch_log_group" "bedrock_logs" {
  name              = "${var.name_prefix}-bedrock-invocation-logs"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.log_encryption.arn
}

resource "aws_iam_role" "bedrock_to_cloudwatch" {
  name = "${var.name_prefix}-bedrock-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:bedrock:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:*" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_to_cloudwatch" {
  name = "${var.name_prefix}-bedrock-cloudwatch-policy"
  role = aws_iam_role.bedrock_to_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.bedrock_logs.arn}:*"
    }]
  })
}

resource "aws_iam_role" "lambda_exec" {
  name = "${var.name_prefix}-bedrock-logging-role"

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
  name = "${var.name_prefix}-bedrock-logging-policy"
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
        # Bedrock's account-level logging configuration APIs are not
        # resource-scopable - "*" is required.
        Effect = "Allow"
        Action = [
          "bedrock:GetModelInvocationLoggingConfiguration",
          "bedrock:PutModelInvocationLoggingConfiguration",
        ]
        Resource = "*"
      },
      {
        # The logging configuration hands Bedrock this role for CloudWatch
        # delivery. Scoped to exactly that role and only to Bedrock.
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = aws_iam_role.bedrock_to_cloudwatch.arn
        Condition = {
          StringEquals = { "iam:PassedToService" = "bedrock.amazonaws.com" }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.enforcement.arn
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

resource "aws_lambda_function" "enforcement" {
  # checkov:skip=CKV_AWS_117: Control-plane only Lambda (Bedrock/SNS/SQS
  # APIs over public AWS endpoints) - no customer VPC resources touched.
  function_name                  = "${var.name_prefix}-enforce-bedrock-logging"
  description                    = "Checks and enforces Bedrock model invocation logging configuration."
  role                           = aws_iam_role.lambda_exec.arn
  handler                        = "enforce_bedrock_logging.lambda_handler"
  runtime                        = "python3.12"
  timeout                        = 30
  memory_size                    = 128
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
      SNS_TOPIC_ARN        = aws_sns_topic.enforcement.arn
      S3_BUCKET_NAME       = aws_s3_bucket.bedrock_logs.id
      CLOUDWATCH_LOG_GROUP = aws_cloudwatch_log_group.bedrock_logs.name
      CLOUDWATCH_ROLE_ARN  = aws_iam_role.bedrock_to_cloudwatch.arn
      LOG_TEXT             = tostring(var.log_text_data)
      LOG_IMAGE            = tostring(var.log_image_data)
      LOG_EMBEDDING        = tostring(var.log_embedding_data)
    }
  }
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${aws_lambda_function.enforcement.function_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.log_encryption.arn
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.name_prefix}-schedule"
  description         = "Triggers the Bedrock logging enforcement check on a schedule."
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "enforcement" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.enforcement.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.enforcement.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
