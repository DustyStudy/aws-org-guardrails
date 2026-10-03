data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/remediate_sagemaker_notebook_exposure.py"
  output_path = "${path.module}/build/lambda.zip"
}

resource "aws_sns_topic" "remediation" {
  name              = "${var.name_prefix}-notebook-remediation-notifications"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.remediation.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_kms_key" "log_encryption" {
  description         = "Encrypts the ${var.name_prefix} SageMaker remediation Lambda's log group, DLQ, and environment variables."
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
            "kms:EncryptionContext:aws:logs:arn" = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-remediate-sagemaker-exposure"
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
  name                      = "${var.name_prefix}-remediation-dlq"
  kms_master_key_id         = aws_kms_key.log_encryption.arn
  message_retention_seconds = 1209600
}

resource "aws_iam_role" "lambda_exec" {
  name = "${var.name_prefix}-sagemaker-remediation-role"

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
  name = "${var.name_prefix}-sagemaker-remediation-policy"
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
        Effect = "Allow"
        Action = [
          "sagemaker:DescribeNotebookInstance",
          "sagemaker:StopNotebookInstance",
          "sagemaker:StartNotebookInstance",
          "sagemaker:UpdateNotebookInstance",
          "sagemaker:AddTags",
          "sagemaker:ListTags",
          "sagemaker:DeleteTags",
        ]
        Resource = "arn:${data.aws_partition.current.partition}:sagemaker:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:notebook-instance/*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.remediation.arn
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

resource "aws_lambda_function" "remediate" {
  # checkov:skip=CKV_AWS_117: Control-plane only Lambda (SageMaker/SNS/SQS
  # APIs over public AWS endpoints) - no customer VPC resources touched.
  function_name                  = "${var.name_prefix}-remediate-sagemaker-exposure"
  description                    = "Detects and remediates SageMaker notebooks with direct internet or root access enabled."
  role                           = aws_iam_role.lambda_exec.arn
  handler                        = "remediate_sagemaker_notebook_exposure.lambda_handler"
  runtime                        = "python3.12"
  timeout                        = 60
  memory_size                    = 128
  reserved_concurrent_executions = 5
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
      SNS_TOPIC_ARN = aws_sns_topic.remediation.arn
      AUTO_RESTART  = tostring(var.auto_restart)
    }
  }
}

resource "aws_cloudwatch_log_group" "remediate" {
  name              = "/aws/lambda/${aws_lambda_function.remediate.function_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.log_encryption.arn
}

# Also listen for the notebook state-change event so a notebook this path
# stops (because it was found non-compliant by Config) still gets its
# settings fixed once it actually reaches Stopped - the SSM Automation
# invocation below only performs the "flag and stop" half.
resource "aws_cloudwatch_event_rule" "notebook_state_change" {
  name        = "${var.name_prefix}-notebook-state-change"
  description = "Matches SageMaker's native notebook instance state-change events."

  event_pattern = jsonencode({
    source      = ["aws.sagemaker"]
    detail-type = ["SageMaker Notebook Instance State Change"]
  })
}

resource "aws_cloudwatch_event_target" "notebook_state_change" {
  rule = aws_cloudwatch_event_rule.notebook_state_change.name
  arn  = aws_lambda_function.remediate.arn
}

resource "aws_lambda_permission" "allow_state_change_rule" {
  statement_id  = "AllowExecutionFromStateChangeRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.notebook_state_change.arn
}

resource "aws_iam_role" "automation" {
  name = "${var.name_prefix}-ssm-automation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ssm.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "automation" {
  name = "${var.name_prefix}-invoke-remediation-lambda"
  role = aws_iam_role.automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = aws_lambda_function.remediate.arn
    }]
  })
}

resource "aws_ssm_document" "remediation" {
  name            = "${var.name_prefix}-RemediateSageMakerNotebookExposure"
  document_type   = "Automation"
  document_format = "YAML"

  content = yamlencode({
    schemaVersion = "0.3"
    description   = "Invokes the remediation Lambda for a non-compliant SageMaker notebook instance."
    assumeRole    = "{{ AutomationAssumeRole }}"
    parameters = {
      NotebookInstanceId = {
        type        = "String"
        description = "The non-compliant notebook instance identifier (Config passes this as RESOURCE_ID)."
      }
      AutomationAssumeRole = {
        type        = "String"
        description = "IAM role ARN used by SSM Automation to execute this document."
      }
    }
    mainSteps = [{
      name   = "InvokeRemediationLambda"
      action = "aws:invokeLambdaFunction"
      inputs = {
        FunctionName = aws_lambda_function.remediate.function_name
        InputPayload = {
          notebook_instance_name = "{{ NotebookInstanceId }}"
        }
      }
    }]
  })
}

resource "aws_config_config_rule" "notebook_no_direct_internet_access" {
  name        = "${var.name_prefix}-sagemaker-no-direct-internet"
  description = "Flags SageMaker notebook instances with direct internet access enabled."

  source {
    owner             = "AWS"
    source_identifier = "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS"
  }

  maximum_execution_frequency = var.maximum_execution_frequency

  scope {
    compliance_resource_types = ["AWS::SageMaker::NotebookInstance"]
  }
}

resource "aws_config_remediation_configuration" "auto_remediate" {
  config_rule_name           = aws_config_config_rule.notebook_no_direct_internet_access.name
  resource_type              = "AWS::SageMaker::NotebookInstance"
  target_type                = "SSM_DOCUMENT"
  target_id                  = aws_ssm_document.remediation.name
  automatic                  = true
  maximum_automatic_attempts = 3
  retry_attempt_seconds      = 60

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.automation.arn
  }

  parameter {
    name           = "NotebookInstanceId"
    resource_value = "RESOURCE_ID"
  }
}
