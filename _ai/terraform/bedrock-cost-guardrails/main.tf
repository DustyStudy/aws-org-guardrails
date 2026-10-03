data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

# Budgets and Cost Anomaly Detection publish as service principals, which
# can't use the AWS-managed aws/sns key (its key policy can't be edited to
# allow them) - without a customer-managed key, alerts would silently never
# arrive.
resource "aws_kms_key" "topic" {
  description         = "Encrypts the ${var.name_prefix} Bedrock cost-alerts SNS topic (customer-managed so Budgets and Cost Anomaly Detection can publish to it)."
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
        Sid       = "AllowBudgetsAndCostAnomalyDetectionToUseKey"
        Effect    = "Allow"
        Principal = { Service = ["budgets.amazonaws.com", "costalerts.amazonaws.com"] }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
      },
    ]
  })
}

resource "aws_sns_topic" "cost_alerts" {
  name              = "${var.name_prefix}-bedrock-cost-alerts"
  kms_master_key_id = aws_kms_key.topic.arn
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.cost_alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_sns_topic_policy" "cost_alerts" {
  arn = aws_sns_topic.cost_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCostAnomalyDetectionPublish"
        Effect    = "Allow"
        Principal = { Service = "costalerts.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = aws_sns_topic.cost_alerts.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
      {
        Sid       = "AllowBudgetsPublish"
        Effect    = "Allow"
        Principal = { Service = "budgets.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = aws_sns_topic.cost_alerts.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
          ArnLike      = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:budgets::${data.aws_caller_identity.current.account_id}:*" }
        }
      },
    ]
  })
}

resource "aws_ce_anomaly_monitor" "bedrock_spend" {
  name         = "${var.name_prefix}-bedrock-spend"
  monitor_type = "CUSTOM"

  monitor_specification = jsonencode({
    Dimensions = {
      Key          = "SERVICE"
      Values       = ["Amazon Bedrock"]
      MatchOptions = ["EQUALS"]
    }
  })
}

resource "aws_ce_anomaly_subscription" "bedrock_spend_alerts" {
  name = "${var.name_prefix}-bedrock-spend-alerts"

  # SNS delivery requires IMMEDIATE frequency - DAILY/WEEKLY only support
  # email subscribers.
  frequency = "IMMEDIATE"

  monitor_arn_list = [aws_ce_anomaly_monitor.bedrock_spend.arn]

  subscriber {
    type    = "SNS"
    address = aws_sns_topic.cost_alerts.arn
  }

  threshold_expression {
    dimension {
      key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      values        = [tostring(var.anomaly_threshold_usd)]
      match_options = ["GREATER_THAN_OR_EQUAL"]
    }
  }
}

resource "aws_budgets_budget" "bedrock_monthly" {
  name         = "${var.name_prefix}-bedrock-monthly-budget"
  budget_type  = "COST"
  time_unit    = "MONTHLY"
  limit_amount = tostring(var.monthly_budget_limit_usd)
  limit_unit   = "USD"

  cost_filter {
    name   = "Service"
    values = ["Amazon Bedrock"]
  }

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.cost_alerts.arn]
  }

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "FORECASTED"
    subscriber_sns_topic_arns = [aws_sns_topic.cost_alerts.arn]
  }
}
