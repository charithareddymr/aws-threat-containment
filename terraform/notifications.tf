# --- Email alerts --------------------------------------------------------- #
resource "aws_sns_topic" "alerts" {
  name              = "${var.project_name}-alerts"
  kms_master_key_id = aws_kms_key.this.arn
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- Dead-letter queue ---------------------------------------------------- #
# Receives events that EventBridge could not deliver, and events the Lambda
# still failed on after its retries, so no finding is silently lost.
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.project_name}-dlq"
  kms_master_key_id         = aws_kms_key.this.arn
  message_retention_seconds = 1209600 # 14 days, the maximum
}

data "aws_iam_policy_document" "dlq" {
  statement {
    sid       = "AllowEventBridgeRule"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.findings.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy    = data.aws_iam_policy_document.dlq.json
}
