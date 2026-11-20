locals {
  # AWS reserves sources starting with "aws.", so hand-made test events use a
  # custom source that the rule also accepts when enable_test_events = true.
  finding_sources = var.enable_test_events ? ["aws.guardduty", "custom.gd-auto-response.test"] : ["aws.guardduty"]
}

resource "aws_cloudwatch_event_rule" "findings" {
  name        = "${var.project_name}-findings"
  description = "GuardDuty findings with severity >= ${var.severity_threshold}"

  event_pattern = jsonencode({
    source        = local.finding_sources
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.severity_threshold] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.findings.name
  arn  = aws_lambda_function.responder.arn

  retry_policy {
    maximum_retry_attempts       = 4
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.findings.arn
}
