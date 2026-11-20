output "lambda_function_name" {
  description = "Name of the response Lambda (use it to read logs)."
  value       = aws_lambda_function.responder.function_name
}

output "sns_topic_arn" {
  description = "Topic that emails you about each finding."
  value       = aws_sns_topic.alerts.arn
}

output "dead_letter_queue_url" {
  description = "Queue holding events that could not be processed."
  value       = aws_sqs_queue.dlq.url
}

output "event_rule_name" {
  description = "EventBridge rule that matches GuardDuty findings."
  value       = aws_cloudwatch_event_rule.findings.name
}

output "guardduty_detector_id" {
  description = "Detector created by this project (empty if you used an existing one)."
  value       = try(aws_guardduty_detector.this[0].id, "")
}
