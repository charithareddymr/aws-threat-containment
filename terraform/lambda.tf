data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/../lambda/src/handler.py"
  output_path = "${path.module}/build/lambda.zip"
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.project_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
}

resource "aws_lambda_function" "responder" {
  #checkov:skip=CKV_AWS_117:Needs only AWS APIs; running in a VPC would add NAT or endpoint cost for no benefit here.
  #checkov:skip=CKV_AWS_272:Code signing is out of scope for a single-developer demo.
  #checkov:skip=CKV_AWS_115:New AWS accounts often have a concurrency limit of 10, so reserving some can fail.

  function_name    = var.project_name
  description      = "Responds to high-severity GuardDuty findings"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 60
  memory_size      = 256
  kms_key_arn      = aws_kms_key.this.arn

  environment {
    variables = {
      SNS_TOPIC_ARN     = aws_sns_topic.alerts.arn
      DRY_RUN           = tostring(var.dry_run)
      SNAPSHOT_VOLUMES  = tostring(var.snapshot_volumes)
      ISOLATION_SG_NAME = "${var.project_name}-isolation"
    }
  }

  tracing_config {
    mode = "Active"
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.lambda,
  ]
}

# EventBridge invokes the Lambda asynchronously: retry twice, then dead-letter.
resource "aws_lambda_function_event_invoke_config" "responder" {
  function_name                = aws_lambda_function.responder.function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 3600
}
