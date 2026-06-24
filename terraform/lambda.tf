data "archive_file" "remediator" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/build/remediator.zip"
}

resource "aws_cloudwatch_log_group" "remediator" {
  name              = "/aws/lambda/${var.project_name}-remediator"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.remediation.arn
}

resource "aws_sqs_queue" "remediator_dlq" {
  name                              = "${var.project_name}-remediator-dlq"
  kms_master_key_id                 = aws_kms_key.remediation.id
  kms_data_key_reuse_period_seconds = 300
}

# reserved_concurrent_executions caps concurrency for this Lambda alone so a
# burst of misconfiguration events can't starve other functions in the
# account-wide unreserved pool.
resource "aws_lambda_function" "remediator" {
  #checkov:skip=CKV_AWS_272:Code signing requires an AWS Signer profile/pipeline out of scope for this lab-scale demo.
  #checkov:skip=CKV_AWS_117:This function only calls public AWS endpoints; a VPC would add NAT/endpoint cost with no security benefit.
  function_name                  = "${var.project_name}-remediator"
  role                           = aws_iam_role.remediator.arn
  handler                        = "handler.handler"
  runtime                        = "python3.12"
  timeout                        = 30
  memory_size                    = 256
  filename                       = data.archive_file.remediator.output_path
  source_code_hash               = data.archive_file.remediator.output_base64sha256
  reserved_concurrent_executions = 5
  kms_key_arn                    = aws_kms_key.remediation.arn

  environment {
    variables = {
      DRY_RUN       = tostring(var.dry_run)
      LOG_LEVEL     = var.log_level
      SNS_TOPIC_ARN = aws_sns_topic.remediation_alerts.arn
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.remediator_dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.remediator]
}
