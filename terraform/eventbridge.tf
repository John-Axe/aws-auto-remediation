# CloudTrail management events are delivered to the default EventBridge bus
# automatically as "AWS API Call via CloudTrail" -- no trail needs to be
# created for these rules to match.

resource "aws_cloudwatch_event_rule" "s3_public_access" {
  name        = "${var.project_name}-s3-public-access"
  description = "Detects S3 bucket ACL/policy/public-access-block changes that may expose a bucket publicly."

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["PutBucketAcl", "PutBucketPolicy", "PutPublicAccessBlock"]
    }
  })
}

resource "aws_cloudwatch_event_rule" "security_group_open_ingress" {
  name        = "${var.project_name}-sg-open-ingress"
  description = "Detects security group ingress rules opened to 0.0.0.0/0 or ::/0."

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress"]
    }
  })
}

resource "aws_cloudwatch_event_rule" "ebs_volume_created" {
  name        = "${var.project_name}-ebs-volume-created"
  description = "Detects newly created EBS volumes so unencrypted ones can be flagged."

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["CreateVolume"]
    }
  })
}

locals {
  event_rules = {
    s3_public_access            = aws_cloudwatch_event_rule.s3_public_access
    security_group_open_ingress = aws_cloudwatch_event_rule.security_group_open_ingress
    ebs_volume_created          = aws_cloudwatch_event_rule.ebs_volume_created
  }
}

resource "aws_cloudwatch_event_target" "remediator" {
  for_each = local.event_rules

  rule = each.value.name
  arn  = aws_lambda_function.remediator.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  for_each = local.event_rules

  statement_id  = "AllowEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = each.value.arn
}
