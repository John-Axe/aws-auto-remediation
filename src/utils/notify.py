import json
import os

import boto3


def publish(subject, message, sns_client=None):
    topic_arn = os.environ.get("SNS_TOPIC_ARN")
    if not topic_arn:
        return None

    sns_client = sns_client or boto3.client("sns")
    body = message if isinstance(message, str) else json.dumps(message, default=str)
    return sns_client.publish(TopicArn=topic_arn, Subject=subject[:100], Message=body)
