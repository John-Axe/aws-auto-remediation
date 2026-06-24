import json
import logging
import os

from remediations import ebs_unencrypted, s3_public, security_group

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Mapped as (module, function name) rather than bound functions so that
# patching <module>.remediate (e.g. in tests) is respected at call time.
DISPATCH = {
    ("s3.amazonaws.com", "PutBucketAcl"): s3_public,
    ("s3.amazonaws.com", "PutBucketPolicy"): s3_public,
    ("s3.amazonaws.com", "PutPublicAccessBlock"): s3_public,
    ("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress"): security_group,
    ("ec2.amazonaws.com", "CreateVolume"): ebs_unencrypted,
}


def _log(level, message, **fields):
    logger.log(level, json.dumps({"message": message, **fields}, default=str))


def handler(event, context):
    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"
    detail = event.get("detail", {})
    event_source = detail.get("eventSource")
    event_name = detail.get("eventName")

    _log(logging.INFO, "received_event", event_source=event_source, event_name=event_name, dry_run=dry_run)

    module = DISPATCH.get((event_source, event_name))
    if not module:
        _log(logging.WARNING, "unhandled_event", event_source=event_source, event_name=event_name)
        return {"status": "ignored", "event_source": event_source, "event_name": event_name}

    result = module.remediate(detail, dry_run=dry_run)
    _log(logging.INFO, "remediation_complete", **result)
    return result
