import logging

import boto3

from utils.notify import publish

logger = logging.getLogger()

FINDING = "ebs_unencrypted"
NON_COMPLIANT_TAG = {"Key": "ComplianceStatus", "Value": "NON_COMPLIANT_UNENCRYPTED"}


def _extract_volume_id(detail):
    return (detail.get("responseElements") or {}).get("volumeId")


def remediate(detail, dry_run=False, ec2_client=None):
    """Tags a newly created unencrypted volume and alerts via SNS.

    EBS volumes cannot be encrypted in place after creation, so the only safe
    automated remediation is to flag the resource and notify a human.
    """
    ec2_client = ec2_client or boto3.client("ec2")
    response_elements = detail.get("responseElements") or {}
    volume_id = _extract_volume_id(detail)

    if not volume_id:
        return {"status": "error", "reason": "no_volume_id", "finding": FINDING}

    if response_elements.get("encrypted", False):
        return {"status": "compliant", "volume_id": volume_id, "finding": FINDING}

    if dry_run:
        return {
            "status": "dry_run",
            "volume_id": volume_id,
            "finding": FINDING,
            "would_tag_non_compliant": True,
            "would_notify": True,
        }

    ec2_client.create_tags(Resources=[volume_id], Tags=[NON_COMPLIANT_TAG])

    result = {"status": "tagged_and_alerted", "volume_id": volume_id, "finding": FINDING}
    publish(subject="Unencrypted EBS volume detected", message=result)
    return result
