#!/usr/bin/env python3
"""Local demo harness: exercise all three remediation modules against LocalStack
and write findings.jsonl so the observability stack's Promtail glob picks it up.

Calls the same remediate() functions the Lambda calls, invoked directly
against a LocalStack endpoint instead of through a real EventBridge-triggered
Lambda invocation -- LocalStack's community edition doesn't wire CloudTrail
management events into EventBridge the way real AWS does, so this reproduces
the same call path (synthetic CloudTrail-shaped `detail`, real API calls
against a real-enough backend) without inventing a second delivery mechanism.

Prerequisites:
    cd ../observability-stack && docker compose up -d localstack
    pip install -r ../requirements-dev.txt

Usage:
    python demo/localstack_demo.py
"""

from __future__ import annotations

import os
import sys
import uuid

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from remediations import ebs_unencrypted, s3_public, security_group  # noqa: E402
from utils.shared_finding import to_shared_finding, write_shared_findings_jsonl  # noqa: E402

ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
REGION = "us-east-1"
FINDINGS_PATH = os.path.join(os.path.dirname(__file__), "..", "findings.jsonl")


def _client(service):
    return boto3.client(
        service,
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def demo_s3_public_bucket(s3):
    bucket = f"demo-public-bucket-{uuid.uuid4().hex[:8]}"
    s3.create_bucket(Bucket=bucket)
    s3.put_bucket_acl(Bucket=bucket, ACL="public-read")

    detail = {
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutBucketAcl",
        "requestParameters": {"bucketName": bucket},
    }
    result = s3_public.remediate(detail, dry_run=False, s3_client=s3)
    print(f"[s3_public_bucket] {result}")
    return result


def demo_sg_open_ingress(ec2):
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    group = ec2.create_security_group(
        GroupName=f"demo-open-sg-{uuid.uuid4().hex[:8]}",
        Description="LocalStack demo: open ingress on port 22",
        VpcId=vpc_id,
    )
    group_id = group["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
    )

    detail = {
        "eventSource": "ec2.amazonaws.com",
        "eventName": "AuthorizeSecurityGroupIngress",
        "requestParameters": {
            "groupId": group_id,
            "ipPermissions": {
                "items": [
                    {
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "toPort": 22,
                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                    }
                ]
            },
        },
    }
    result = security_group.remediate(detail, dry_run=False, ec2_client=ec2)
    print(f"[sg_open_ingress] {result}")
    return result


def demo_ebs_unencrypted(ec2):
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    volume = ec2.create_volume(AvailabilityZone=az, Size=1, Encrypted=False)

    detail = {
        "eventSource": "ec2.amazonaws.com",
        "eventName": "CreateVolume",
        "responseElements": {"volumeId": volume["VolumeId"], "encrypted": False},
    }
    result = ebs_unencrypted.remediate(detail, dry_run=False, ec2_client=ec2)
    print(f"[ebs_unencrypted] {result}")
    return result


def main() -> None:
    s3 = _client("s3")
    ec2 = _client("ec2")

    results = [
        demo_s3_public_bucket(s3),
        demo_sg_open_ingress(ec2),
        demo_ebs_unencrypted(ec2),
    ]

    findings = [f for f in (to_shared_finding(r) for r in results) if f is not None]
    write_shared_findings_jsonl(findings, FINDINGS_PATH)
    print(f"\nWrote {len(findings)} finding(s) to {FINDINGS_PATH}")


if __name__ == "__main__":
    main()
