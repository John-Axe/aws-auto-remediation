"""Map a remediation module's result dict onto the ecosystem-wide shared finding schema.

Deliberately zero new runtime dependency for the Lambda itself: this repo's
Terraform packaging (`archive_file` on `src/`) zips the source directory
directly with no pip-install step, so pulling in `finding-schema`/pydantic
here would mean building real Lambda packaging infrastructure just for this.
The dict shape matches finding.schema.json; anyone who wants strict
validation can install `finding-schema` (../finding-schema) and pass this
dict to `finding_schema.Finding(**d)`.

Schema: ../finding-schema/schema/finding.schema.json
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

SOURCE = "aws-auto-remediation"
CATEGORY = "cloud-misconfig"

# Every remediation module returns a "finding" key holding one of these
# identifiers (see remediations/*.py's FINDING constant). None of them
# assign a severity today -- that judgment call lives here instead.
_SEVERITY = {
    "s3_public_bucket": "critical",
    "sg_open_ingress": "high",
    "ebs_unencrypted": "medium",
}

_TITLE = {
    "s3_public_bucket": "S3 bucket publicly accessible",
    "sg_open_ingress": "Security group open to the internet on a sensitive port",
    "ebs_unencrypted": "EBS volume created unencrypted",
}

_DESCRIPTION = {
    "s3_public_bucket": "An S3 bucket had a public ACL grant and/or was missing Block Public Access.",
    "sg_open_ingress": "A security group allowed inbound access from 0.0.0.0/0 or ::/0 on a sensitive port.",
    "ebs_unencrypted": "An EBS volume was created without encryption at rest.",
}

# Resource identifier key each remediation module actually returns.
_RESOURCE_KEY = {
    "s3_public_bucket": "bucket",
    "sg_open_ingress": "group_id",
    "ebs_unencrypted": "volume_id",
}

# Only map MITRE ATT&CK where it's a real, established technique. Left empty
# for sg_open_ingress/ebs_unencrypted rather than forcing a weak fit --
# "leaving a port open" and "forgetting encryption" aren't themselves ATT&CK
# techniques the way exfiltrating from cloud storage is.
_MITRE_ATTACK = {
    "s3_public_bucket": ["T1530"],  # Data from Cloud Storage Object
}

# Statuses that represent an actual misconfiguration being found, whether or
# not it was (or could be) acted on. "compliant" (nothing wrong) and "error"
# (malformed event, not a security signal) are not findings.
_FINDING_STATUSES = {"remediated", "no_action", "tagged_and_alerted", "dry_run"}


def _remediation_text(result: dict) -> str | None:
    if result.get("actions_taken"):
        return ", ".join(result["actions_taken"])
    if result["status"] == "dry_run":
        would = [key for key, value in result.items() if key.startswith("would_") and value]
        return ", ".join(would) or None
    if "rules_revoked" in result:
        return f"revoked {result['rules_revoked']} ingress rule(s)"
    return None


def to_shared_finding(result: dict) -> dict | None:
    """Map one remediation module's result dict onto finding.schema.json.

    Returns None for results that aren't findings at all: "compliant" (the
    resource was already fine) and "error" (malformed event, not a security
    signal) don't belong in the findings stream.
    """
    finding_type = result.get("finding")
    if result.get("status") not in _FINDING_STATUSES or finding_type not in _SEVERITY:
        return None

    resource_key = _RESOURCE_KEY[finding_type]
    return {
        "id": str(uuid.uuid4()),
        "source": SOURCE,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": _SEVERITY[finding_type],
        "category": CATEGORY,
        "title": _TITLE[finding_type],
        "description": _DESCRIPTION[finding_type],
        "resource": result.get(resource_key),
        "mitre_attack": _MITRE_ATTACK.get(finding_type, []),
        "owasp": [],
        "remediation": _remediation_text(result),
        "raw": {k: v for k, v in result.items() if k not in {"status", "finding"}},
    }


def write_shared_findings_jsonl(findings: list[dict], path: str | Path) -> None:
    """Write findings.jsonl for the observability stack's Promtail to tail.

    Overwrites the file each run -- a demo harness invocation is a fresh
    point-in-time snapshot, not an append-only event log.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for finding in findings:
            f.write(json.dumps(finding))
            f.write("\n")
