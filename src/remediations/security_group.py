import logging

import boto3

from utils.notify import publish

logger = logging.getLogger()

# Ports we consider sensitive enough to revoke on sight when opened to the world.
SENSITIVE_PORTS = {22, 23, 1433, 27017, 3306, 3389, 5432, 5984, 6379, 9200}
PUBLIC_CIDR_V4 = "0.0.0.0/0"
PUBLIC_CIDR_V6 = "::/0"

FINDING = "sg_open_ingress"


def _extract_group_id(detail):
    return (detail.get("requestParameters") or {}).get("groupId")


def _is_sensitive_rule(item):
    from_port = item.get("fromPort")
    to_port = item.get("toPort")
    if from_port is None or to_port is None:
        return True
    return any(from_port <= port <= to_port for port in SENSITIVE_PORTS)


def _find_offending_permissions(detail):
    request_params = detail.get("requestParameters") or {}
    items = (request_params.get("ipPermissions") or {}).get("items", [])
    offending = []
    for item in items:
        ip_ranges = (item.get("ipRanges") or {}).get("items", [])
        ipv6_ranges = (item.get("ipv6Ranges") or {}).get("items", [])
        is_public = any(r.get("cidrIp") == PUBLIC_CIDR_V4 for r in ip_ranges) or any(
            r.get("cidrIpv6") == PUBLIC_CIDR_V6 for r in ipv6_ranges
        )
        if is_public and _is_sensitive_rule(item):
            offending.append(item)
    return offending


def _to_revoke_permission(item):
    permission = {"IpProtocol": item.get("ipProtocol")}
    if item.get("fromPort") is not None:
        permission["FromPort"] = item["fromPort"]
    if item.get("toPort") is not None:
        permission["ToPort"] = item["toPort"]

    ip_ranges = [
        {"CidrIp": r["cidrIp"]}
        for r in (item.get("ipRanges") or {}).get("items", [])
        if r.get("cidrIp") == PUBLIC_CIDR_V4
    ]
    if ip_ranges:
        permission["IpRanges"] = ip_ranges

    ipv6_ranges = [
        {"CidrIpv6": r["cidrIpv6"]}
        for r in (item.get("ipv6Ranges") or {}).get("items", [])
        if r.get("cidrIpv6") == PUBLIC_CIDR_V6
    ]
    if ipv6_ranges:
        permission["Ipv6Ranges"] = ipv6_ranges

    return permission


def remediate(detail, dry_run=False, ec2_client=None):
    """Revokes ingress rules that open a sensitive port to 0.0.0.0/0 or ::/0."""
    ec2_client = ec2_client or boto3.client("ec2")
    group_id = _extract_group_id(detail)

    if not group_id:
        return {"status": "error", "reason": "no_group_id", "finding": FINDING}

    offending = _find_offending_permissions(detail)
    if not offending:
        return {"status": "compliant", "group_id": group_id, "finding": FINDING}

    if dry_run:
        return {
            "status": "dry_run",
            "group_id": group_id,
            "finding": FINDING,
            "would_revoke_rules": len(offending),
        }

    revoked = 0
    for item in offending:
        permission = _to_revoke_permission(item)
        try:
            ec2_client.revoke_security_group_ingress(GroupId=group_id, IpPermissions=[permission])
            revoked += 1
        except Exception:
            logger.exception("revoke_security_group_ingress_failed group_id=%s", group_id)

    result = {
        "status": "remediated" if revoked else "no_action",
        "group_id": group_id,
        "finding": FINDING,
        "rules_revoked": revoked,
    }
    if revoked:
        publish(subject="Security group open ingress revoked", message=result)
    return result
