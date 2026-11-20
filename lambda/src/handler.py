"""GuardDuty auto-response Lambda.

Triggered by an EventBridge rule when Amazon GuardDuty reports a finding at or
above a severity threshold. Depending on the affected resource it:

* EC2 instance  -> moves the instance into an "isolation" security group with
                   no inbound or outbound rules, tags it, and snapshots its EBS
                   volumes for forensics.
* IAM user key  -> deactivates the compromised access key.
* anything else -> sends a notification only.

Every finding produces an SNS notification describing what was (or, in dry-run
mode, what would have been) done.
"""

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

ISOLATED_TAG_KEY = "AutoResponse"
ISOLATED_TAG_VALUE = "isolated"
EXEMPT_TAG_KEY = "AutoResponseExempt"


def _env_bool(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes")


def _config():
    """Read configuration at call time so tests can change environment variables."""
    return {
        "dry_run": _env_bool("DRY_RUN", True),
        "snapshot_volumes": _env_bool("SNAPSHOT_VOLUMES", True),
        "sns_topic_arn": os.environ.get("SNS_TOPIC_ARN", ""),
        "isolation_sg_name": os.environ.get("ISOLATION_SG_NAME", "gd-auto-response-isolation"),
    }


class Clients:
    """AWS clients, created lazily so unit tests can pass in fakes."""

    def __init__(self, ec2=None, iam=None, sns=None):
        self._ec2, self._iam, self._sns = ec2, iam, sns

    @property
    def ec2(self):
        if self._ec2 is None:
            self._ec2 = boto3.client("ec2")
        return self._ec2

    @property
    def iam(self):
        if self._iam is None:
            self._iam = boto3.client("iam")
        return self._iam

    @property
    def sns(self):
        if self._sns is None:
            self._sns = boto3.client("sns")
        return self._sns


def _error_code(error):
    return getattr(error, "response", {}).get("Error", {}).get("Code", "")


def _mask(value):
    """Never put a full access key ID in logs or emails."""
    if not value or len(value) < 8:
        return "****"
    return value[:4] + "..." + value[-4:]


# --------------------------------------------------------------------------- #
# EC2 isolation
# --------------------------------------------------------------------------- #
def get_or_create_isolation_sg(ec2, vpc_id, sg_name, dry_run):
    """Return the ID of a security group with no inbound and no outbound rules."""
    existing = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": [sg_name]},
        ]
    )["SecurityGroups"]
    if existing:
        return existing[0]["GroupId"]
    if dry_run:
        return "(new isolation security group)"

    created = ec2.create_security_group(
        GroupName=sg_name,
        Description="Quarantine group: no inbound or outbound traffic (GuardDuty auto-response)",
        VpcId=vpc_id,
        TagSpecifications=[
            {
                "ResourceType": "security-group",
                "Tags": [{"Key": "Purpose", "Value": "guardduty-quarantine"}],
            }
        ],
    )
    sg_id = created["GroupId"]

    # New security groups allow all outbound traffic by default. Remove every
    # egress rule (IPv4 and, in IPv6-enabled VPCs, IPv6) so nothing can leave.
    group = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    egress = group.get("IpPermissionsEgress", [])
    if egress:
        ec2.revoke_security_group_egress(GroupId=sg_id, IpPermissions=egress)
    return sg_id


def isolate_instance(ec2, finding, config):
    instance_id = (
        finding.get("resource", {}).get("instanceDetails", {}).get("instanceId")
    )
    if not instance_id:
        return ["No instance ID in finding; no action taken."]

    try:
        reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as error:
        if _error_code(error) in ("InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"):
            return [
                f"Instance {instance_id} not found in this account/region "
                "(GuardDuty sample findings use fake IDs); no action taken."
            ]
        raise

    if not reservations or not reservations[0]["Instances"]:
        return [f"Instance {instance_id} not found; no action taken."]
    instance = reservations[0]["Instances"][0]
    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}

    if tags.get(EXEMPT_TAG_KEY, "").lower() == "true":
        return [f"Instance {instance_id} is tagged {EXEMPT_TAG_KEY}=true; skipped by policy."]
    if tags.get(ISOLATED_TAG_KEY) == ISOLATED_TAG_VALUE:
        return [f"Instance {instance_id} is already isolated; no further action."]

    vpc_id = instance.get("VpcId")
    if not vpc_id:
        return [f"Instance {instance_id} has no VPC; cannot apply a security group."]

    sg_id = get_or_create_isolation_sg(ec2, vpc_id, config["isolation_sg_name"], config["dry_run"])
    volume_ids = [
        m["Ebs"]["VolumeId"]
        for m in instance.get("BlockDeviceMappings", [])
        if "Ebs" in m and "VolumeId" in m["Ebs"]
    ]

    if config["dry_run"]:
        actions = [f"DRY RUN: would move {instance_id} into isolation security group {sg_id}."]
        if config["snapshot_volumes"] and volume_ids:
            actions.append(f"DRY RUN: would snapshot volumes {', '.join(volume_ids)}.")
        return actions

    actions = []
    # 1. Contain first: replace every security group on the instance.
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[sg_id])
    actions.append(f"Moved {instance_id} into isolation security group {sg_id}.")

    # 2. Mark it, so a repeated finding does not repeat the work.
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": ISOLATED_TAG_KEY, "Value": ISOLATED_TAG_VALUE},
            {"Key": "AutoResponseFinding", "Value": finding.get("id", "unknown")[:255]},
        ],
    )
    actions.append(f"Tagged {instance_id} {ISOLATED_TAG_KEY}={ISOLATED_TAG_VALUE}.")

    # 3. Preserve evidence.
    if config["snapshot_volumes"]:
        for volume_id in volume_ids:
            snap = ec2.create_snapshot(
                VolumeId=volume_id,
                Description=f"Forensic snapshot of {instance_id} for GuardDuty finding",
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "Purpose", "Value": "guardduty-forensics"},
                            {"Key": "SourceInstance", "Value": instance_id},
                        ],
                    }
                ],
            )
            actions.append(f"Started forensic snapshot {snap['SnapshotId']} of {volume_id}.")
    return actions


# --------------------------------------------------------------------------- #
# IAM access key
# --------------------------------------------------------------------------- #
def disable_access_key(iam, finding, config):
    details = finding.get("resource", {}).get("accessKeyDetails", {})
    key_id = details.get("accessKeyId", "")
    user_type = details.get("userType", "")
    user_name = details.get("userName", "")

    if user_type != "IAMUser" or not user_name or key_id.startswith("ASIA"):
        return [
            f"Principal type '{user_type or 'unknown'}' uses temporary credentials or is not an "
            "IAM user; its key cannot be deactivated automatically. Review manually "
            "(for a role: revoke active sessions)."
        ]

    if config["dry_run"]:
        return [f"DRY RUN: would deactivate access key {_mask(key_id)} for IAM user {user_name}."]

    try:
        iam.update_access_key(UserName=user_name, AccessKeyId=key_id, Status="Inactive")
    except ClientError as error:
        if _error_code(error) == "NoSuchEntity":
            return [
                f"Access key {_mask(key_id)} / user {user_name} not found "
                "(sample findings use fake keys); no action taken."
            ]
        raise
    return [f"Deactivated access key {_mask(key_id)} for IAM user {user_name}."]


# --------------------------------------------------------------------------- #
# Notification
# --------------------------------------------------------------------------- #
def build_message(event, finding, actions, config):
    region = event.get("region") or finding.get("region", "")
    finding_id = finding.get("id", "")
    lines = [
        "GuardDuty auto-response",
        "",
        f"Mode:      {'DRY RUN (no changes made)' if config['dry_run'] else 'LIVE'}",
        f"Finding:   {finding.get('type', 'unknown')}",
        f"Severity:  {finding.get('severity', 'unknown')}",
        f"Account:   {finding.get('accountId', event.get('account', 'unknown'))}",
        f"Region:    {region}",
        f"Resource:  {finding.get('resource', {}).get('resourceType', 'unknown')}",
        f"Title:     {finding.get('title', '')}",
        "",
        "Actions:",
    ]
    lines += [f"  - {a}" for a in actions]
    if finding_id and region:
        lines += [
            "",
            "Open in console:",
            f"  https://console.aws.amazon.com/guardduty/home?region={region}#/findings?fId={finding_id}",
        ]
    return "\n".join(lines)


def notify(sns, event, finding, actions, config):
    subject = f"[GuardDuty sev {finding.get('severity', '?')}] {finding.get('type', 'finding')}"
    # SNS subjects: ASCII only, no line breaks, at most 100 characters.
    subject = subject.encode("ascii", "replace").decode().replace("\n", " ")[:100]
    message = build_message(event, finding, actions, config)
    if not config["sns_topic_arn"]:
        LOG.warning("SNS_TOPIC_ARN not set; notification only logged.")
        return
    sns.publish(TopicArn=config["sns_topic_arn"], Subject=subject, Message=message)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def lambda_handler(event, context, clients=None):
    clients = clients or Clients()
    config = _config()
    finding = (event or {}).get("detail") or {}

    if not finding.get("id") or "resource" not in finding:
        LOG.error(json.dumps({"msg": "event is not a GuardDuty finding", "event": event}))
        return {"status": "ignored", "reason": "not a GuardDuty finding"}

    resource_type = finding["resource"].get("resourceType", "")
    LOG.info(json.dumps({
        "msg": "processing finding",
        "findingId": finding["id"],
        "type": finding.get("type"),
        "severity": finding.get("severity"),
        "resourceType": resource_type,
        "dryRun": config["dry_run"],
    }))

    failure = None
    try:
        if resource_type == "Instance":
            actions = isolate_instance(clients.ec2, finding, config)
        elif resource_type == "AccessKey":
            actions = disable_access_key(clients.iam, finding, config)
        else:
            actions = [f"No automated response for resource type '{resource_type}'; notification only."]
    except ClientError as error:
        failure = error
        actions = [f"FAILED: {_error_code(error) or 'error'}: {error}. Manual response needed."]

    for action in actions:
        LOG.info(json.dumps({"findingId": finding["id"], "action": action}))
    notify(clients.sns, event, finding, actions, config)

    if failure is not None:
        # Re-raise so Lambda retries the event and, if it keeps failing,
        # sends it to the dead-letter queue for investigation.
        raise failure

    return {"status": "ok", "findingId": finding["id"], "dryRun": config["dry_run"], "actions": actions}
