"""Unit tests for the GuardDuty auto-response handler (no AWS calls)."""

import copy

import pytest
from botocore.exceptions import ClientError

import handler


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class FakeEC2:
    def __init__(self, instance=None, existing_sg=None, not_found=False):
        self.instance = instance
        self.existing_sg = existing_sg
        self.not_found = not_found
        self.calls = []

    def describe_instances(self, InstanceIds):
        self.calls.append(("describe_instances", InstanceIds))
        if self.not_found:
            raise ClientError({"Error": {"Code": "InvalidInstanceID.NotFound"}}, "DescribeInstances")
        return {"Reservations": [{"Instances": [self.instance]}]}

    def describe_security_groups(self, Filters=None, GroupIds=None):
        self.calls.append(("describe_security_groups", Filters or GroupIds))
        if GroupIds:
            return {"SecurityGroups": [{
                "GroupId": GroupIds[0],
                "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
            }]}
        return {"SecurityGroups": [{"GroupId": self.existing_sg}] if self.existing_sg else []}

    def create_security_group(self, **kwargs):
        self.calls.append(("create_security_group", kwargs))
        return {"GroupId": "sg-new123"}

    def revoke_security_group_egress(self, **kwargs):
        self.calls.append(("revoke_security_group_egress", kwargs))

    def modify_instance_attribute(self, **kwargs):
        self.calls.append(("modify_instance_attribute", kwargs))

    def create_tags(self, **kwargs):
        self.calls.append(("create_tags", kwargs))

    def create_snapshot(self, **kwargs):
        self.calls.append(("create_snapshot", kwargs))
        return {"SnapshotId": "snap-" + kwargs["VolumeId"][-3:]}

    def names(self):
        return [c[0] for c in self.calls]


class FakeIAM:
    def __init__(self, missing=False):
        self.missing = missing
        self.calls = []

    def update_access_key(self, **kwargs):
        self.calls.append(kwargs)
        if self.missing:
            raise ClientError({"Error": {"Code": "NoSuchEntity"}}, "UpdateAccessKey")


class FakeSNS:
    def __init__(self):
        self.published = []

    def publish(self, **kwargs):
        self.published.append(kwargs)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
INSTANCE = {
    "InstanceId": "i-0abc1234def567890",
    "VpcId": "vpc-111",
    "Tags": [{"Key": "Name", "Value": "web-1"}],
    "BlockDeviceMappings": [
        {"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-aaa"}},
        {"DeviceName": "/dev/xvdb", "Ebs": {"VolumeId": "vol-bbb"}},
    ],
}

EC2_EVENT = {
    "source": "aws.guardduty",
    "region": "us-east-1",
    "account": "123456789012",
    "detail-type": "GuardDuty Finding",
    "detail": {
        "id": "finding-ec2-1",
        "type": "Backdoor:EC2/C&CActivity.B!DNS",
        "severity": 8,
        "accountId": "123456789012",
        "title": "EC2 instance is querying a command and control server.",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {"instanceId": "i-0abc1234def567890"},
        },
    },
}

KEY_EVENT = {
    "source": "aws.guardduty",
    "region": "us-east-1",
    "detail": {
        "id": "finding-key-1",
        "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "severity": 8,
        "resource": {
            "resourceType": "AccessKey",
            "accessKeyDetails": {
                "accessKeyId": "AKIAABCDEFGHIJKLMNOP",
                "userType": "IAMUser",
                "userName": "ci-deploy",
            },
        },
    },
}


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:alerts")
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("SNAPSHOT_VOLUMES", "true")


def run(event, ec2=None, iam=None, sns=None):
    sns = sns or FakeSNS()
    clients = handler.Clients(ec2=ec2 or FakeEC2(), iam=iam or FakeIAM(), sns=sns)
    return handler.lambda_handler(copy.deepcopy(event), None, clients=clients), sns


# --------------------------------------------------------------------------- #
# EC2 tests
# --------------------------------------------------------------------------- #
def test_isolates_instance_creates_locked_sg_tags_and_snapshots():
    ec2 = FakeEC2(instance=copy.deepcopy(INSTANCE))
    result, sns = run(EC2_EVENT, ec2=ec2)

    assert result["status"] == "ok"
    assert "create_security_group" in ec2.names()
    assert "revoke_security_group_egress" in ec2.names()
    modify = [c for c in ec2.calls if c[0] == "modify_instance_attribute"][0][1]
    assert modify == {"InstanceId": "i-0abc1234def567890", "Groups": ["sg-new123"]}
    # containment happens before evidence collection
    assert ec2.names().index("modify_instance_attribute") < ec2.names().index("create_snapshot")
    assert len([c for c in ec2.calls if c[0] == "create_snapshot"]) == 2
    assert len(sns.published) == 1
    assert "LIVE" in sns.published[0]["Message"]


def test_reuses_existing_isolation_sg():
    ec2 = FakeEC2(instance=copy.deepcopy(INSTANCE), existing_sg="sg-existing")
    run(EC2_EVENT, ec2=ec2)
    assert "create_security_group" not in ec2.names()
    modify = [c for c in ec2.calls if c[0] == "modify_instance_attribute"][0][1]
    assert modify["Groups"] == ["sg-existing"]


def test_dry_run_makes_no_changes(monkeypatch):
    monkeypatch.setenv("DRY_RUN", "true")
    ec2 = FakeEC2(instance=copy.deepcopy(INSTANCE))
    result, sns = run(EC2_EVENT, ec2=ec2)
    assert result["dryRun"] is True
    for write in ("create_security_group", "modify_instance_attribute", "create_tags", "create_snapshot"):
        assert write not in ec2.names()
    assert "DRY RUN" in sns.published[0]["Message"]


def test_exempt_instance_is_skipped():
    instance = copy.deepcopy(INSTANCE)
    instance["Tags"].append({"Key": "AutoResponseExempt", "Value": "true"})
    ec2 = FakeEC2(instance=instance)
    result, _ = run(EC2_EVENT, ec2=ec2)
    assert "skipped by policy" in result["actions"][0]
    assert "modify_instance_attribute" not in ec2.names()


def test_already_isolated_instance_is_not_reprocessed():
    instance = copy.deepcopy(INSTANCE)
    instance["Tags"].append({"Key": "AutoResponse", "Value": "isolated"})
    ec2 = FakeEC2(instance=instance)
    result, _ = run(EC2_EVENT, ec2=ec2)
    assert "already isolated" in result["actions"][0]
    assert "modify_instance_attribute" not in ec2.names()


def test_sample_finding_with_fake_instance_is_handled():
    ec2 = FakeEC2(not_found=True)
    result, sns = run(EC2_EVENT, ec2=ec2)
    assert result["status"] == "ok"
    assert "not found" in result["actions"][0]
    assert len(sns.published) == 1


# --------------------------------------------------------------------------- #
# Access key tests
# --------------------------------------------------------------------------- #
def test_deactivates_iam_user_key_and_masks_it():
    iam = FakeIAM()
    result, sns = run(KEY_EVENT, iam=iam)
    assert iam.calls == [{"UserName": "ci-deploy", "AccessKeyId": "AKIAABCDEFGHIJKLMNOP", "Status": "Inactive"}]
    assert "AKIAABCDEFGHIJKLMNOP" not in sns.published[0]["Message"]
    assert "AKIA...MNOP" in result["actions"][0]


def test_role_credentials_are_not_touched():
    event = copy.deepcopy(KEY_EVENT)
    event["detail"]["resource"]["accessKeyDetails"].update(
        {"accessKeyId": "ASIAXXXXXXXXXXXXXXXX", "userType": "AssumedRole", "userName": "app-role"}
    )
    iam = FakeIAM()
    result, _ = run(event, iam=iam)
    assert iam.calls == []
    assert "Review manually" in result["actions"][0]


def test_sample_finding_with_fake_key_is_handled():
    iam = FakeIAM(missing=True)
    result, _ = run(KEY_EVENT, iam=iam)
    assert "not found" in result["actions"][0]


# --------------------------------------------------------------------------- #
# General behaviour
# --------------------------------------------------------------------------- #
def test_unknown_resource_type_notifies_only():
    event = copy.deepcopy(EC2_EVENT)
    event["detail"]["resource"] = {"resourceType": "S3Bucket"}
    result, sns = run(event)
    assert "notification only" in result["actions"][0]
    assert len(sns.published) == 1


def test_non_guardduty_event_is_ignored():
    result, sns = run({"detail": {"foo": "bar"}})
    assert result["status"] == "ignored"
    assert sns.published == []


def test_aws_error_still_notifies_then_raises_for_retry():
    class BrokenEC2(FakeEC2):
        def modify_instance_attribute(self, **kwargs):
            raise ClientError({"Error": {"Code": "UnauthorizedOperation"}}, "ModifyInstanceAttribute")

    sns = FakeSNS()
    with pytest.raises(ClientError):
        run(EC2_EVENT, ec2=BrokenEC2(instance=copy.deepcopy(INSTANCE)), sns=sns)
    assert "FAILED" in sns.published[0]["Message"]


def test_subject_is_short_and_ascii():
    event = copy.deepcopy(EC2_EVENT)
    event["detail"]["type"] = "X" * 300
    _, sns = run(event, ec2=FakeEC2(instance=copy.deepcopy(INSTANCE)))
    subject = sns.published[0]["Subject"]
    assert len(subject) <= 100
    subject.encode("ascii")
