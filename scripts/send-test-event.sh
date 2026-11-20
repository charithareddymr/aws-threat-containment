#!/usr/bin/env bash
# Sends a fake high-severity GuardDuty finding about one of YOUR test EC2
# instances, so you can watch the full response end to end.
#
# Usage:   bash scripts/send-test-event.sh i-0123456789abcdef0
# Needs:   AWS CLI and jq (both are pre-installed in AWS CloudShell).
#
# Only use an instance you created for testing: in live mode it WILL be isolated.

set -euo pipefail

INSTANCE_ID="${1:?Usage: $0 <instance-id>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
REGION="${AWS_REGION:-$(aws configure get region || echo us-east-1)}"

ENTRIES="$(jq -c \
  --arg id "$INSTANCE_ID" --arg acct "$ACCOUNT_ID" --arg region "$REGION" \
  '[{
     Source: "custom.gd-auto-response.test",
     DetailType: "GuardDuty Finding",
     Detail: (.resource.instanceDetails.instanceId = $id
              | .accountId = $acct
              | .region = $region
              | tojson)
   }]' "$SCRIPT_DIR/test-finding-ec2.json")"

aws events put-events --region "$REGION" --entries "$ENTRIES"
echo "Test event sent for $INSTANCE_ID. Check your email and the Lambda logs in a minute."
