resource "aws_guardduty_detector" "this" {
  #checkov:skip=CKV2_AWS_3:Single-account demo; no AWS Organization to delegate GuardDuty to.
  count = var.create_guardduty_detector ? 1 : 0

  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}
