# Observability env state — currently small, intentionally separate
# from the prod env so a bad change to the monitoring stack can never
# accidentally roll the cluster running etp-node.
#
# What lives here today:
#   - A KMS CMK that wraps Secrets Manager entries for the PagerDuty
#     (or OpsGenie) integration key, plus any future Grafana
#     admin/Datadog API credentials.
#
# What will live here later (PR B2 / B-follow-up):
#   - aws_secretsmanager_secret "pagerduty_integration_key" (created here
#     so the value can be rotated without touching prod state)
#   - aws_secretsmanager_secret "grafana_admin_password"
#
# The actual Prometheus/Grafana/AlertManager workloads run *inside* the
# prod EKS cluster (see infra/helm/observability/ when PR B2 lands).
# This env just owns the AWS-side secrets they consume.

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.tags
  }
}

module "kms_observability" {
  source = "../../modules/kms"

  name                = "${var.name}-secrets"
  description         = "LTP observability secrets wrapping — PagerDuty integration key, Grafana admin credentials, future paging-backend tokens."
  enable_key_rotation = true
  tags                = var.tags
}
