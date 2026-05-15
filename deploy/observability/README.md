# ETP Observability Stack

Local Prometheus + AlertManager + Grafana stack for monitoring one or
more ETP / LTP nodes. Built for both developer laptops and production
bastions.

## Visuals

If you want the architecture context behind the metrics, see [`docs/visuals/`](../../docs/visuals/README.md):

- [LTP presentation](../../docs/visuals/ltp.html)
- [GSX DAG presentation](../../docs/visuals/gsx-dag.html)
- [GSX DB presentation](../../docs/visuals/gsx-db.html)
- [Ecosystem Atlas](../../docs/visuals/gsx-ecosystem-atlas.html)

## Layout

```
deploy/observability/
├── docker-compose.yml
├── prometheus/
│   ├── prometheus.yml    # scrape config + external_labels
│   └── alerts.yml        # 14 rules over 4 groups
├── alertmanager/
│   └── alertmanager.yml  # routing (pagerduty / slack / webhook)
└── grafana/
    ├── dashboards/
    │   └── etp-node.json # "ETP / LTP Node Health" dashboard
    └── provisioning/
        ├── datasources/prometheus.yml
        └── dashboards/default.yml
```

## Quickstart

```bash
cd deploy/observability
docker-compose up -d

# Tail container logs
docker-compose logs -f prometheus alertmanager grafana
```

Endpoints:

| Service      | URL                    | Credentials        |
|--------------|------------------------|--------------------|
| Prometheus   | http://localhost:9090  | —                  |
| AlertManager | http://localhost:9093  | —                  |
| Grafana      | http://localhost:3000  | `admin` / `admin`  |

On first Grafana login you'll be prompted to set a new password.

The `ETP` folder under `Dashboards` is provisioned with
**ETP / LTP Node Health** — five rows covering node health, Merkle log &
audit, gateway, cross-chain bridge, and gossip / security events.

## Pointing at a real node

By default, Prometheus scrapes `host.docker.internal:8080`, which works
for a node running on the Docker host. To monitor remote nodes:

1. Edit `prometheus/prometheus.yml`:

   ```yaml
   scrape_configs:
     - job_name: etp-nodes
       scheme: https        # if your node serves TLS
       tls_config:
         ca_file: /etc/prometheus/etp-ca.crt
       static_configs:
         - targets: ["etp-node-us-east-1.example.com:8080"]
           labels:
             node_id: etp-mainnet-us-east-1
             region: US-East
         - targets: ["etp-node-eu-west-1.example.com:8080"]
           labels:
             node_id: etp-mainnet-eu-west-1
             region: EU-West
   ```

2. If scraping over TLS with a private CA, mount the CA cert into the
   prometheus container:

   ```yaml
   # docker-compose.yml override
   services:
     prometheus:
       volumes:
         - ./prometheus/etp-ca.crt:/etc/prometheus/etp-ca.crt:ro
   ```

3. Reload Prometheus:

   ```bash
   curl -X POST http://localhost:9090/-/reload
   ```

## Alerts

14 rules across 4 groups (`etp-node-health`, `etp-bridge`,
`etp-security`, `etp-network`). Severities:

- **critical** (page): node down, STH gap >10m, key rotation failure,
  nonce violation, bridge stuck >1h.
- **warning** (ticket / chat): elevated audit failures, REST 5xx or
  latency regressions, bridge retry queue growing, gossip isolation.

Each rule references the operator runbook via a `runbook:` annotation
(see `docs/OPERATOR_RUNBOOK.md` section 7).

### Wiring real receivers

`alertmanager/alertmanager.yml` ships with webhook stubs. To enable
real integrations, edit the file:

**Slack** (webhook):

```yaml
global:
  slack_api_url: "https://hooks.slack.com/services/T000/B000/XXXXX"

receivers:
  - name: slack-warnings
    slack_configs:
      - channel: "#etp-alerts"
        title: "{{ .GroupLabels.alertname }}"
        text: "{{ range .Alerts }}{{ .Annotations.summary }}\n{{ .Annotations.description }}\n{{ end }}"
```

**PagerDuty**:

```yaml
receivers:
  - name: pagerduty-critical
    pagerduty_configs:
      - service_key: "REPLACE_WITH_PD_INTEGRATION_KEY"
        description: "{{ .GroupLabels.alertname }} on {{ .GroupLabels.node_id }}"
```

Reload AlertManager:

```bash
curl -X POST http://localhost:9093/-/reload
```

## Metrics exported by the node

All metrics are defined in `src/ltp/observability/metrics.py` and
prefixed `etp_`. The dashboard covers all 17:

| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `etp_sth_publish_gap_seconds`          | gauge     | node_id | Seconds since last STH |
| `etp_audit_failure_rate`               | gauge     | node_id | Rolling PDP failure rate |
| `etp_materialize_failure_total`        | counter   | node_id | Reconstruct failures |
| `etp_rest_5xx_total`                   | counter   | node_id, route | Gateway 5xx |
| `etp_rest_latency_seconds`             | histogram | node_id, route | Gateway latency |
| `etp_shard_fetch_latency_seconds`      | histogram | node_id, peer  | Shard fetch latency |
| `etp_key_rotation_failures_total`      | counter   | node_id | KMS rotation failures |
| `etp_bridge_message_age_seconds`       | gauge     | node_id, chain | Oldest unfinalized bridge msg |
| `etp_nonce_violation_total`            | counter   | node_id | Replay / rewind attempts |
| `etp_dst_regression_total`             | counter   | node_id | Destination-state regressions |
| `etp_bridge_records_bridged_total`     | counter   | node_id, chain | Anchored records |
| `etp_bridge_records_failed_total`      | counter   | node_id, chain | Failed anchors |
| `etp_bridge_retry_queue_size`          | gauge     | node_id | Retry queue depth |
| `etp_gossip_peers_discovered_total`    | counter   | node_id | Newly discovered peers |
| `etp_gossip_peers_timed_out_total`     | counter   | node_id | Peer timeouts |
| `etp_gossip_exchanges_sent_total`      | counter   | node_id | Outbound gossip |

## Troubleshooting

**Prometheus target is down.**
Check the node's `/metrics` endpoint directly — from the Docker host:
`curl -fsS http://localhost:8080/metrics | head`. If it responds here
but not from the container, Docker can't reach `host.docker.internal`
(common on some Linux setups). Replace with the host's LAN IP.

**Grafana shows "Datasource not found".**
The `uid` must be `prometheus` — matches what the dashboard panels
reference. Don't rename it in `provisioning/datasources/prometheus.yml`.

**Dashboards don't appear.**
Check `docker-compose logs grafana`. The provisioning loader logs each
file it picks up. Typically a YAML error in
`provisioning/dashboards/default.yml`.

**Alerts fire during deploys.**
Expected. Use AlertManager silences:

```bash
amtool --alertmanager.url http://localhost:9093 silence add \
    alertname=ETPNodeDown node_id=etp-mainnet-us-east-1 \
    --duration=15m --comment="planned restart"
```

## Production hardening

For real deployments, the compose file is a starting point — you should:

- Replace default Grafana admin credentials (`GF_SECURITY_ADMIN_PASSWORD`).
- Put all three services behind an authenticated reverse proxy.
- Enable persistent storage backups for `prometheus-data`.
- Use remote-write to a long-term storage backend (Cortex, Thanos,
  Mimir) if you need >15 days of history.
- Pin image digests (`prom/prometheus@sha256:...`) in CI.
