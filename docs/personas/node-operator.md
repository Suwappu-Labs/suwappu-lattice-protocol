# Node Operator

You're running an **LTP node**, a **gateway**, or a **corridor super-node**.
You're responsible for keys, uptime, monitoring, and deploys.

## 30-second value prop

LTP nodes ingest off-chain state, build Merkle trees, sign the roots with
ML-DSA-65 + Ed25519 hybrid, and submit them to the on-chain registry on a
fixed cadence. As an operator you keep the signing keys safe, the node
synced, and the anchor submissions flowing. Everything is observable and
upgradable; nothing is irreversible.

## Start here

1. **[DEPLOYMENT_GUIDE.md](../DEPLOYMENT_GUIDE.md)** — Docker, Kubernetes,
   CI/CD, key management, monitoring. Read this end-to-end before your
   first deploy.
2. **[OPERATOR_RUNBOOK.md](../OPERATOR_RUNBOOK.md)** — day-2 operations:
   key rotation, incident response, on-call rotation, emergency-pause
   procedure. Section 13 has the v7 deploy checklist.
3. **[DEPLOYED_CONTRACTS.md](../DEPLOYED_CONTRACTS.md)** — current
   registry addresses, MultiSig signers, Timelock delays. Your node
   submits to these.
4. **[bridge-mvp-scope.md](../bridge-mvp-scope.md)** — what the corridor
   super-node is responsible for in the bridge MVP, and what is out of
   scope for v1.

## Pre-flight checklist

Before bringing a node into production traffic:

- [ ] Keys generated with HSM (not soft keys) — see
      [DEPLOYMENT_GUIDE.md](../DEPLOYMENT_GUIDE.md) §"Key Management"
- [ ] `LTP_ENV=production` set; verify with `make health`
- [ ] Anchor submission cadence matches the registry's configured epoch
- [ ] Monitoring dashboards wired (anchor-submission rate, signing latency,
      registry tx success rate)
- [ ] On-call rotation acknowledged the runbook §3 escalation tree
- [ ] Emergency-pause MultiSig signer keys distributed to the right people

## Common questions

- **"How do I rotate signing keys without downtime?"**
  → [OPERATOR_RUNBOOK.md](../OPERATOR_RUNBOOK.md) §7 "Key Rotation".
  Hybrid window is 7 days; both old and new keys are accepted by the
  registry during that window.
- **"What if I miss an anchor epoch?"**
  → Resubmit within the next epoch with `--catch-up`. The registry
  tolerates up to 3 missed consecutive epochs before the contract enters
  degraded mode (see [THREAT_MODEL.md](../THREAT_MODEL.md) §"Liveness").
- **"Where do alerts go?"**
  → Default: `security-on-call@globalsettlement.dev`. Override in
  `config/alerting.yaml`.
