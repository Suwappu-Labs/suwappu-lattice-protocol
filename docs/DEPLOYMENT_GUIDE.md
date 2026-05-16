# ETP Deployment Guide

```mermaid
flowchart LR
    S1["Stage 1\nLocal Dev"] --> S2["Stage 2\nContainerized"] --> S3["Stage 3\nCI/CD"] --> S4["Stage 4\nKubernetes"] --> S5["Stage 5\nKey Management"] --> S6["Stage 6\nMonitoring"] --> S7["Stage 7\nChecklist"]
```

Concrete steps to deploy the Entanglement Transfer Protocol from local dev to production infrastructure. See [STABILITY_PROMISES.md](./STABILITY_PROMISES.md) for the version-skew tolerances and [plans/2026-05-11-production-roadmap.md](./plans/2026-05-11-production-roadmap.md) for the current roadmap.

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | >= 3.10 | Runtime |
| Docker | >= 24.0 | Containerization |
| docker-compose | >= 2.20 | Local multi-service |
| Kubernetes | >= 1.28 | Production orchestration |
| Helm | >= 3.12 | K8s package management |
| `gh` CLI | >= 2.0 | CI/CD (GitHub Actions) |
| RocksDB | >= 8.0 | Persistent storage (Phase 2+) |
| liboqs | >= 0.15.0 | Production PQ crypto (Phase 1+) |

---

## Stage 1: Local Development (Current State)

```bash
# Clone and install
git clone <repo-url> && cd Entanglement-Transfer-Protocol
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run demo
python -m ltp
```

All 821 tests pass with zero external dependencies (stdlib-only PoC crypto).

---

## Stage 2: Containerized Development

### 2.1 Base Dockerfile

```dockerfile
# Dockerfile
FROM python:3.12-slim AS base

# Install liboqs + RocksDB build dependencies (Phase 1 crypto swap + Phase 2 storage)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build libssl-dev git librocksdb-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs + liboqs-python
RUN git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cd /tmp/liboqs && mkdir build && cd build \
    && cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local \
       -DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON .. \
    && ninja && ninja install \
    && rm -rf /tmp/liboqs

# Python dependencies (production)
RUN pip install --no-cache-dir \
    liboqs-python>=0.15.0 \
    PyNaCl>=1.5.0 \
    zfec>=1.5.0 \
    blake3>=1.0.0 \
    grpcio>=1.60.0 \
    fastapi>=0.109.0 \
    uvicorn[standard]>=0.27.0 \
    prometheus-client>=0.20.0 \
    python-rocksdb>=0.7.0

# Application code
COPY src/ /app/src/
COPY tests/ /app/tests/
COPY pyproject.toml /app/
WORKDIR /app

RUN pip install --no-cache-dir -e ".[dev]"

ENV PYTHONPATH=/app/src
ENV ETP_ENV=development

# --- Service-specific images built FROM base ---

FROM base AS api-gateway
EXPOSE 8000
CMD ["uvicorn", "ltp.api.gateway:app", "--host", "0.0.0.0", "--port", "8000"]

FROM base AS protocol-service
EXPOSE 50051
CMD ["python", "-m", "ltp.services.protocol"]

FROM base AS log-service
EXPOSE 50052
VOLUME ["/data/merkle"]
CMD ["python", "-m", "ltp.services.log"]

FROM base AS shard-node
EXPOSE 50053
VOLUME ["/data/shards"]
CMD ["python", "-m", "ltp.services.shard_node"]

FROM base AS bridge-anchor
CMD ["python", "-m", "ltp.bridge.services.anchor"]

FROM base AS bridge-relayer
CMD ["python", "-m", "ltp.bridge.services.relayer"]

FROM base AS bridge-materializer
CMD ["python", "-m", "ltp.bridge.services.materializer"]
```

### 2.2 docker-compose.yml (Development)

```yaml
version: "3.9"

x-common: &common
  build:
    context: .
    dockerfile: Dockerfile
  restart: unless-stopped
  networks:
    - etp-net

services:
  # --- Core Services ---
  api-gateway:
    <<: *common
    build:
      context: .
      target: api-gateway
    ports:
      - "8000:8000"
    environment:
      - ETP_LOG_SERVICE=log-service:50052
      - ETP_PROTOCOL_SERVICE=protocol-service:50051
    depends_on:
      - protocol-service
      - log-service

  protocol-service:
    <<: *common
    build:
      context: .
      target: protocol-service
    ports:
      - "50051:50051"
    environment:
      - ETP_LOG_SERVICE=log-service:50052
      - ETP_SHARD_NODES=shard-node-1:50053,shard-node-2:50053,shard-node-3:50053
    depends_on:
      - log-service
      - shard-node-1
      - shard-node-2
      - shard-node-3

  log-service:
    <<: *common
    build:
      context: .
      target: log-service
    ports:
      - "50052:50052"
    volumes:
      - merkle-data:/data/merkle
    environment:
      - ETP_SIGNING_KEY_PATH=/run/secrets/operator_sk
      - ETP_ROCKSDB_PATH=/data/merkle/db
    secrets:
      - operator_sk

  # --- Shard Storage Nodes ---
  shard-node-1:
    <<: *common
    build:
      context: .
      target: shard-node
    ports:
      - "50053:50053"
    volumes:
      - shard-data-1:/data/shards
    environment:
      - ETP_NODE_ID=node-1
      - ETP_REGION=us-east

  shard-node-2:
    <<: *common
    build:
      context: .
      target: shard-node
    ports:
      - "50054:50053"
    volumes:
      - shard-data-2:/data/shards
    environment:
      - ETP_NODE_ID=node-2
      - ETP_REGION=us-west

  shard-node-3:
    <<: *common
    build:
      context: .
      target: shard-node
    ports:
      - "50055:50053"
    volumes:
      - shard-data-3:/data/shards
    environment:
      - ETP_NODE_ID=node-3
      - ETP_REGION=eu-west

  # --- Bridge Services ---
  bridge-anchor:
    <<: *common
    build:
      context: .
      target: bridge-anchor
    environment:
      - ETP_L1_RPC=http://l1-node:8545
      - ETP_PROTOCOL_SERVICE=protocol-service:50051

  bridge-relayer:
    <<: *common
    build:
      context: .
      target: bridge-relayer
    environment:
      - ETP_L2_VERIFIER_EK_PATH=/run/secrets/l2_verifier_ek
    secrets:
      - l2_verifier_ek

  bridge-materializer:
    <<: *common
    build:
      context: .
      target: bridge-materializer
    environment:
      - ETP_L2_VERIFIER_DK_PATH=/run/secrets/l2_verifier_dk
      - ETP_LOG_SERVICE=log-service:50052
    secrets:
      - l2_verifier_dk

  # --- Observability ---
  prometheus:
    image: prom/prometheus:v2.50.0
    ports:
      - "9090:9090"
    volumes:
      - ./deploy/prometheus.yml:/etc/prometheus/prometheus.yml
    networks:
      - etp-net

  grafana:
    image: grafana/grafana:10.3.0
    ports:
      - "3000:3000"
    environment:
      - GF_AUTH_ANONYMOUS_ENABLED=true
    volumes:
      - ./deploy/grafana/dashboards:/etc/grafana/provisioning/dashboards
    networks:
      - etp-net

volumes:
  merkle-data:
  shard-data-1:
  shard-data-2:
  shard-data-3:

networks:
  etp-net:
    driver: bridge

secrets:
  operator_sk:
    file: ./secrets/operator_sk.key
  l2_verifier_ek:
    file: ./secrets/l2_verifier_ek.key
  l2_verifier_dk:
    file: ./secrets/l2_verifier_dk.key
```

---

## Stage 3: CI/CD Pipeline

### 3.1 GitHub Actions

```yaml
# .github/workflows/ci.yml
name: ETP CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -e ".[dev]"
      - run: pytest tests/ -v --tb=short

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install ruff mypy
      - run: ruff check src/ tests/
      - run: mypy src/ --ignore-missing-imports

  docker-build:
    runs-on: ubuntu-latest
    needs: [test, lint]
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/build-push-action@v5
        with:
          context: .
          target: base
          push: false
          tags: etp/base:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

  integration:
    runs-on: ubuntu-latest
    needs: [docker-build]
    steps:
      - uses: actions/checkout@v4
      - run: docker compose up -d
      - run: docker compose exec -T api-gateway python -m pytest tests/ -v
      - run: docker compose down -v
```

### 3.2 Release Pipeline

```yaml
# .github/workflows/release.yml
name: ETP Release

on:
  push:
    tags: ["v*"]

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: |
            ghcr.io/${{ github.repository }}/api-gateway:${{ github.ref_name }}
            ghcr.io/${{ github.repository }}/api-gateway:latest
          target: api-gateway
      # Repeat for each service target...
```

---

## Stage 4: Kubernetes Production Deployment

### 4.1 Namespace and RBAC

```yaml
# deploy/k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: etp
  labels:
    app.kubernetes.io/part-of: etp
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: etp-operator
  namespace: etp
```

### 4.2 Log Service (StatefulSet — needs stable storage)

```yaml
# deploy/k8s/log-service.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: log-service
  namespace: etp
spec:
  serviceName: log-service
  replicas: 1  # Single operator model (Phase 2)
  selector:
    matchLabels:
      app: log-service
  template:
    metadata:
      labels:
        app: log-service
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
    spec:
      serviceAccountName: etp-operator
      containers:
        - name: log-service
          image: ghcr.io/<org>/etp/log-service:latest
          ports:
            - containerPort: 50052
              name: grpc
            - containerPort: 9090
              name: metrics
          env:
            - name: ETP_ROCKSDB_PATH
              value: /data/merkle/db
            - name: ETP_SIGNING_KEY_PATH
              value: /run/secrets/operator-sk/key
          volumeMounts:
            - name: merkle-data
              mountPath: /data/merkle
            - name: operator-sk
              mountPath: /run/secrets/operator-sk
              readOnly: true
          resources:
            requests:
              memory: "512Mi"
              cpu: "500m"
            limits:
              memory: "2Gi"
              cpu: "2000m"
          livenessProbe:
            grpc:
              port: 50052
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            grpc:
              port: 50052
            initialDelaySeconds: 5
            periodSeconds: 10
      volumes:
        - name: operator-sk
          secret:
            secretName: etp-operator-signing-key
  volumeClaimTemplates:
    - metadata:
        name: merkle-data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: fast-ssd
        resources:
          requests:
            storage: 50Gi
```

### 4.3 Shard Nodes (StatefulSet — one per region)

```yaml
# deploy/k8s/shard-nodes.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: shard-node
  namespace: etp
spec:
  serviceName: shard-node
  replicas: 8  # Matches default n=8
  selector:
    matchLabels:
      app: shard-node
  template:
    metadata:
      labels:
        app: shard-node
    spec:
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: topology.kubernetes.io/zone
          whenUnsatisfiable: DoNotSchedule
          labelSelector:
            matchLabels:
              app: shard-node
      containers:
        - name: shard-node
          image: ghcr.io/<org>/etp/shard-node:latest
          ports:
            - containerPort: 50053
              name: grpc
          env:
            - name: ETP_NODE_ID
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: ETP_NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            # ETP_REGION is set per-zone via Helm values or separate StatefulSets.
            # The K8s downward API cannot select individual label keys.
            # Option A: Use Helm --set region=us-east per zone deployment
            # Option B: Init container reads node labels via K8s API
            - name: ETP_REGION
              value: "us-east"  # Override per-zone deployment
          volumeMounts:
            - name: shard-data
              mountPath: /data/shards
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "1Gi"
              cpu: "1000m"
  volumeClaimTemplates:
    - metadata:
        name: shard-data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: standard-ssd
        resources:
          requests:
            storage: 100Gi
```

### 4.4 API Gateway (Deployment — stateless)

```yaml
# deploy/k8s/api-gateway.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  namespace: etp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
    spec:
      containers:
        - name: api-gateway
          image: ghcr.io/<org>/etp/api-gateway:latest
          ports:
            - containerPort: 8000
              name: http
          env:
            - name: ETP_LOG_SERVICE
              value: log-service-0.log-service.etp.svc.cluster.local:50052
            - name: ETP_PROTOCOL_SERVICE
              value: protocol-service.etp.svc.cluster.local:50051
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "1000m"
---
apiVersion: v1
kind: Service
metadata:
  name: api-gateway
  namespace: etp
spec:
  type: ClusterIP
  selector:
    app: api-gateway
  ports:
    - port: 8000
      targetPort: 8000
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-gateway
  namespace: etp
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts:
        - api.etp.example.com
      secretName: etp-api-tls
  rules:
    - host: api.etp.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api-gateway
                port:
                  number: 8000
```

---

## Stage 5: Key Management

### 5.0 Key Protection Strategy

The STH signing key is the trust anchor for the entire commitment log. Key protection
options were evaluated as of early 2026:

| Solution | ML-DSA-65 Status | Hardware-Protected? | Monthly Cost (HA) |
|----------|-----------------|--------------------|--------------------|
| **AWS KMS** | **GA** | Yes (AWS-managed FIPS 140-3 L3 HSMs) | **~$1.26** |
| AWS CloudHSM | Preview (not GA) | Yes (self-managed) | ~$2,100 |
| Vault Enterprise | Experimental | No (software) | ~$4,500+ |
| Thales Luna HSM v7.9 | Production firmware | Yes (self-managed hardware) | Varies |

**Recommended approach (phased):**

1. **Now — AWS KMS ML-DSA-65** (default): GA since mid-2025, FIPS 140-3 Level 3 internally,
   $1.26/month. Key never leaves AWS HSMs. Trade-off: you trust AWS to operate the hardware.
   Alternatively, sign in software with liboqs and encrypt the key at rest via KMS envelope
   encryption (~$1/month + compute).

2. **When CloudHSM ML-DSA goes GA** — Migrate signing into CloudHSM for self-managed hardware
   isolation. Key never exists outside your HSM. ~$2,100/month for 2-HSM HA cluster.

3. **Vault makes sense only if** you're already running Vault Enterprise for other purposes
   (database creds, PKI, cloud IAM). It does not provide hardware isolation during signing —
   keys live in server process memory. Not recommended as a standalone solution for a single
   signing key.

### 5.1 Option A: AWS KMS ML-DSA-65 (Recommended)

```bash
#!/bin/bash
# scripts/keygen-kms.sh — Create ML-DSA-65 signing key in AWS KMS
set -euo pipefail

# Create the operator STH signing key (ML-DSA-65, FIPS 140-3 Level 3)
OPERATOR_KEY_ID=$(aws kms create-key \
  --key-spec ML_DSA_65 \
  --key-usage SIGN_VERIFY \
  --description "ETP operator STH signing key" \
  --query 'KeyMetadata.KeyId' --output text)

aws kms create-alias \
  --alias-name alias/etp-operator-sth \
  --target-key-id "$OPERATOR_KEY_ID"

echo "Operator signing key: $OPERATOR_KEY_ID"
echo "Sign via: aws kms sign --key-id alias/etp-operator-sth --signing-algorithm ML_DSA_SHAKE_256 ..."

# L2 verifier ML-KEM keypair (generated locally, DK encrypted at rest by KMS)
python3 -c "
from ltp.primitives import MLKEM
ek, dk = MLKEM.keygen()
open('secrets/l2_verifier_ek.key', 'wb').write(ek)
open('secrets/l2_verifier_dk.key', 'wb').write(dk)
print(f'Verifier EK: {len(ek)} bytes')
print(f'Verifier DK: {len(dk)} bytes — encrypt at rest with KMS envelope encryption')
"
```

Kubernetes integration:

```bash
# Store KMS key ID as a K8s secret (the actual key never leaves KMS)
kubectl create secret generic etp-operator-kms-key \
  --namespace=etp \
  --from-literal=key-id="$OPERATOR_KEY_ID"

# L2 verifier DK — encrypt with KMS, then store in K8s
aws kms encrypt --key-id alias/etp-data-key \
  --plaintext fileb://secrets/l2_verifier_dk.key \
  --output text --query CiphertextBlob | base64 --decode > secrets/l2_verifier_dk.enc

kubectl create secret generic etp-l2-verifier-dk \
  --namespace=etp --from-file=key=secrets/l2_verifier_dk.enc
```

### 5.2 Option B: Software Signing + KMS Envelope Encryption

For environments where you want to avoid direct KMS API calls on the signing hot path:

```bash
#!/bin/bash
# scripts/keygen-local.sh — Generate locally, protect at rest with KMS
set -euo pipefail

echo "Generating ETP operator keys..."

# Operator ML-DSA signing key (for STH signatures)
python3 -c "
from ltp.primitives import MLDSA
vk, sk = MLDSA.keygen()
open('secrets/operator_vk.key', 'wb').write(vk)
open('secrets/operator_sk.key', 'wb').write(sk)
print(f'Operator VK: {len(vk)} bytes')
print(f'Operator SK: {len(sk)} bytes')
"

# Encrypt SK at rest with KMS
aws kms encrypt --key-id alias/etp-data-key \
  --plaintext fileb://secrets/operator_sk.key \
  --output text --query CiphertextBlob | base64 --decode > secrets/operator_sk.enc
rm secrets/operator_sk.key  # plaintext removed

# L2 verifier ML-KEM keypair
python3 -c "
from ltp.primitives import MLKEM
ek, dk = MLKEM.keygen()
open('secrets/l2_verifier_ek.key', 'wb').write(ek)
open('secrets/l2_verifier_dk.key', 'wb').write(dk)
print(f'Verifier EK: {len(ek)} bytes')
print(f'Verifier DK: {len(dk)} bytes')
"

echo "Keys generated. SK encrypted at rest by KMS. Plaintext only in memory at runtime."
echo "NEVER commit secrets/ to version control."
```

Kubernetes integration:

```bash
# Create K8s secrets from KMS-encrypted files
kubectl create secret generic etp-operator-signing-key \
  --namespace=etp --from-file=key=secrets/operator_sk.enc

kubectl create secret generic etp-l2-verifier-dk \
  --namespace=etp --from-file=key=secrets/l2_verifier_dk.key
```

The signing service decrypts via KMS at startup, holds the key in memory, and signs
STHs locally. Harden the service: minimal container, no core dumps, encrypted swap,
strict IAM, restricted network.

---

## Stage 6: Monitoring Setup

### 6.1 Prometheus Config

```yaml
# deploy/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: etp-services
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names: [etp]
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        target_label: __address__
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: ${1}:${2}
```

### 6.2 Critical Alerts

```yaml
# deploy/alerts.yml
groups:
  - name: etp-critical
    rules:
      - alert: STHPublishingStalled
        expr: time() - etp_sth_last_published_timestamp > 120
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "STH not published for >2 minutes"

      - alert: ShardNodeDown
        expr: up{job="shard-node"} == 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Shard node {{ $labels.instance }} is down"

      - alert: AuditFailureRate
        expr: rate(etp_audit_failures_total[5m]) / rate(etp_audit_total[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Audit failure rate exceeds 5%"

      - alert: MaterializeErrorSpike
        expr: rate(etp_materialize_errors_total[5m]) > 0.1
        for: 3m
        labels:
          severity: warning
        annotations:
          summary: "Materialize error rate spiking"

      - alert: NonceReplay
        expr: increase(etp_nonce_replay_rejected_total[1m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Replay attack detected — nonce reuse rejected"
```

---

## Stage 7: Deployment Checklist

### Pre-Production

- [ ] Phase 1 crypto swap complete (liboqs ML-KEM/ML-DSA, PyNaCl AEAD, zfec, BLAKE3)
- [ ] All 821+ tests pass with production crypto
- [ ] RocksDB storage backend integrated and tested
- [ ] gRPC service interfaces defined (protobuf schema finalized)
- [ ] Operator ML-DSA signing key created in AWS KMS (or generated locally + KMS envelope encryption)
- [ ] L2 verifier ML-KEM keypair generated and DK encrypted at rest via KMS
- [ ] Docker images built and pushed to registry
- [ ] Kubernetes manifests reviewed and applied to staging

### Production Launch

- [ ] Deploy log-service (StatefulSet) — verify STH signing works
- [ ] Deploy shard-nodes (StatefulSet, 8 replicas across 3 zones)
- [ ] Deploy protocol-service — run end-to-end commit/lattice/materialize
- [ ] Deploy api-gateway (3 replicas) — verify REST endpoints
- [ ] Enable Prometheus scraping + Grafana dashboards
- [ ] Configure alerting (PagerDuty/Opsgenie integration)
- [ ] Deploy bridge-anchor, bridge-relayer, bridge-materializer
- [ ] Run full bridge end-to-end: lock on L1 → relay → materialize on L2
- [ ] Verify replay protection (duplicate nonce rejected)
- [ ] Verify shard repair (kill one node, confirm k-of-n reconstruction)
- [ ] Load test: 100 concurrent transfers, measure p50/p99 latency

### Post-Launch

- [ ] STH monitoring: verify monotonic sequence + signature validity
- [ ] Audit cycle: random shard challenges every 60s, <5% failure threshold
- [ ] Key rotation schedule: L2 verifier EK/DK rotated quarterly
- [ ] Incident runbook documented for each alert
- [ ] Backup strategy: RocksDB snapshots to object storage (S3/GCS) daily

---

## Environment Variables Reference

| Variable | Service | Description |
|----------|---------|-------------|
| `ETP_ENV` | All | `development`, `staging`, `production` |
| `ETP_LOG_SERVICE` | protocol, api, materializer | gRPC address of log service |
| `ETP_PROTOCOL_SERVICE` | api, anchor | gRPC address of protocol service |
| `ETP_SHARD_NODES` | protocol | Comma-separated shard node gRPC addresses |
| `ETP_SIGNING_KEY_PATH` | log | Path to operator ML-DSA signing key |
| `ETP_ROCKSDB_PATH` | log | Path to RocksDB data directory |
| `ETP_NODE_ID` | shard-node | Unique node identifier |
| `ETP_REGION` | shard-node | Geographic region for placement |
| `ETP_L1_RPC` | anchor | L1 chain RPC endpoint |
| `ETP_L2_VERIFIER_EK_PATH` | relayer | Path to L2 verifier encapsulation key |
| `ETP_L2_VERIFIER_DK_PATH` | materializer | Path to L2 verifier decapsulation key |
| `ETP_DEFAULT_N` | protocol | Total shards (default: 8) |
| `ETP_DEFAULT_K` | protocol | Reconstruction threshold (default: 4) |
| `ETP_AUDIT_INTERVAL_S` | shard-nodes | Seconds between audit challenges (default: 60) |
| `ETP_STH_PUBLISH_INTERVAL_S` | log | Seconds between STH publications (default: 30) |

---

## Estimated Infrastructure Costs (AWS, minimal production)

| Component | Instance/Service | Monthly Cost |
|-----------|-----------------|-------------|
| 3x API Gateway | t3.medium (EKS) | ~$100 |
| 1x Log Service | m6i.large + 50GB gp3 | ~$90 |
| 8x Shard Nodes | t3.medium + 100GB gp3 | ~$400 |
| 3x Bridge Services | t3.small | ~$45 |
| EKS Control Plane | Managed | ~$73 |
| ALB (Ingress) | Application LB | ~$25 |
| AWS KMS (operator key) | ML-DSA-65 key + signing ops | ~$1 |
| **Total** | | **~$734/mo** |

**Key management upgrade path:**

| Tier | Key Protection | Additional Cost | Total |
|------|---------------|----------------|-------|
| Default | AWS KMS ML-DSA-65 (GA, FIPS 140-3 L3 managed) | +$1/mo | ~$734/mo |
| Enhanced | CloudHSM 2-HSM HA (when ML-DSA goes GA) | +$2,100/mo | ~$2,833/mo |
| Enterprise | Thales Luna HSM (self-managed, ML-DSA production-ready now) | Varies | Varies |

See [Stage 5: Key Management](#stage-5-key-management) for the full comparison and phased approach.

---

## Scaling Guidance

| Dimension | Scaling Strategy |
|-----------|-----------------|
| Throughput (transfers/s) | Add API gateway + protocol-service replicas (stateless) |
| Storage (total entities) | Add shard nodes; increase RocksDB volume size |
| Availability | Spread shard nodes across more AZs; increase n (more shards) |
| Bridge throughput | Add relayer replicas (stateless sealed key transport) |
| Merkle tree size >1M entries | Evaluate Merkle Mountain Range (MMR) for storage efficiency |
| Multi-region | Deploy shard nodes in 3+ geographic regions; use consistent hashing for placement |
