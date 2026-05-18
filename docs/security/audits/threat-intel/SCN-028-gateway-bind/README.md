# SCN-028 — Gateway 0.0.0.0 default exposure

**Status.** VERIFIED-GREEN. Gateway defaults to loopback; public bind is opt-in.
**Layer.** 7 — Off-chain infrastructure.
**Historical pattern.** Many crypto / DeFi services have shipped
with internal APIs bound to 0.0.0.0 by default, exposing them
to the public Internet.
**LTP-A-* link.** [LTP-A-011](../../internal/SECURITY_AUDIT_2026-05-15.md)
(closed by previous audit work; SCN-028 is the regression test).

## What happens in this class

A service binds to `0.0.0.0` (all interfaces) by default. The
operator typically expects "but it's behind our firewall." In
practice:

1. Misconfigured cloud security groups expose the service.
2. Ingress rules drift over time as the team grows.
3. The dev/staging environment has the same default and IS
   exposed.
4. A leaked SSRF anywhere in the network lets an attacker reach
   the "internal" service.

The defense is **fail-safe defaults**: bind to loopback
(`127.0.0.1`) by default; require an explicit opt-in to bind
publicly. The opt-in forces the operator to make a conscious
decision and (ideally) pair it with authentication and rate-
limit middleware.

## LTP analogue

LTP's gateway VM in `src/ltp/gateway_vm/__main__.py:206-207`:

```python
host = os.environ.get("ETP_GATEWAY_HOST", "127.0.0.1")
port = int(os.environ.get("ETP_GATEWAY_PORT", "8000"))
```

The defaults pin to loopback. The opt-in path is explicit
(`ETP_GATEWAY_HOST=0.0.0.0` or `ETP_GATEWAY_HOST=10.0.0.5`).
LTP-A-011 was closed by this exact change.

| ID | Defense | Source |
|----|---------|--------|
| GW1 | Default `host` is `127.0.0.1` (loopback) | `__main__.py:206` |
| GW2 | Explicit env-var opt-in for `0.0.0.0` or any other interface | `__main__.py:206` |
| GW3 | Default port is 8000 (documented) | `__main__.py:207` |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| pytest | `tests/security/historical/test_scn_028_gateway_bind.py` | GW1×2 (default loopback + explicit anti-0.0.0.0), GW2×2 (explicit 0.0.0.0 + specific-interface opt-in), GW3×2 (port override + default 8000) |

## How to run

```bash
pip install -e '.[dev]'
pytest tests/security/historical/test_scn_028_gateway_bind.py -v
```

## Cross-references

- **SCN-029** (gRPC resource-exhaustion) — sibling
  infrastructure-tier defense
- **LTP-A-011** — closed by previous audit; SCN-028 is the
  regression
- **OPERATOR_RUNBOOK §11** (monitoring) — would alert on
  unexpected public-bind configuration in production

## Findings opened

None. Defense pre-exists (LTP-A-011 already closed). Regression
test pins the post-fix behavior.
