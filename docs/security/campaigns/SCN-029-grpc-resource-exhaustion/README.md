# SCN-029 — gRPC resource exhaustion

**Status.** VERIFIED-GREEN. gRPC server caps message size + concurrent streams + thread pool.
**Layer.** 7 — Off-chain infrastructure.
**Historical pattern.** Default-unlimited gRPC configurations
have repeatedly enabled single-client OOM / DoS attacks across
the broader gRPC ecosystem.
**LTP-A-* link.** [LTP-A-019](../../../SECURITY_AUDIT_2026-05-15.md)
(closed by previous audit work; SCN-029 is the regression test).

## What happens in this class

A gRPC server with no explicit limits accepts:

- Messages of any size (up to gRPC's protocol max ~2 GiB).
  A malicious client can send a 1 GiB message and force the
  server to allocate and decode it — OOM kill.
- Unlimited concurrent streams per connection. A single client
  can open thousands of streams and exhaust the server's
  worker pool, freezing legitimate traffic.
- Unlimited concurrent requests via the underlying executor.
  Threads or asyncio tasks pile up indefinitely.

The defense is **explicit, low caps on every relevant resource
limit** — message size, stream count, executor size.

## LTP analogue

LTP's gRPC server in `src/ltp/network/server.py:106-129`:

```python
def __init__(self, ..., max_workers: int = 10, ...):
    ...
    grpc.server(
        futures.ThreadPoolExecutor(max_workers=max_workers),
        options=[
            ("grpc.max_receive_message_length", 4 * 1024 * 1024),
            ("grpc.max_send_message_length",    4 * 1024 * 1024),
            ("grpc.max_concurrent_streams",     100),
        ],
    )
```

| ID | Defense | Source |
|----|---------|--------|
| GR1 | `max_receive_message_length` capped at 4 MiB | `server.py:121` |
| GR2 | `max_send_message_length` capped at 4 MiB | `server.py:122` |
| GR3 | `max_concurrent_streams` capped at 100 | `server.py:123` |
| GR4 | Thread pool capped at 10 workers by default | `server.py:106` |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| pytest (static inspection) | `tests/security/historical/test_scn_029_grpc_limits.py` | GR1, GR2, GR1+GR2 cap value, GR3 present, GR3 value, GR4 default, plus defense-in-depth check that the options are actually passed to `grpc.server()` |

The tests use `inspect.getsource()` rather than spinning up a
real gRPC server in CI (which would require port management +
async event loop). The text-search approach catches any drift
where the options are deleted, the cap value is changed, or the
options stop being passed to `grpc.server()`.

## How to run

```bash
pip install -e '.[dev]'
pytest tests/security/historical/test_scn_029_grpc_limits.py -v
```

## Cross-references

- **SCN-028** (Gateway bind) — sibling infrastructure-tier
  defense
- **LTP-A-019** — closed by previous audit; SCN-029 is the
  regression test
- **OPERATOR_RUNBOOK §11** (monitoring) — alerts on resource-
  saturation events in production

## Findings opened

None. Defense pre-exists (LTP-A-019 closed). Regression test
pins the post-fix configuration.
