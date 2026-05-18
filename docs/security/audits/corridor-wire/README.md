# Corridor wire format audits

Audits scoped to the `LTP-corridor-v1` wire format (envelope
serialization, BLS attestation framing, replay/version negotiation
rules — see [`docs/STABILITY_PROMISES.md`](../../../STABILITY_PROMISES.md)).

| Date | Vendor | Scope | Report |
|---|---|---|---|
| _none yet_ | | | |

## How to add an entry

1. Drop the report PDF / markdown into a subfolder named
   `<vendor>-YYYY-MM/` here.
2. Add a row to the table above with the date, vendor name, scope
   (which envelope fields / framing rules were in scope), and a
   link to the report file.
3. Open issues for each finding under the `LTP-A-NNN` audit-finding
   tracker (see [`docs/THREAT_MODEL.md`](../../../THREAT_MODEL.md)
   for the current open list).
4. Corridor wire changes are stability-breaking — if the audit
   recommends a wire change, file an ADR under
   [`docs/design-decisions/`](../../../design-decisions/) and link
   it from the audit row.
