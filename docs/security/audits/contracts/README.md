# Contracts audits

Audits scoped to the Solidity registry (`contracts/`).

| Date | Vendor | Scope | Report |
|---|---|---|---|
| _none yet_ | | | |

## How to add an entry

1. Drop the report PDF / markdown into a subfolder named
   `<vendor>-YYYY-MM/` here.
2. Add a row to the table above with the date, vendor name, scope
   (which contracts / interfaces were in scope), and a link to the
   report file.
3. Open issues for each finding under the `LTP-A-NNN` audit-finding
   tracker (see [`docs/THREAT_MODEL.md`](../../../THREAT_MODEL.md)
   for the current open list).
4. `make contracts-secaudit` must remain green for the
   `contracts/` tree at the time the report lands — record the
   commit SHA in the audit subfolder's own README.
