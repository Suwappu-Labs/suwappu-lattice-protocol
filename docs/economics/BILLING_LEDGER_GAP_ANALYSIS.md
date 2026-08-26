# Billing Ledger — Gap Analysis Against Production Practice

> **Status:** assessment, not adopted mechanism. This document measures the
> shipped billing surface (`src/ltp/incentives.py`, `src/ltp/inference.py`,
> `src/ltp/bridge_deposits.py`) against how production financial systems
> actually build metered-usage ledgers, and states what is missing, in
> priority order. It is deliberately unflattering: every gap below was
> either reproduced against this code or is a documented property of it.

## 0. The one-sentence verdict

The shipped ledger is a **correct in-process accounting model with no
durability, no cross-process coordination, and no two-phase primitive** —
which means its solvency invariant is self-consistent within one running
process and blind to reality outside it.

Everything below is downstream of that sentence.

## 1. What was measured, not assumed

Three limits were reproduced locally against this code before writing this:

| Limit | How it was shown | Result |
|---|---|---|
| No persistence | Restart the service, replay the same on-chain deposit | Customer's spent balance **reappears**, the same tx **credits again**, and *both* ledgers still report `solvent=True` |
| Unbounded memory | Commit receipts in a loop, measure retained bytes | **3,951 B/receipt**, retained forever → ~3.4 GB/day at 10 req/s, ~341 GB/day at 1000 req/s |
| Concurrency (since fixed) | Two threads crediting and debiting one ledger | Drift −7,620 to +14,360 micro-USD, `solvent=False`; fixed by the `RLock` in §6 of `INFERENCE_REVENUE.md` |

The first result is the important one, and it is worth restating plainly:
**the solvency invariant passed while the ledger was wrong.** `held ==
deposited − withdrawn` is a statement about numbers the process is holding
in memory. It cannot detect that those numbers no longer describe the
world, because there is no second record to check them against.

## 2. The precedent that matters

Twilio's 2013 billing incident is the exact failure mode of an in-memory
balance store, and it is worth reading in full
([post-mortem](https://www.twilio.com/en-us/blog/company/communications/billing-incident-post-mortem-breakdown-analysis-and-root-cause-html)).
In-flight account balances lived in Redis. A network partition triggered a
mass slave resync; the master was restarted, read a wrong config, and
attempted recovery from a **non-existent AOF file instead of the binary
snapshot** — dropping all balance data. It then came up as a slave of
itself, therefore read-only, so balances read as zero, so the billing
system **auto-recharged customers' credit cards repeatedly**.

They recovered for exactly one reason: *"the billing system maintains
independent double-bookkeeping for all balance data in a separate
relational datastore."* The in-memory store was not the system of record.

Ours is. That is the gap, stated as an incident rather than an
abstraction.

## 3. Gaps, in priority order

### P0 — Durability: entries, not balances

**What we do:** mutable in-memory balances (`_customer_balances`,
`_pool_micro`, per-node accounts), mutated under a lock.

**What production does:** immutable append-only double-entry journals;
balances are *derived*, never stored as the authority. Modern Treasury
states the rule directly — *"it's more accurate to store immutable
transactions and always compute balances from those transactions.
Mutating balances directly creates a system that is prone to errors"*
([Accounting for Developers I](https://www.moderntreasury.com/journal/accounting-for-developers-part-i),
[II](https://www.moderntreasury.com/journal/accounting-for-developers-part-ii)).
The minimal schema is `accounts` / `transactions` / `entries`, with
`sum(debits) == sum(credits)` enforced **per transaction and per
currency** — netting $1 USD against 1 ETH sums to zero and creates value
from nothing
([Scale a Ledger V](https://www.moderntreasury.com/journal/how-to-scale-a-ledger-part-v)).

**Four distinct things a mutable balance costs us**, which are not the
same problem:

1. **Audit** — no answer to "why is this number what it is."
2. **Reconciliation** — you cannot diff a scalar against on-chain deposits
   or a provider invoice. You need postings that align line by line.
3. **Corrections** — a refund becomes `balance += x`, indistinguishable
   from a fraudulent credit. The correct handling is never an UPDATE:
   reverse the original with an opposite-signed transaction and post a
   corrected one
   ([Enforcing Immutability](https://www.moderntreasury.com/journal/enforcing-immutability-in-your-double-entry-ledger)).
4. **Partial failure** — a crash between debit and credit destroys money
   with no record it existed. With a journal, the pair either both exist
   or neither does.

Uber, Square, and Airbnb all retrofitted double-entry *after* incidents
involving missing funds. Retrofit is the expensive path; we are still
early enough to not take it.

**Cached balances are still fine — under two conditions** that we do not
currently meet: write the cache **in the same transaction** as the entry,
and run a **drift detector** that recomputes from entries and
automatically disables cache reads for any account that diverges
([Scale a Ledger VI](https://www.moderntreasury.com/journal/how-to-scale-a-ledger-part-vi)).
A cache with no divergence detector is a mutable balance column with
extra steps. Note also that the production shape is **four counters**
(`pending_debits`, `pending_credits`, `posted_debits`, `posted_credits`),
not one net figure — which leads directly to P1.

### P0 — Idempotency: a durable table, not an in-memory set

**What we do:** `DepositWatcher._credited_tx` (a `set` of tx hashes) and
`InferenceMarket`'s settled-`request_id` set. Both in memory, both lost on
restart.

**What production does:** Stripe's contract is public and precise
([idempotent requests](https://docs.stripe.com/api/idempotent_requests)):
the client supplies the key; Stripe **stores the resulting status code and
body of the first request — success or failure — and replays it**,
including 500s; **parameters are compared against the original and error
if they differ**; concurrent duplicates get **409**; keys are pruned after
~24h, so a retry at T+30h silently double-charges.

The reference implementation to actually copy is Brandur Leach's
[Implementing Stripe-like Idempotency Keys in Postgres](https://brandur.org/idempotency-keys):
a table unique on `(user_id, idempotency_key)` carrying `request_params`,
`response_code`, `response_body`, `locked_at`, and — the part we most
lack — a **`recovery_point`** column written inside the same transaction
as each atomic phase, so a retry resumes at the last completed checkpoint
instead of re-executing. Plus a **reaper** (delete old keys) and a
**completer** (push abandoned in-flight requests to completion). Airbnb
generalized the same discipline into a library, Orpheus, with one central
rule: [never hold a DB transaction open across an RPC call](https://medium.com/airbnb-engineering/avoiding-double-payments-in-a-distributed-payments-system-2981f6b070bb).

**Our set is not idempotency.** It is duplicate suppression, and it fails
in seven distinct ways: not durable (restart re-executes every in-flight
retry — worst precisely after a crash, when retries storm); not shared
(two replicas = two sets, so horizontal scaling silently disables it);
stores no result (a duplicate must return *the original response*, not
"seen"); has no lock, so two simultaneous same-id requests both check
before either inserts; does not compare parameters; has no documented
retention window; and has no recovery points, so it cannot represent
"foreign mutation done, local commit pending" — which is the failure that
actually costs money.

**Framing correction we should adopt in our own docs:** exactly-once
delivery does not exist. What is buildable is at-least-once delivery plus
idempotent processing, which means **the dedup state must be as durable
and as replicated as the money it protects.**

Note two different windows for two different problems: **~24h** is the
industry default for API-call idempotency; **~32 days** for usage-event
dedup (OpenMeter's default, keyed on `source` + `id` rather than `id`
alone; Stripe meter events use an `identifier` unique over a rolling ≥24h,
and **generate one for you if omitted — so a retry without it
double-counts**)
([OpenMeter](https://openmeter.io/blog/usage-deduplication),
[Stripe meter events](https://docs.stripe.com/api/billing/meter-event/create)).
Conflating the two is a bug.

### P1 — No pending/posted two-phase primitive

This single missing primitive causes three separate defects, which is why
it ranks above the individually larger ones below.

**The shape:** a transfer reserves against `pending`, leaving `posted`
untouched; it later posts (possibly for **less** than reserved, with the
remainder automatically returned), voids, or expires on a timeout.
TigerBeetle implements exactly this as
[two-phase transfers](https://docs.tigerbeetle.com/coding/two-phase-transfers/),
validated pessimistically: if there isn't enough balance to support
posting, **the pending transfer fails at reserve time, not at settle
time**, and re-resolution returns `pending_transfer_already_posted` /
`already_voided` / `expired`. Modern Treasury's three-balance model
(posted / pending / available = posted − pending holds) is the same idea.

What it buys us, in three places:

1. **LLM token holds.** "I reserved 4,000 output tokens, the model emitted
   900" is *precisely* partial posting.
2. **Optimistic deposit crediting.** Credit to *pending* at low
   confirmation depth (the user sees it, cannot spend it), post at
   finality.
3. **Any long-running operation.** Without a hold, every in-flight
   generation is a TOCTOU window measured in **seconds**, not
   microseconds.

**Our current exposure, concretely.** The gateway checks
`min_balance_to_serve_micro` as an admission floor, runs the backend, then
debits. That is the **post-facto** model. N concurrent requests each pass
the floor check before any of them has debited. With a hold you overdraw
by zero; post-facto you overdraw by up to N × max-response-cost. At N=50
and $0.50/response that is **$25 of free inference per exhaustion event,
per customer, repeatable**. The floor bounds one request's exposure; it
does not bound concurrency's.

### P1 — Billing must follow server-reported usage, not handler completion

The single most useful documented fact from this research, from Anthropic's
own billing page: *"If your client disconnects or times out in the middle
of a request that was on track to succeed, that request is still
charged"*, and *"failed requests aren't charged"*
([Claude API billing](https://support.claude.com/en/articles/8977456-how-do-i-pay-for-my-claude-api-usage)).

Any metering that decrements only when the handler runs to completion
**systematically under-bills every aborted stream** — and aborts correlate
with long, expensive generations, so the loss is biased toward the
expensive tail. Our debit is taken after `backend(...)` returns and after
`receipt_log.commit(...)`; a process death in that window is unbilled
compute with no durable record that it happened.

Worse for streaming, which we will want: OpenAI's usage counts arrive in a
**final** chunk (`stream_options: {"include_usage": true}`), so a
cancelled stream may deliver **no usage number at all**
([streaming responses](https://developers.openai.com/api/docs/guides/streaming-responses)).
The reconciliation path must handle "generation happened, token count
unknown" — settle the hold against our own count of emitted tokens, then
reconcile against the provider's figures later. That requires both a hold
and a durable per-request record. We have neither.

**On the unknown-output-length problem: there is no clean answer and the
industry has not converged.** The three options are (a) reserve
`max_tokens × output_price` and refund the difference — correct, but locks
up worst-case credit (often 10× actual) and fails outright when the caller
omits `max_tokens`; (b) reserve a static estimate — cheap, wrong in both
directions; (c) post-facto — bounded overrun per stream, unbounded under
concurrency. LiteLLM does (a) with (b) as fallback and rejects
budget-exceeding requests *before* they reach the provider
([budgets](https://docs.litellm.ai/docs/proxy/users)); the frontier
providers appear to do (c) plus an admission gate at zero. **We currently
do (c) with a floor.** The honest position is to say which we chose and
why, not to imply a best answer exists.

### P2 — Deposit crediting: wrong dedup key, wrong finality signal

Two specific, checkable defects in `bridge_deposits.py`:

1. **Dedup is keyed on `tx_hash` alone.** It must be
   **`(tx_hash, log_index)`** — one transaction can carry multiple
   transfers. There is a documented trap here: an ERC-20 `transfer()` can
   emit logs from *both* a system emitter and the token contract, so
   filtering to the system emitter is load-bearing or you credit the same
   deposit twice ([Arc deposits](https://docs.arc.io/integrate/exchanges/deposits)).
   Our `BridgeEmitterDepositSource` does filter by emitter address and
   topic0, which covers that case — but the key is still too coarse for
   multi-transfer transactions.
2. **Confirmations are computed as a block-count delta**
   (`latest − block_number + 1`) against a `min_confirmations` default of
   6. Trail of Bits is explicit that for delayed-finality chains
   ***"block delays are not an adequate way to 'wait' for blocks to become
   final"*** — you must query the chain: Ethereum
   `eth_getBlockByNumber("finalized", ...)` (>2/3 validators, ~2 epochs,
   12–13 min), Arbitrum/Optimism the same tag, Solana `finalized`
   commitment, StarkNet `ACCEPTED_ON_L1`
   ([Engineer's Guide to Blockchain Finality](https://blog.trailofbits.com/2023/08/23/the-engineers-guide-to-blockchain-finality/)).
   Ethereum's May 2023 finality incident is the case where block-delay
   logic failed and finality-tag logic did not.

Also worth internalizing: **there is no universal confirmation count, and
anyone quoting one is not thinking about it.** Kraken uses 4 for BTC,
Coinbase 3, Trail of Bits computes 2 for a $75k deposit — three risk
appetites, not a contradiction. The defensible design is **value-tiered**:
low depth for small deposits, finality for large ones. And for L2s, Circle
Gateway waits **~65 Ethereum L1 blocks**, not L2 blocks, because an L2's
own confirmation is a sequencer promise
([supported blockchains](https://developers.circle.com/gateway/references/supported-blockchains)).

**Reorgs are a state machine, not a set.** `detected → confirmed →
finalized → reversed`. A set of seen hashes cannot express "a hash I
correctly marked seen must now be un-seen, and the credit reversed" — and
the reversal must be a compensating entry, never a deletion, which is P0's
immutability discipline paying off directly.

One anti-pattern to avoid when we build reconciliation: **do not reconcile
`eth_getBalance` against Transfer events for the same address.** They are
the same underlying state, and decimal differences (6 vs 18) manufacture
phantom discrepancies. Reconcile the **event log against the ledger**.

### P2 — Attribution is destroyed by our own sweep

Fireblocks' guidance is the line that ties this back to P0: *maintain an
internal ledger independent of custodial balances, since swept funds
obscure actual per-user holdings*
([Manage Deposits at Scale](https://developers.fireblocks.com/docs/manage-deposits-at-scale)).
Once funds are swept to treasury, the chain no longer says who owns what —
**the ledger becomes the sole record of customer ownership**, and
attribution exists only in the window before the sweep. Our
`unattributed()` quarantine is the right instinct; it needs to be durable
for the same reason.

Chain model determines the pattern: UTXO chains get an address per
customer (and *mandatory* periodic consolidation — Fireblocks enforces a
250-input cap, past which you cannot spend your own balance); account
chains need a vault per user, and sweeping ERC-20s has a chicken-and-egg
gas problem (the depositor has no base asset — hence gas-station
pre-funding, a real per-deposit cost that can exceed small deposits);
memo/tag chains are cheapest but users mistype memos, which is the single
largest source of crypto deposit support tickets.

### P3 — Unbounded receipt-log memory

3,951 B/receipt retained forever. At 1000 req/s that is 341 GB/day. The
Merkle log needs a persistence tier and a retention policy (STHs pinned,
leaves archived) before any load that matters.

## 4. What we already got right

Stated for calibration, not comfort:

- **Serialized mutators with an atomic check-and-debit.** The `RLock` fix
  is the correct *shape* — it is exactly the `SELECT ... FOR UPDATE`
  discipline (check inside the critical section, never before it). It is
  correct for one process and worth nothing across two.
- **Solvency asserted, not assumed.** Having a continuously checkable
  global invariant at all is the right instinct; it is the same instinct
  as double-entry's "sum of credit-normal balances equals sum of
  debit-normal." We just need the second record that makes it meaningful.
- **Proof-gated payment and epoch settlement clamps.** Paying only from
  what is held, clamping to the pool, is the right conservatism.
- **Committed receipts.** Genuinely unoccupied ground — see §2.1 of
  `INFERENCE_REVENUE.md` for what that does and does not prove.
- **Deposit attribution refuses to guess.** Quarantining unattributed
  deposits rather than assigning them is correct and matches exchange
  practice.

## 4.5 What has since been built

`src/ltp/ledger_journal.py` implements items 1, 2 and part of 3 and 5
below. It is a durable double-entry journal on stdlib `sqlite3`:
`accounts` / `transactions` / `entries` with a per-transaction
debits==credits assertion, balances **derived** rather than stored,
corrections by reversal (never UPDATE or DELETE), a four-counter balance
cache written in the *same* SQL transaction as its entries, a
`detect_drift()` that recomputes from the journal and disables cache
reads on divergence, pending/posted entry states with an `available`
balance, a durable idempotency table (`(scope, key)` unique, parameter
hash, cached response including failures, `locked_at`, `recovery_point`,
reaper, and an `abandoned_keys()` feed for a completer), and
`(tx_hash, log_index)` uniqueness enforced by a database constraint on
the transaction itself.

The measured defect at the top of this document is fixed and pinned as a
regression test: after a restart the customer's spent balance stays
spent, and replaying the same on-chain deposit raises
`DuplicateExternalRef` instead of crediting again.

Two findings from building it, both caught by tests written to break the
code rather than confirm it:

- `check_solvency()` originally read through the balance cache, which
  meant it could not detect a tampered journal — the forged entry never
  touches the cached counters, so the check reported healthy while the
  entries said otherwise. It now audits `recompute_balance()` directly.
  An integrity check must not trust the thing it is auditing.
- `AccountBalance.available` had its sign inverted, so a hold *increased*
  the spendable balance. It was hidden by a test asserting `x or y`,
  which passes whichever way the sign goes. Both are now exact.

## 4.6 The journal, wired underneath the ledger

`src/ltp/ledger_durable.py` closes the swap §4.5 left open.
`DurableStablecoinLedger` is a drop-in subclass of `StablecoinLedger`:
same constructor keyword, same methods, same return types, so the
gateway, market, settlement engine and deposit watcher are unchanged.
Every movement is journaled as a balanced transaction *before* it
touches memory, and the in-memory figures are rebuilt from entries on
construction. The inversion is the point — **the dictionaries become a
cache and the journal becomes the ledger**, which is the same
relationship the journal already maintains between its `balance_cache`
and its `entries`, one level up.

The chart of accounts is one debit-normal `assets:custody` against
credit-normal claims (`pool:operator`, `pool:insurance`,
`pool:treasury`, `bond:<node_id>`, `customer:<customer_id>`), so
solvency is the ordinary balance-sheet identity. `check_solvency()`
keeps its old in-memory meaning for compatibility; the new
`audit_solvency()` answers the same question by replaying entries, and
only that one can see a forged movement. `detect_drift()` reconciles the
in-memory figures against the journal, because a cache nobody audits is
a mutable balance column with extra steps.

Three things the books deliberately do not hold. `earned_claim_micro`,
`audit_offense_count` and `evicted` are written directly onto the
account object by the settlement engine, and none is a claim on custody:
an accrued claim is money owed but *not yet funded*, so booking it as a
liability would report insolvency for every network that has ever
accrued. They are persisted as memos in the same database instead —
because losing them is not acceptable either. **A lost `evicted` flag
silently un-evicts a node that was expelled for cause**, which is a
security defect, not a bookkeeping one. Persisting them without touching
the engine needed a `__setattr__` interception on the account object;
overriding a ledger method would not have caught writes that never go
through one.

Measured, restart-to-restart:

| | in-memory ledger | wired journal |
|---|---|---|
| customer balance after spend + restart | resurrects | stays spent |
| replayed on-chain deposit | credited again | `DuplicateExternalRef` |
| accrued claim after mid-epoch restart | lost | still owed, settles |
| node evicted for cause, after restart | **un-evicted** | still evicted |
| forged journal entry | invisible | `audit_solvency()` is `False` |

The three guards that matter were checked by breaking them: disabling
memo write-through, pointing `audit_solvency()` at memory, and dropping
the reversal on a failed apply each fail the suite. A failed in-memory
apply reverses its journal transaction rather than deleting it, so the
attempt stays visible in history.

**Still open from the list below:** billing still follows handler
completion rather than server-reported usage; deposit confirmation depth
is still a block-count delta rather than the chain's `finalized` tag;
the receipt log is still unbounded in memory; and the two-phase
pending/posted primitive exists in the journal but nothing reserves
against it yet. SQLite's single-writer ceiling is the journal's own
limit — real, and the reason the schema is plain SQL that Postgres can
take over.

## 5. Recommended order of work

1. **Persist the ledger as entries** (`accounts` / `transactions` /
   `entries`), with cached balances written in the same transaction and a
   drift detector that disables the cache on divergence. Everything else
   is downstream.
2. **Durable idempotency table** unique on `(scope, key)`, storing request
   params and the cached response, with `locked_at`, `recovery_point`, a
   documented retention window, a reaper, and a completer — **written in
   the same transaction as the ledger entries it protects.** Separate
   `(source, id)` dedup for usage events with a ~32-day window.
3. **Two-phase pending/posted transfers.** One primitive, three uses (LLM
   holds, optimistic deposit credit, any long operation). Build it once.
4. **Bill from server-reported usage**, reserve on admission, post the
   actual, void on abort — and state explicitly which unknown-length
   strategy we chose.
5. **Deposit correctness:** `(tx_hash, log_index)` as a **uniqueness
   constraint on the ledger entry itself** (so double-crediting is
   impossible by construction, not by convention), the `finalized` tag
   instead of block-count delays, value-tiered depth, and an explicit
   reversal path for reorgs.

**On build-vs-buy:** Fly.io uses Metronome rather than building
([case study](https://metronome.com/blog/how-fly-io-solves-usage-based-billing-challenges-with-metronome)),
and **Stripe itself now steers new usage-based integrations to Metronome
rather than to its own Billing Meters**
([recording usage](https://docs.stripe.com/billing/subscriptions/usage-based/recording-usage)).
That is a strong signal about how hard high-volume metering ingest is. The
pattern for building it ourselves is Postgres for metadata plus either a
balance-assertion conditional write or TigerBeetle for the money — the
latter is explicitly designed to sit *alongside* a general-purpose DB, not
replace it
([system architecture](https://docs.tigerbeetle.com/coding/system-architecture/)),
gets strict serializability by executing transfers one at a time on a
single core, carries client-supplied `u128` transfer ids so **idempotency
is in the data model rather than bolted on**, and was independently
verified by [Jepsen](https://jepsen.io/analyses/tigerbeetle-0.16.11).

One number to design against either way: Modern Treasury publishes **~100
entries/second on an individual account** in balance-assertion-enforcing
mode, versus thousands/sec in async recording mode
([Scale a Ledger IV](https://www.moderntreasury.com/journal/how-to-scale-a-ledger-part-iv)).
**Per-account contention is the hard ceiling**, and knowing which mode
each account is in is a design decision, not an implementation detail.

## 6. Known gaps in this research

Stated so nobody over-reads it. Baseten, Anyscale, and Modal publish no
engineering detail on their metering ledgers — pricing pages only. Neither
OpenAI nor Anthropic documents whether an internal hold exists before
streaming; the observable contract is post-hoc deduction plus an admission
gate at zero. The reserve-then-reconcile pattern is documented only at the
gateway layer (LiteLLM), not by any frontier provider. And Lago's docs
give the honest number the marketing does not: their "ongoing balance"
refreshes **every 5 minutes**
([wallets](https://getlago.com/docs/guide/wallet-and-prepaid-credits/overview))
— assume any vendor's "real-time burndown" has lag of that order unless
they state a stronger guarantee, and size overdraft tolerance accordingly.
