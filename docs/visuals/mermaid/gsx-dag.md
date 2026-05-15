# GSX DAG — Mermaid

```mermaid
flowchart LR
  Users[Users / Apps] --> DAG[gsx-dag]
  DAG --> C[Consensus<br/>Mysticeti-C DAG]
  C --> E[Execution<br/>Dual VM]
  E --> DB[gsx-db<br/>Canonical state lattice]
  DB --> LTP[LTP<br/>Commit / Lattice / Materialize]
  LTP --> Corridors[(Base chains / corridors)]
  A[Authority Ring<br/>30–50 institutions] -->|proposes blocks| C
  V[Validator Ring<br/>100–500 stake-weighted participants] -->|votes / certifies| C
```
