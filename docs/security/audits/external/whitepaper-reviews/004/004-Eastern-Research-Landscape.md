# LTP Whitepaper/Codebase Expansion Roadmap — Eastern Research Landscape

## Context

Cross-referencing the LTP whitepaper and codebase against leading Eastern/Asian publications, research institutions, company engineering blogs, industry conferences, and regulatory bodies to identify where LTP can expand, differentiate, or needs to catch up. Companion to the Western Research Landscape analysis.

---

## 1. POST-QUANTUM CRYPTOGRAPHY — China's Independent Standards & Asia-Pacific Divergence

### Current State in LTP
- ML-KEM-768 / ML-DSA-65 simulated via BLAKE2b lookup tables (PoC only)
- Aligned with NIST FIPS 203/204/205 — no support for Chinese national crypto (SM series)
- No hybrid PQ/classical mode, no QKD integration layer

### Eastern Research & Industry

**China — Independent PQC Standardization (NGCC Program)**
China launched its Next-Generation Commercial Cryptographic Algorithms Program (NGCC) in Feb 2025, inviting global proposals. Unlike adoption of NIST selections, China is developing **independent PQ standards** under ICCS. Draft guidelines released; no final algorithm selection yet. Roadmap: PQC GB/T standards (KEM+signature) by 2026Q4, "state secret + PQC" hybrid suite for TLS/QUIC/IPsec/5G, target >=80% migration by 2029-2034.

China's current national crypto suite (SM2/SM3/SM4/SM9) is **quantum-vulnerable** — SM2 (ECC-based) and SM9 (pairing-based) fall to Shor's algorithm. A lattice-based replacement is anticipated but not yet standardized.

**XJTLU** broke its own world record solving the lattice SVP at 210 dimensions (Jan 2026), after solving Kyber-208 challenge (Nov 2025) — state-of-the-art lattice security analysis.

**China's QKD Leadership**: Beijing-Shanghai backbone (2,000+ km), Micius satellite (7,800 km QKD), Jinan-1 microsatellite (13,000 km). QuantumCTek builds national backbone. China at TRL 7 for space-based QKD — global leader.

**Japan — CRYPTREC Alignment + NTT Hybrid Deployments**
CRYPTREC endorses NIST PQC selections (ML-KEM, ML-DSA) while preserving local preferences (Camellia cipher). Japan's National Cyber Security Bureau mandates government PQC transition by **2035**. CRYPTREC recommends **hybrid PQ/T schemes** and crypto-agility.

NTT Communications (Jan 2025) deployed multi-PQC-algorithm secure key exchange in production, with crypto-suite switching without service interruption. KDDI + Toshiba multiplexed 33.4 Tbps with QKD over 80 km (March 2025). NICT demonstrated QKD integration with IOWN all-photonics network — QKD on existing telecom fiber.

**South Korea — KpqC Competition Winners**
KISA's Korean PQC Competition selected final winners (Jan 2025):
- **KEMs**: SMAUG-T, NTRU+
- **Signatures**: HAETAE, AIMer (Samsung SDS + KAIST — 6.35x faster, 2.9x smaller than alternatives)
- National Intelligence Service unveiled "Nationwide Migration to PQC" master plan

Samsung SDS's AIMer optimized for mobile/IoT devices — directly relevant to LTP's lightweight node scenarios.

**Singapore — NQSN+ National Quantum-Safe Network**
IMDA launched NQSN+ integrating both QKD and PQC. Singtel + SPTel deploying nationwide quantum-safe networks. ID Quantique + Singtel building first enterprise-grade nationwide QKD network. CQT (NUS) continues fundamental quantum crypto research.

### Expansion Opportunities

| # | Topic | Source | Priority |
|---|-------|--------|----------|
| E1a | **SM2/SM3/SM4/SM9 crypto provider** — China market access requires national crypto | [China NGCC](https://thequantuminsider.com/2025/02/18/china-launches-its-own-quantum-resistant-encryption-standard-bypassing-us-efforts/) | **HIGH** |
| E1b | **Dual-standard PQ support** — NIST ML-KEM + future Chinese PQ KEM | [Akamai PQC Guide](https://www.akamai.com/blog/security/guide-international-post-quantum-cryptography-standards) | **HIGH** |
| E1c | **KpqC algorithm support** (SMAUG-T, AIMer) — Korean market differentiation | [Samsung SDS AIMer](https://www.samsungsds.com/us/news/1287864_5933.html), [KpqC Competition](https://pqc.metamui.id/algorithms/kpqc/) | MEDIUM |
| E1d | **QKD integration layer** — hybrid QKD+PQC for institutional deployments | [NICT IOWN QKD](https://www.nict.go.jp/en/press/2025/09/16-1.html), China backbone | MEDIUM |
| E1e | **Crypto-agility for multi-jurisdiction** — pluggable national crypto suites | [CRYPTREC guidelines](https://www.cryptrec.go.jp/en/tech_guidelines.html), [Japan PQC 2035](https://pqshield.com/2035-japans-nco-sets-the-timeline-for-quantum-security/) | **HIGH** |

---

## 2. ERASURE CODING — Chinese Hyperscaler Innovations

### Current State in LTP
- Reed-Solomon GF(2^8) Vandermonde evaluation — fully working
- Fixed k-of-n MDS, O(k) repair bandwidth per failed node
- No repair optimization, no network coding, no stripeless designs

### Eastern Research & Industry

**Alibaba Cloud — Production Erasure Coding Research**
Active deployment and research across multiple fronts:
- **NCBlob (USENIX FAST'25)**: Network-coding-based warm blob storage with non-systematic MSR codes. Reduces single-block repair time by **45%**, full-node repair by **38.4%**, with only 2.1% read throughput loss. Deployed on Alibaba Cloud.
- **ELECT (USENIX FAST'24)**: Erasure coding tiering for LSM-tree storage (extends Cassandra). **56.1% edge storage savings** with similar performance.
- **HBRepair**: Recovery scheduling reducing repair time by **11.6-26.7%** vs RepairBoost/CMRepair.
- **AZ-Code (MSST'19)**: Availability zone-level erasure code for cross-AZ fault tolerance.

**Nostor (USENIX OSDI'25)**: Stripeless erasure coding for in-memory KV stores. **1.61-2.60x throughput** improvement over stripe-based baselines. Novel Nos coding scheme eliminates stripe alignment constraints.

**Frontiers of Computer Science (2026)**: Chinese journal publishing cutting-edge erasure coding for distributed storage, addressing RS repair bandwidth problem.

**Huawei**: Active in erasure coding for OceanStor and FusionStorage products, though specifics are less public than Alibaba's academic publications.

### Expansion Opportunities

| # | Topic | Source | Priority |
|---|-------|--------|----------|
| E2a | **Network-coded repair** (MSR codes) — 45% repair time reduction | [NCBlob FAST'25](https://www.usenix.org/system/files/fast25-gan.pdf) | **HIGH** |
| E2b | **Stripeless erasure coding** — eliminate stripe alignment overhead | [Nostor OSDI'25](https://www.usenix.org/system/files/osdi25-gao.pdf) | MEDIUM |
| E2c | **Erasure coding tiering** — hot/warm/cold data tiers with EC | [ELECT FAST'24](https://www.usenix.org/system/files/fast24-ren.pdf) | MEDIUM |
| E2d | **Cross-AZ erasure codes** — availability zone fault tolerance | AZ-Code (Alibaba MSST'19) | LOW |

---

## 3. ZERO-KNOWLEDGE PROOFS — Asian-Founded ZK Infrastructure

### Current State in LTP
- Simulated Groth16 (192B) and STARK (~45KB) — no real implementations
- No zkEVM integration, no cross-chain ZK verification
- Open Question 8a: circuit composition model undefined

### Eastern Research & Industry

**Scroll (China-founded, zkEVM)**
Type-1 zkEVM with full Ethereum equivalence. Released Scroll SDK for deploying sovereign zkEVM chains. Three-tier proving pipeline: chunk proofs, batch proofs, bundle proofs. Reached ~$1B TVL before airdrop. Strong EVM compatibility focus.

**Polyhedra Network (China-founded, Expander proof system)**
- **Expander (2025)**: 3,000 TPS verification, proving costs under $0.50, 15-second finality
- **zkBridge**: ZK-SNARK-based cross-chain verification across 25+ chains, 12M+ transactions processed
- Partnered with Google Cloud, $75M raised at $1B valuation
- **2026 roadmap**: EXPchain mainnet (zkML, verifiable AI), Bitcoin Layer 2 ZK verification
- Integrated with LayerZero as decentralized verifier network (DVN)

**Broader Asian ZK Landscape**
- Polygon sunsetting zkEVM Mainnet Beta (2026) — market consolidating
- Ethereum Fusaka upgrade (Dec 2025) enhancing ZK rollup performance
- Academic survey (arXiv 2510.05376) systematically analyzed 5 production zkEVMs (Polygon, zkSync, Scroll, Linea, Taiko)

### Expansion Opportunities

| # | Topic | Source | Priority |
|---|-------|--------|----------|
| E3a | **Cross-chain ZK verification** (Polyhedra/Expander model) | [Polyhedra 2026](https://blog.polyhedra.network/polyhedra-moving-into-2026/) | **HIGH** |
| E3b | **zkML / Verifiable AI** — emerging application for storage proofs | Polyhedra EXPchain roadmap | MEDIUM |
| E3c | **ZK proving pipeline architecture** (chunk/batch/bundle) | [Scroll SDK](https://scroll.io/blog/zkevm) | MEDIUM |
| E3d | **ZK-based Bitcoin L2 verification** — LTP bridge to Bitcoin | Polyhedra Bitcoin ZK verification | LOW |

---

## 4. CONSENSUS & ARCHITECTURE — Chinese L1 Innovations

### Current State in LTP
- Three-phase commitment: COMMIT/LATTICE/MATERIALIZE
- No DAG-based consensus, no UTXO model, no tree-graph parallelism

### Eastern Research & Industry

**Conflux (Tsinghua-incubated, Shanghai government-backed)**
- Tree-Graph consensus: combines DAG parallelism with PoW security
- Pivot blocks form main chain; non-pivot blocks process in parallel
- Current: ~3,000 TPS. **Conflux 3.0** targeting **15,000 TPS** with sub-second confirmations
- Only compliant public blockchain in China. Partnered with AnchorX for digital-yuan derivative (AxCNH) for Belt & Road cross-border settlement
- Shanghai Science and Technology Committee incubation (2019)

**Nervos CKB (UTXO + Cell Model)**
- "Bitcoin-isomorphic" design: PoW + generalized UTXO (Cell model)
- **RGB++ protocol**: Binds Bitcoin UTXOs to CKB UTXOs for programmability
- CKB Lightning Network for L2 scaling
- By March 2025: 581 tokens supported, one token (Seal) with 42,000+ holders
- Token transfers: minimal overhead, collateral costs under $0.75/UTXO

**Academic Validation**: Formal security proofs for UTXO binding published, implemented on CKB with on-chain Bitcoin light client verification.

### Expansion Opportunities

| # | Topic | Source | Priority |
|---|-------|--------|----------|
| E4a | **DAG-parallel block processing** — Conflux tree-graph model for throughput | [Conflux USENIX ATC'20](https://people.iiis.tsinghua.edu.cn/~weixu/Krvdro9c/li-atc20.pdf) | MEDIUM |
| E4b | **Generalized UTXO (Cell model)** — deterministic state management | [Nervos CKB](https://www.nervos.org/) | LOW |
| E4c | **Cross-chain UTXO binding** — Bitcoin programmability via auxiliary chain | Nervos RGB++ | LOW |

---

## 5. STORAGE NETWORKS — Asian Decentralized Storage Ecosystem

### Current State in LTP
- PDP (Proof of Data Possession) with aggregate tags
- Burst challenges for anti-outsourcing
- No TEE-based storage proofs, no cross-chain storage verification

### Eastern Research & Industry

**Crust Network (China-origin, Polkadot ecosystem)**
- GPoS (Guaranteed Proof of Stake): staking power tied to storage proofs — no storage = reduced staking
- **MPoW (Meaningful Proof of Work)**: TEE-backed storage attestation via sWorker processes
- Cross-chain storage across Ethereum, Polkadot, BSC, and more
- Won Polkadot parachain slot (lease to May 2026)
- Partnerships: NodeShift (AI cloud), TON (CrustBags marketplace), TAN L1

**Key Innovation**: Crust's GPoS aligns economic incentives with actual storage — relevant to LTP's slashing model where storage obligations could modulate stake weight.

**Filecoin Asia Operations**: Significant Asian miner base (especially China pre-ban, now distributed). Filecoin's PDP for hot storage and NI-PoRep advances covered in Western analysis but Asian operators drive much of the network's storage capacity.

### Expansion Opportunities

| # | Topic | Source | Priority |
|---|-------|--------|----------|
| E5a | **TEE-attested storage proofs** (Crust MPoW model) | [Crust Network](https://crust.network/) | MEDIUM |
| E5b | **Storage-weighted staking** — GPoS-style stake modulation | Crust GPoS design | MEDIUM |
| E5c | **Cross-chain storage verification** | Crust cross-chain solution | LOW |

---

## 6. FORMAL VERIFICATION — Asian Research Groups

### Current State in LTP
- `EnforcementInvariants` with runtime safety/liveness checks
- Comments mention Spin/Promela, Lean 4, Hypothesis — none implemented
- No TLA+ specs, no model checking, no fuzzing framework

### Eastern Research & Industry

**Tsinghua University — Blockchain Fuzzing & Chaos Engineering**
- **Fuchen Ma** (Shuimu Scholar, Tsinghua): Framework deploying "inside agents" for node-level disruption testing. **50+ vulnerabilities** found in Go-Ethereum, Hyperledger Fabric, FISCO BCOS, Diem. 14 CVEs assigned. Published at CCS, NDSS, USENIX Security, S&P.
- **SmartUpdater (IEEE TSE 2025)**: Optimization-oriented contract generation + publicly verifiable state migration for smart contracts.
- **Yuanjie Li** (Associate Professor, Tsinghua): Bridging networking and security with formal verification and distributed computing.

**Automated Reasoning in Blockchain (arXiv 2025)**: Comprehensive survey of automated reasoning techniques applied to blockchain systems, covering model checking, theorem proving, and runtime verification.

**Stanford Security Seminar (2025-2026)**: Fuchen Ma invited to present blockchain resilience testing, bridging Tsinghua research to Western academia.

### Expansion Opportunities

| # | Topic | Source | Priority |
|---|-------|--------|----------|
| E6a | **Chaos engineering / fuzzing framework** for LTP nodes | [Fuchen Ma, Tsinghua](https://fcorleone.github.io/), CCS/NDSS papers | **HIGH** |
| E6b | **Automated reasoning for protocol verification** | [arXiv 2503.20461](https://arxiv.org/pdf/2503.20461) | MEDIUM |
| E6c | **Smart contract state migration verification** | SmartUpdater IEEE TSE 2025 | LOW |

---

## 7. ACADEMIC CONFERENCES — Key Eastern Venues & Papers

### Asiacrypt 2024 (Kolkata, India)
- 127 papers from 433 submissions
- **"Dense and Smooth Lattices in Any Genus"** (van Woerden) — Lattice Isomorphism Problem for PQ hardness assumptions
- Lattice-based PAKE protocols leveraging Kyber KEM
- Post-quantum key exchange advances

### Asiacrypt 2025 (Melbourne, Australia)
- 143 papers from 533 submissions
- **Privacy-preserving lattice-based protocols** with efficient NIZK for advanced lattice crypto
- **Cryptanalysis of QA-SD / F4OLEage** — broke parameters proposed at Crypto'23/Asiacrypt'24
- **Tanuki**: Post-quantum blind signatures from cryptographic group actions (CSIDH, LESS)
- Proceedings: Springer LNCS volumes 16245-16252

### Key Research Groups
- **Tsinghua**: 186 blockchain papers (2018-2021), CS department ranked #1 globally (US News)
- **KAIST**: AIMer signature (KpqC winner), blockchain systems research
- **NTT Research**: NTRU Prime co-creators, PQC deployment in production
- **Alibaba DAMO Academy**: Distributed storage, erasure coding, cloud infrastructure
- **XJTLU**: Lattice SVP record-breaking (210 dimensions)

### Expansion Opportunities

| # | Topic | Source | Priority |
|---|-------|--------|----------|
| E7a | **Lattice Isomorphism Problem** as alternative PQ hardness assumption | [Asiacrypt 2024](https://asiacrypt.iacr.org/2024/program.php) | LOW |
| E7b | **Privacy-preserving lattice NIZK** for advanced protocols | [Asiacrypt 2025](https://asiacrypt.iacr.org/2025/acceptedpapers.php) | MEDIUM |
| E7c | **PQ blind signatures** (Tanuki) for privacy features | Asiacrypt 2025 | LOW |

---

## 8. REGULATORY FRAMEWORKS — Multi-Jurisdiction Eastern Compliance

### Current State in LTP
- `compliance.py` covers FIPS/RBAC/GDPR/geo-fence/HSM/SIEM/key rotation
- Western-focused: no SM crypto suite, no Asian regulator compliance
- No whitepaper section on Eastern regulatory alignment

### Eastern Regulatory Landscape

**China**
- **BSN (Blockchain-based Service Network)**: State-backed infrastructure, nodes in 20+ countries, root key held by government. BSN China uses domestic cloud (China Mobile, China Telecom, Baidu AI Cloud). RealDID (decentralized identity) deployed on BSN.
- **Commercial Cryptography Law**: Mandates SM2/SM3/SM4 for commercial systems. Any protocol operating in China must support national crypto.
- **e-CNY (Digital Yuan)**: Production CBDC with programmable payment capabilities. Separate from private crypto — mining/trading banned.
- **MIIT National Blockchain Standard (2023)**: Guiding industry development. Full-stack alternative to Western blockchain infrastructure.

**Japan**
- **FSA**: Comprehensive crypto exchange licensing since 2017. JVCEA self-regulatory body.
- **Stablecoin framework**: Permissible stablecoin issuers defined (banks, trust companies, fund transfer providers). Global exchanges partnering with licensed Japanese entities.
- **Bank of Japan**: CBDC pilot Phase 2 (retail digital yen testing with commercial banks).
- **CRYPTREC**: PQC transition by 2035, hybrid PQ/T recommended.

**South Korea**
- **Digital Asset Basic Act (DABA)**: Passed June 2025, replacing "virtual assets" with "digital assets." Comprehensive rulebook for issuance, trading, consumer protection.
- Delayed by stablecoin issuance dispute (Bank of Korea vs FSC). Full implementation expected 2026.
- Korean individuals hold ~KRW 104 trillion ($80B) in digital assets (~5% GDP).
- **KISA**: Mandatory ISMS certification for exchanges.

**Singapore**
- **MAS Project Guardian**: International tokenization initiative, 40+ financial institutions. Published operational framework for tokenized funds.
- **2026 CBDC pilot**: Tokenized government bills settled via wholesale CBDC. Successful 2025 trial with DBS, JPMorgan, Standard Chartered.
- **BLOOM Initiative**: Tokenized bank liabilities and regulated stablecoins.
- **Stablecoin regulation**: Draft legislation being finalized.
- Partners: ISDA, Ant International, BNY, HSBC, OCBC for cross-border FX settlement.

**Hong Kong**
- **SFC ASPIRe Roadmap**: Comprehensive VA licensing for dealing, advisory, management, custody. Bill targeting 2026 Legislative Council.
- **HKMA Project Ensemble**: Tokenized deposit settlement via HKD RTGS. EnsembleTX operating throughout 2026.
- SFC expanding VATP product offerings and enabling global affiliate liquidity sharing.
- No transitional period for new licensing regime.

**India**
- **RBI Digital Rupee (e-Rupee)**: 17 banks, 6M+ users, INR 1,016 crore ($120M) in circulation (March 2025). Deposit tokenization pilot (Oct 2025).
- **COINS Act 2025**: Proposed comprehensive framework. 30% flat tax on crypto profits, 1% TDS.
- **SEBI**: Proposed multi-regulator framework. Currently no crypto exposure permitted for SEBI-regulated entities.
- AML: Major exchanges registered with FIU-IND. VDAs under PMLA since March 2023.

**UAE**
- **VARA (Dubai)**: Custody Services Rulebook (March 2025) — 95% cold storage minimum, mandatory third-party audits. Travel Rule fully implemented (Feb 2026). Fines totaling AED 7.5M for marketing violations.
- **ADGM (Abu Dhabi)**: First global jurisdiction with comprehensive VA regulation (2018). DeFi protocol operators brought under scope (Sept 2025). Staking regulatory framework published. 40+ licensed crypto entities.
- **Federal**: Cabinet Resolution 111/2025 expanded VA definition to include tokenized securities and RWA tokens.
- $30B+ crypto inflows in 12 months. 1 in 4 adults hold digital assets. FATF grey list removal (Feb 2024).

### Expansion Opportunities

| # | Topic | Source | Priority |
|---|-------|--------|----------|
| E8a | **Chinese national crypto suite** (SM2/SM3/SM4) in compliance.py | [China Commercial Crypto Law](https://www.csis.org/blogs/strategic-technologies-blog/chinas-blockchain-playbook-infrastructure-influence-and-new) | **CRITICAL** |
| E8b | **MAS/SFC compliance module** — Singapore+HK tokenization standards | [MAS Project Guardian](https://www.mas.gov.sg/schemes-and-initiatives/project-guardian), [SFC ASPIRe](https://www.sfc.hk/en/News-and-announcements/Policy-statements-and-announcements/A-S-P-I-Re-for-a-brighter-future-SFCs-regulatory-roadmap-for-Hong-Kongs-virtual-asset-market) | **HIGH** |
| E8c | **VARA/ADGM custody compliance** — 95% cold storage, audit requirements | [VARA Custody Rulebook](https://www.getdefy.co/en/resources/blog/uae-crypto-compliance), [ADGM FSRA](https://www.adgm.com/media/announcements/adgm-fsra-presents-key-enhancements-to-its-digital-assets-framework-at-abu-dhabi-finance-week-2025) | **HIGH** |
| E8d | **Multi-jurisdiction compliance matrix** — whitepaper section | All above sources | **HIGH** |
| E8e | **BSN interoperability consideration** — China market infrastructure | [CSIS BSN Analysis](https://www.csis.org/blogs/strategic-technologies-blog/chinas-blockchain-playbook-infrastructure-influence-and-new) | MEDIUM |
| E8f | **CBDC settlement integration** — e-CNY, digital yen, e-Rupee | [RBI CBDC](https://www.thenewsminute.com/partner/blockchain-adoption-accelerates-in-indias-banking-sector-as-rbi-pilots-digital-rupee), [MAS CBDC pilot](https://www.tradingview.com/news/coinpedia:09e438f01094b:0-singapore-s-mas-unveils-2026-tokenized-cbdc-pilot-tightens-stablecoin-rules/) | MEDIUM |

---

## 9. QKD/PQC CONVERGENCE — Unique Eastern Opportunity

### Current State in LTP
- PQC only (simulated), no QKD integration
- No hybrid QKD+PQC architecture

### Eastern Research & Industry

Asia leads globally in QKD deployment. The convergence of QKD and PQC is a uniquely Eastern strength:

**China**: World's largest QKD backbone + satellite network. QuantumCTek production infrastructure.

**Japan**: NTT crypto-agile transport (Jan 2025) — switches cryptographic suites without interruption. KDDI+Toshiba 33.4 Tbps QKD multiplexing (March 2025). NICT proved QKD works on existing telecom fiber via IOWN.

**Singapore**: NQSN+ integrating QKD+PQC nationwide. Singtel + ID Quantique enterprise deployment.

**South Korea**: SK Telecom QKD network deployment. Samsung quantum-safe mobile devices research.

**Key Insight**: While the West focuses on PQC migration (Cloudflare, Chrome, OpenSSL), Asia is building **QKD+PQC hybrid** infrastructure. This dual-layer approach provides defense-in-depth: PQC protects against Harvest-Now-Decrypt-Later, QKD provides information-theoretic security for the highest-value links.

### Expansion Opportunities

| # | Topic | Source | Priority |
|---|-------|--------|----------|
| E9a | **QKD key integration API** — consume QKD-derived keys for shard encryption | [NICT IOWN](https://www.nict.go.jp/en/press/2025/09/16-1.html) | MEDIUM |
| E9b | **Crypto-agile transport** — runtime algorithm switching (NTT model) | NTT Communications Jan 2025 | **HIGH** |
| E9c | **Hybrid QKD+PQC key hierarchy** — QKD for master keys, PQC for session keys | Singapore NQSN+ | MEDIUM |

---

## 10. CROSS-BORDER INFRASTRUCTURE — Belt & Road Digital Corridors

### Current State in LTP
- `federation.py` stubs — no cross-network capability
- No cross-border settlement or multi-jurisdiction transfer

### Eastern Research & Industry

**Conflux AxCNH**: Digital-yuan derivative for Belt & Road cross-border trade settlement, operating within AIFC (Astana) framework. First compliant public blockchain enabling China-Central Asia digital trade corridors.

**MAS Project Guardian FX**: ISDA + Ant International developed tokenized bank liabilities for cross-border FX settlement. Contributors include BNY, HSBC, OCBC, GFMA.

**HKMA Project Ensemble**: Interbank settlement of tokenized deposits, initially via HKD RTGS. SFC + HKMA co-led tokenized money market fund simulation.

**Deutsche Bundesbank + MAS**: Cross-border digital asset settlement agreement building on Project Guardian. 40+ financial institutions involved.

### Expansion Opportunities

| # | Topic | Source | Priority |
|---|-------|--------|----------|
| E10a | **Cross-border settlement protocol** — multi-CBDC interoperability | [MAS Guardian FX](https://www.isda.org/2025/07/03/isda-and-ant-international-lead-new-industry-report-on-use-of-tokenized-bank-liabilities-for-fx-settlement-and-cross-border-payments-under-project-guardian/) | MEDIUM |
| E10b | **Tokenized deposit interoperability** — HKMA Ensemble model | [HKMA Ensemble](https://www.hkma.gov.hk/eng/news-and-media/press-releases/2025/11/20251113-3/) | MEDIUM |
| E10c | **Federation for regulated corridors** — LTP cross-deployment for institutional transfer | Conflux AxCNH, MAS Guardian | MEDIUM |

---

## PRIORITY MATRIX — Eastern Research Landscape

### Tier 1 — Critical (address for Asia-Pacific market access)
1. **E8a** Chinese national crypto suite (SM2/SM3/SM4) — legal requirement for China operations
2. **E1a** SM crypto provider in LTP — Commercial Cryptography Law compliance
3. **E1b** Dual-standard PQ support (NIST + future Chinese PQ KEM) — avoid vendor lock-in
4. **E1e** Crypto-agility for multi-jurisdiction — Japan/Korea/China each have distinct requirements
5. **E8b** MAS/SFC compliance module — Singapore+HK tokenization standards
6. **E8c** VARA/ADGM custody compliance — UAE is fastest-growing crypto market
7. **E8d** Multi-jurisdiction compliance matrix — whitepaper needs Eastern regulatory section
8. **E2a** Network-coded repair (NCBlob/MSR) — Alibaba-proven 45% repair improvement
9. **E3a** Cross-chain ZK verification — Polyhedra model for multi-chain LTP
10. **E6a** Chaos engineering/fuzzing — Tsinghua's 50+ bugs in major blockchains
11. **E9b** Crypto-agile transport — NTT's runtime algorithm switching

### Tier 2 — Important Enhancements
- **E1c** KpqC algorithms (SMAUG-T, AIMer) — Korean market
- **E1d** QKD integration layer — institutional deployments
- **E2b** Stripeless erasure coding (Nostor) — throughput improvement
- **E2c** Erasure coding tiering — storage cost optimization
- **E3b** zkML / Verifiable AI — emerging application
- **E3c** ZK proving pipeline architecture — Scroll model
- **E5a/E5b** TEE storage proofs, storage-weighted staking — Crust innovations
- **E7b** Privacy-preserving lattice NIZK — advanced protocols
- **E8e** BSN interoperability — China infrastructure
- **E8f** CBDC settlement integration — multi-country
- **E9a/E9c** QKD key integration, hybrid key hierarchy
- **E10a/E10b/E10c** Cross-border settlement protocols

### Tier 3 — Future Research
- **E2d** Cross-AZ erasure codes
- **E3d** ZK-based Bitcoin L2 verification
- **E4a** DAG-parallel block processing (Conflux model)
- **E4b/E4c** Generalized UTXO, cross-chain UTXO binding
- **E5c** Cross-chain storage verification
- **E6b/E6c** Automated reasoning, smart contract migration verification
- **E7a/E7c** Lattice Isomorphism Problem, PQ blind signatures

---

## CROSS-REFERENCE: Eastern vs Western Priority Overlap

Several Eastern findings **reinforce** Western priorities:

| Western Priority | Eastern Reinforcement |
|---|---|
| **1a** Hybrid PQ/Classical | Japan CRYPTREC mandates hybrid PQ/T; NTT deployed in production |
| **1d** Crypto-agility | Each Asian jurisdiction has different crypto requirements — agility is essential |
| **2a** Locally Repairable Codes | Alibaba NCBlob (MSR codes) provides complementary repair optimization |
| **4a** Circle STARKs | Polyhedra Expander provides alternative high-performance proving |
| **6a** Data Availability Sampling | Conflux data availability research (IACR 2025/569) |
| **9a** TLA+ formal verification | Tsinghua fuzzing framework complements static verification |
| **11a** Regulatory whitepaper | Eastern regulatory landscape is even more fragmented — urgent need |

**Unique Eastern priorities not in Western analysis:**
- SM crypto suite for China market (E8a/E1a) — no Western equivalent
- KpqC algorithms for Korea (E1c) — domestic standard
- QKD integration (E1d/E9a-c) — Asia leads globally in QKD deployment
- BSN interoperability (E8e) — China's state blockchain infrastructure
- CBDC settlement (E8f) — 4+ Asian CBDCs in production/pilot
- Storage-weighted staking (E5b) — Crust's novel GPoS mechanism

---

## COMBINED EXPANSION OPPORTUNITY COUNT

| Category | Western | Eastern | Total Unique |
|---|---|---|---|
| Post-Quantum Crypto | 5 | 5 | 10 |
| Erasure Coding | 4 | 4 | 8 |
| VDFs | 3 | 0 | 3 |
| Zero-Knowledge Proofs | 4 | 4 | 8 |
| Consensus/Architecture | 0 | 3 | 3 |
| Storage Proofs | 3 | 3 | 6 |
| Data Availability | 3 | 0 | 3 |
| MEV Protection | 2 | 0 | 2 |
| Slashing/Economics | 3 | 0 | 3 |
| Formal Verification | 3 | 3 | 6 |
| Academic/Conferences | 0 | 3 | 3 |
| Regulation | 4 | 6 | 10 |
| Merkle Log | 3 | 0 | 3 |
| QKD/PQC Convergence | 0 | 3 | 3 |
| Cross-Border Infrastructure | 0 | 3 | 3 |
| Federation | 2 | 0 | 2 |
| **TOTAL** | **39** | **37** | **76** |
