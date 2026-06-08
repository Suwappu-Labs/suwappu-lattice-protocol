# P6 — Front-end / integration audit

Target: `/Users/toma/gsx/suwappu-bridge` (Next.js 16 / React 19 / wagmi 2 / viem 2 / RainbowKit).

## Headline: the UI is 100% mock and must not be presented as a working bridge

`components/bridge/Bridge.tsx` `runBridge()` (lines 683-692) only advances animation
state with `setTimeout` and sets `phase='done'`. **There is no `writeContract` /
`sendTransaction` anywhere in the app** — connecting a wallet and "bridging" moves zero
funds. The cryptographic artifacts shown to the user are **hardcoded constants**
(`Bridge.tsx:666-668`):
```
const commitId    = '0x3f4ab2c1...'
const zkProofHash = '0xd4e5f6a7...'
const mldsaSig    = '0x9f8e7d6c...'
```
`hooks/useBridge.ts` is pure local React state; no chain interaction.

**Risk:** shipped to a bridge-looking domain, a user can connect a wallet, "bridge," and
receive a fabricated commit-id + ZK-proof + ML-DSA signature + a "success" receipt while
nothing happened. Operationally indistinguishable from a phishing/scam UI. **Gate
condition: the front end must either be clearly labelled a demo/simulation, or wired to the
real contracts — and must NEVER display fabricated proof hashes as genuine.**

## Other findings

| # | Severity | Finding | Location |
|---|---|---|---|
| FE1 | Critical (product) | Mock UI presents fake proofs/receipts as real (above) | `Bridge.tsx:666-692`, `useBridge.ts` |
| FE2 | Low | Placeholder WalletConnect `projectId: 'YOUR_WALLETCONNECT_PROJECT_ID'` ships a dead credential slot; breaks WalletConnect | `lib/wagmi.ts` |
| FE3 | Low | Hardcoded public RPC endpoints (`eth.llamarpc.com`, etc.) — an untrusted RPC can lie to the UI about balances/tx status | `lib/chains.ts` |
| FE4 | Info | Caret-ranged deps (`^`) pull unpinned transitive versions | `package.json` |

## Confirmed clean (good)
- **No web-injection surface:** no `dangerouslySetInnerHTML`, `eval`, or `innerHTML`; the
  only external links (`TransferStatus.tsx`) use `target="_blank" rel="noopener noreferrer"`.
- No secrets committed in the client bundle (the placeholder projectId is a non-secret).

## Integration security requirements (for the REAL front end)
When the mock is replaced with on-chain calls, require:
1. **Simulate-before-send** (`simulateContract`) and show the user the exact decoded
   action (amount, token, destination chain, recipient) that they are signing.
2. **chainId / domain checks** — refuse to build a tx for the wrong chain; bind the
   displayed destination to the actual call args.
3. **Approval hygiene** — exact-amount ERC-20 approvals, never unbounded; show the spender.
4. **No fabricated proofs** — display only artifacts returned by the chain/relayer, never
   placeholders.
5. **Trusted RPC** — use authenticated/own RPC endpoints, not arbitrary public ones, for
   balance/status the user relies on.
