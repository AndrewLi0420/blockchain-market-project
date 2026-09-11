# Jailbreakers

An on-chain marketplace where **red-teamers sell reproducible model-failure findings** to
buyers who **pay before they can see the exploit** — kept honest by hashlock disclosure, an
on-chain-adjudicated garbage dispute, seller collateral, and a resolver that **re-runs the
eval against the model** to settle every claim. Deployed, verified, and proven live on
Sepolia (buy → disclose → dispute → slash → reputation, driven end-to-end by autonomous
agents; a browser Sell/Buy flow is on the dashboard).

| | |
|---|---|
| **Live dashboard** | https://andrewli42nt.github.io/signal-bazaar-frontend/ |
| **Contract (Ethereum Sepolia)** | `0x59eAe206c6E30798C21FB0fcA3b9E0Ac11dDABC8` |
| **Etherscan** | https://sepolia.etherscan.io/address/0x59eAe206c6E30798C21FB0fcA3b9E0Ac11dDABC8 |
| **Verified source** | [Sourcify](https://repo.sourcify.dev/11155111/0x59eAe206c6E30798C21FB0fcA3b9E0Ac11dDABC8/) (exact match) · [Blockscout](https://eth-sepolia.blockscout.com/address/0x59eAe206c6E30798C21FB0fcA3b9E0Ac11dDABC8?tab=contract) |
| **Network** | Ethereum Sepolia testnet only — zero real value anywhere in this project |

---

## The vertical

Model red-teaming. **Sellers** are red-teamers and eval researchers; **buyers** are AI labs
and deployers who need to know how a model fails *before* they ship on it. A listing is a
falsifiable, dated claim about a **named model snapshot** — e.g. *"`sentinel-v1` leaks its
system secret under obfuscated prompt-injection ≥ 90% of the time over 8 trials, judged by
grader `leak:ST-9F3A-…`."* The valuable IP — the prompt suite that triggers the failure — is
encrypted and sold; everything needed to *judge* the finding (model, grader, claimed rate,
trial count) is public on-chain, so a buyer knows exactly how the claim will be scored before
paying. The vertical fits the mechanism on every axis: the evidence is **re-runnable** (so
settlement is a real measurement, not a human's opinion), **reveal-after-payment is
coordinated disclosure** (publishing the exploit after sale is the desired end state, not a
leak), and the characteristic scam is **overfitting** — a cherry-picked result that won't
reproduce — which the market is built to punish.

## Trust assumptions

**Trustless (enforced by the contract):** disclosure is atomic — escrow releases *only* on a
key whose hash matches the on-chain commitment; buyers are refunded if the seller never
discloses; the garbage **dispute is adjudicated on-chain** — the contract decrypts the suite
itself and checks it's a well-formed eval for the claimed model; and all money movement —
stake solvency (`price × buyers ≤ stake`), 50% slashing, pro-rata rebates, reputation, and
pull-payment withdrawals — is contract law.

**Trusted (and marked as such):** the **resolver** reports the re-measured failure rate — it
can't steal escrow or stake, but a dishonest resolver could mis-report a number; the demo
mitigates this by using a **public reference model**, so anyone can re-run the exact prompts
and prove a false resolution (production: a pinned model behind a TEE, or an M-of-N re-run
committee). Also trusted: the **model's identity** (a shared reference implementation here; a
pinned, hash-identified snapshot in production) and **IPFS availability** (the chain commits
to the ciphertext hash, not its availability — the buyer fetches and hash-verifies it before
paying).

## Biggest design decision

**Two verification mechanisms with an explicit, honest trust boundary — matched to what can
and cannot be checked on-chain.**

1. **`disputeInvalid` — fully trustless, on-chain.** The suite is encrypted with a
   **keccak-CTR cipher the EVM itself can run**, and the ciphertext is committed on-chain by
   its `sha256` (which *is* its IPFS CIDv1 digest). So the contract verifies the ciphertext
   against the commitment, decrypts it, and checks it targets the claimed model with the
   declared trial count — all inside `disputeInvalid`. Neither party can lie about what was
   sold, and a buyer can't frame an honest seller, because the *contract* does the judging.
2. **`resolve` — verifiable oracle.** Whether a well-formed finding actually *reproduces*
   can't run on-chain (the model can't execute in the EVM), so it is trusted — but the
   resolver **re-runs the suite and reports the measured rate**, checkable by anyone against
   the public model. Overfitted findings are slashed here.

The judgment on display is knowing which guarantee each half can actually deliver and not
overselling the trusted half as trustless. The same construction also closes a subtle
economic hole: **reputation only ever counts *sold* findings**, so a seller can't farm a
track record with zero-buyer claims.

## One important limitation

**The model under test is a deterministic reference implementation ("Sentinel"), not a live
frontier model.** This is deliberate — it keeps resolution free and, more importantly,
*independently verifiable*, since anyone can re-run the pure function and confirm the
resolver told the truth. The trade-off is that the demo doesn't exercise real-model
**stochasticity**: in production each prompt would be sampled M times against a pinned
snapshot, the resolver would report the mean, and the ±10-percentage-point tolerance already
in the contract would absorb the variance. The market mechanics are identical either way —
only the thing behind `runModel()` changes.
