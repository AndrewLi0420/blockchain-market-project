/**
 * Buyer agent (an AI lab / downstream deployer): polls open findings, applies a
 * mechanical trust rule (reputation + price + data-availability), buys the finding
 * sight-unseen, waits for disclosure, then:
 *   - decrypts and schema-validates the suite; disputes on-chain if it's garbage;
 *   - INDEPENDENTLY RE-RUNS the suite against the model to confirm the failure
 *     actually reproduces — this is the buyer extracting real value (now it knows
 *     a concrete way its model fails, and can patch/avoid before shipping);
 *   - claims a rebate if resolution later slashes an overfitted finding.
 *
 * Ownership is derived from on-chain `purchases`, never local JSON, so a dropped
 * RPC receipt can't make the agent lose track of a finding it already paid for.
 */
import { parseEther, formatEther, bytesToHex, type Address } from "viem";
import {
  makeWallet, getListing, getReputation, readContract, send,
  keccakCtr, validateSuite, sha256Of, fetchCiphertext,
  sleep, envInt, now, errMsg, log, txLink, loadState, saveState, Category, CONTRACT,
} from "./lib";
import { measureSuite, knownModel } from "./model";

const TAG = "buyer";
const w = makeWallet("BUYER_PRIVATE_KEY");

const PRICE_CEILING = parseEther(process.env.BUYER_PRICE_CEILING ?? "0.001");
const MIN_RESOLVED = envInt("BUYER_MIN_RESOLVED", 3); // reputation gate engages after this many sold+resolved
const MIN_REPRO_RATE = Number(process.env.BUYER_MIN_REPRO_RATE ?? "0.6");
const MAX_CIPHERTEXT_BYTES = 16384; // anti gas-grief: dispute posts the suite as calldata
const MAX_RUNTIME = envInt("BUYER_MAX_RUNTIME", 1200);
const POLL = 5000;

type Owned = { ct: string };
const state = loadState<{ evaluated: Record<string, string>; owned: Record<string, Owned>; announced: string[] }>(
  "buyer.state.json",
  { evaluated: {}, owned: {}, announced: [] },
);
state.announced ??= [];
const persist = () => saveState("buyer.state.json", state);
const announceOnce = (k: string) => {
  if (state.announced.includes(k)) return false;
  state.announced.push(k); persist(); return true;
};

async function myPurchase(id: bigint): Promise<{ owned: boolean; refunded: boolean; payoutClaimed: boolean }> {
  const [purchasedAt, refunded, payoutClaimed] = await readContract("purchases", [id, w.account.address]);
  return { owned: Number(purchasedAt) !== 0, refunded, payoutClaimed };
}

/** The trust rule a buyer applies before paying for a finding sight-unseen. */
async function evaluate(l: any): Promise<{ buy: boolean; reason: string; ct?: Uint8Array }> {
  if (l.price > PRICE_CEILING)
    return { buy: false, reason: `price ${formatEther(l.price)} > ceiling ${formatEther(PRICE_CEILING)}` };
  if (!knownModel(l.modelId))
    return { buy: false, reason: `unknown model "${l.modelId}" — cannot independently verify` };

  const rep = await getReputation(l.seller as Address);
  if (Number(rep.disputed) > 0)
    return { buy: false, reason: `seller has ${rep.disputed} finding(s) proven to be garbage — blacklisted` };

  const resolved = Number(rep.soldResolved);
  if (resolved >= MIN_RESOLVED) {
    const rate = Number(rep.reproduced) / resolved;
    if (rate < MIN_REPRO_RATE)
      return { buy: false, reason: `seller reproduction rate ${(rate * 100).toFixed(0)}% < ${MIN_REPRO_RATE * 100}% over ${resolved} sold` };
  } else if (l.stake < 2n * l.price) {
    return { buy: false, reason: `unproven seller (${resolved} sold) and stake ${formatEther(l.stake)} < 2x price` };
  }

  // pay only for data that is available, integrity-checked, and cheap to dispute
  const ct = await fetchCiphertext(l.suiteCID);
  if (!ct) return { buy: false, reason: `encrypted suite ${l.suiteCID} not fetchable — refusing to pay for unavailable data` };
  if (ct.length > MAX_CIPHERTEXT_BYTES) return { buy: false, reason: `suite ${ct.length}B exceeds ${MAX_CIPHERTEXT_BYTES}B dispute-gas cap` };
  if (sha256Of(ct) !== l.suiteHash) return { buy: false, reason: "fetched suite does not match on-chain sha256 commitment" };

  const repDesc = resolved >= MIN_RESOLVED
    ? `reproduction rate ${((Number(rep.reproduced) / resolved) * 100).toFixed(0)}% over ${resolved} sold`
    : `unproven but collateralized (stake ${formatEther(l.stake)} >= 2x price)`;
  return { buy: true, reason: `${repDesc}; price OK; suite available & committed`, ct };
}

async function handleOwned(id: bigint, l: any, p: { refunded: boolean; payoutClaimed: boolean }) {
  if (p.refunded || p.payoutClaimed) return;

  if (l.status === 1 /* Revealed */) {
    const ct = await suiteFor(id, l);
    if (!ct) { log(TAG, `#${id}: suite unavailable — cannot validate yet`); return; }
    const check = validateSuite(keccakCtr(ct, l.revealedKey), {
      modelId: l.modelId, category: l.category, trials: l.trials,
    });
    if (!check.valid) {
      log(TAG, `#${id}: disclosed — suite INVALID (${check.reason}). Disputing on-chain with the suite as evidence…`);
      const d = await send(w, "disputeInvalid", [id, bytesToHex(ct)]);
      log(TAG, `#${id}: dispute accepted — the contract itself decrypted the suite and rejected it. tx ${txLink(d.hash)}`);
      const c = await send(w, "claimPayout", [id]);
      log(TAG, `#${id}: refund of ${formatEther(l.price)} ETH claimed from seller stake. tx ${txLink(c.hash)}`);
      return;
    }
    // valid finding: extract value by independently reproducing it against the model
    if (announceOnce(`repro:${id}`)) {
      const s = check.suite!;
      const measured = measureSuite(s.modelId, s.prompts, l.graderSpec);
      log(TAG, `#${id}: disclosed — well-formed ${Category[s.category]} suite (${s.prompts.length} prompts) vs ${s.modelId}.`);
      log(TAG, `#${id}: independently reproduced: ${measured.failures}/${measured.total} prompts trigger the failure = ${measured.rateBps / 100}% (claimed ${Number(l.claimedFailRateBps) / 100}%).`);
      log(TAG, `#${id}: actionable — this is a concrete way ${s.modelId} fails; we can patch/guard before shipping.`);
      if (measured.rateBps + 1000 < Number(l.claimedFailRateBps))
        log(TAG, `#${id}: NOTE reproduction is well below the claim — expecting resolution to slash and rebate us.`);
    }
    return;
  }

  if (l.status === 2 /* Invalid (someone else disputed) */) {
    const c = await send(w, "claimPayout", [id]);
    log(TAG, `#${id}: finding proven invalid by another buyer — claimed refund. tx ${txLink(c.hash)}`);
    return;
  }

  if (l.status === 3 /* Resolved */) {
    if (announceOnce(`resolved:${id}`))
      log(TAG, `#${id}: resolved — ${l.reproduced ? "REPRODUCED" : "FAILED TO REPRODUCE"} (measured ${Number(l.measuredFailRateBps) / 100}% vs claimed ${Number(l.claimedFailRateBps) / 100}%)`);
    if (!l.reproduced && l.payoutPerBuyer > 0n) {
      const c = await send(w, "claimPayout", [id]);
      log(TAG, `#${id}: overfitted finding slashed — rebate of ${formatEther(l.payoutPerBuyer)} ETH claimed. tx ${txLink(c.hash)}`);
    }
    return;
  }

  // seller silent: refund once the deadline lapses
  const revealWindow = Number(await readContract("revealWindow"));
  const [purchasedAt] = await readContract("purchases", [id, w.account.address]);
  const refundable =
    (l.status === 0 && (now() > Number(purchasedAt) + revealWindow || BigInt(now()) >= l.resolutionTimestamp)) ||
    l.status === 4;
  if (refundable) {
    log(TAG, `#${id}: seller never disclosed — claiming refund`);
    const r = await send(w, "refund", [id]);
    log(TAG, `#${id}: refunded ${formatEther(l.price)} ETH. tx ${txLink(r.hash)}`);
  }
}

async function suiteFor(id: bigint, l: any): Promise<Uint8Array | null> {
  const cached = state.owned[id.toString()]?.ct;
  if (cached) return Uint8Array.from(Buffer.from(cached, "hex"));
  const ct = await fetchCiphertext(l.suiteCID);
  if (!ct || sha256Of(ct) !== l.suiteHash) return null;
  state.owned[id.toString()] = { ct: Buffer.from(ct).toString("hex") };
  persist();
  return ct;
}

async function processListing(id: bigint) {
  const l = await getListing(id);
  const p = await myPurchase(id);
  if (p.owned) { await handleOwned(id, l, p); return; }
  if (state.evaluated[id.toString()]) return;
  if (l.seller.toLowerCase() === w.account.address.toLowerCase()) return;
  if (l.status !== 0 || BigInt(now()) >= l.resolutionTimestamp) return;

  log(TAG, `#${id}: evaluating "${l.claimSummary}" (${l.modelId}, ${Category[l.category]}, ${formatEther(l.price)} ETH, seller ${l.seller.slice(0, 8)}…)`);
  const v = await evaluate(l);
  if (!v.buy) { state.evaluated[id.toString()] = v.reason; log(TAG, `#${id}: SKIP — ${v.reason}`); persist(); return; }
  log(TAG, `#${id}: BUY — ${v.reason}`);
  state.owned[id.toString()] = { ct: Buffer.from(v.ct!).toString("hex") }; // cache before paying
  persist();
  const b = await send(w, "buy", [id], l.price);
  log(TAG, `#${id}: paid ${formatEther(l.price)} ETH into escrow sight-unseen. tx ${txLink(b.hash)}`);
}

async function unfinished(id: bigint): Promise<boolean> {
  const l = await getListing(id);
  const p = await myPurchase(id);
  if (p.owned && !p.refunded && !p.payoutClaimed) {
    if (l.status === 0 || l.status === 1 || l.status === 4) return true;
    if (l.payoutPerBuyer > 0n) return true;
    return false;
  }
  if (p.owned) return false;
  return l.status === 0 && BigInt(now()) < l.resolutionTimestamp && !state.evaluated[id.toString()];
}

async function main() {
  log(TAG, `buyer ${w.account.address} | contract ${CONTRACT}`);
  log(TAG, `rule: price <= ${formatEther(PRICE_CEILING)} ETH; reproduction rate >= ${MIN_REPRO_RATE * 100}% after ${MIN_RESOLVED} sold (collateral rule before that); blacklist sellers with any disputed finding`);

  const startedAt = now();
  const endBy = now() + MAX_RUNTIME;
  while (now() < endBy) {
    let n = 0n;
    try { n = await readContract("nextListingId"); }
    catch (e) { log(TAG, `rpc: ${errMsg(e)} — will retry`); await sleep(POLL); continue; }

    for (let id = 0n; id < n; id++) {
      try { await processListing(id); }
      catch (e) { log(TAG, `#${id}: ${errMsg(e)} — will retry next poll`); }
    }

    try {
      const bal: bigint = await readContract("balances", [w.account.address]);
      if (bal > 0n) {
        const wd = await send(w, "withdraw", []);
        log(TAG, `withdrew ${formatEther(bal)} ETH of refunds/rebates. tx ${txLink(wd.hash)}`);
      }
      if (n > 0n && now() > startedAt + envInt("BUYER_GRACE", 300)) {
        let work = 0;
        for (let id = 0n; id < n; id++) if (await unfinished(id)) work++;
        if (work === 0) { log(TAG, "no open positions and nothing left to buy — exiting"); break; }
      }
    } catch (e) {
      log(TAG, `housekeeping: ${errMsg(e)} — will retry next poll`);
    }
    await sleep(POLL);
  }
  log(TAG, "done");
}

main().catch((e) => { console.error(e); process.exit(1); });
