/**
 * Resolver agent — the verifiable oracle. For each disclosed finding past its
 * resolution time, it FETCHES the ciphertext from IPFS, DECRYPTS the suite with
 * the on-chain-revealed key, RE-RUNS every prompt against the named model, applies
 * the public grader, and reports the actually-measured failure rate on-chain.
 * This is a real measurement, not a synthetic number.
 *
 * Trust boundary (see README): the resolver is trusted to run the model honestly.
 * Because the demo model is a public reference implementation, anyone can re-run
 * these exact prompts and confirm the resolver reported the truth — a dishonest
 * resolution is publicly detectable. In production this step would be a pinned
 * model behind a TEE, or an M-of-N committee that re-runs and attests.
 */
import { formatEther } from "viem";
import {
  makeWallet, getListing, readContract, send, findEvent, decodeSuite, fetchCiphertext,
  keccakCtr, sha256Of, sleep, envInt, now, chainNow, errMsg, log, txLink, Category, CONTRACT,
} from "./lib";
import { measureSuite, knownModel } from "./model";

const TAG = "resolver";
const w = makeWallet("DEPLOYER_PRIVATE_KEY");
const MAX_RUNTIME = envInt("RESOLVER_MAX_RUNTIME", 1500);
const POLL = 10000;

/** Fetch → integrity-check → decrypt → decode → re-run the suite. Returns measured bps. */
async function remeasure(l: any): Promise<{ bps: number; detail: string }> {
  if (!knownModel(l.modelId)) return { bps: 0, detail: `unknown model "${l.modelId}" — measured 0%` };
  const ct = await fetchCiphertext(l.suiteCID);
  if (!ct) return { bps: 0, detail: `suite ${l.suiteCID} unavailable — measured 0%` };
  if (sha256Of(ct) !== l.suiteHash) return { bps: 0, detail: "suite failed sha256 commitment — measured 0%" };
  let suite;
  try {
    suite = decodeSuite(keccakCtr(ct, l.revealedKey));
  } catch (e) {
    return { bps: 0, detail: `suite not decodable (${errMsg(e)}) — measured 0%` };
  }
  const r = measureSuite(l.modelId, suite.prompts, l.graderSpec);
  return { bps: r.rateBps, detail: `re-ran ${r.total} prompts vs ${l.modelId}: ${r.failures} triggered ${Category[l.category]} = ${r.rateBps / 100}%` };
}

async function main() {
  log(TAG, `resolver ${w.account.address} | contract ${CONTRACT}`);
  const disputeWindow = Number(await readContract("disputeWindow"));
  const done = new Set<string>();
  const startedAt = now();

  const endBy = now() + MAX_RUNTIME;
  while (now() < endBy) {
    let n = 0n, ts = 0n;
    try { n = await readContract("nextListingId"); ts = await chainNow(); }
    catch (e) { log(TAG, `rpc: ${errMsg(e)} — will retry`); await sleep(POLL); continue; }

    let pending = 0;
    for (let id = 0n; id < n; id++) {
      if (done.has(id.toString())) continue;
      try {
        const l = await getListing(id);
        if (l.status >= 2) { done.add(id.toString()); continue; } // Invalid/Resolved/Expired/Cancelled
        pending++;
        if (ts < l.resolutionTimestamp) continue;

        if (l.status === 0 /* never disclosed */) {
          const { hash } = await send(w, "resolve", [id, 0n]);
          log(TAG, `#${id}: resolution passed with no disclosure — marked Expired (buyers refundable). tx ${txLink(hash)}`);
          done.add(id.toString());
          continue;
        }
        if (ts <= BigInt(Number(l.revealedAt) + disputeWindow)) continue; // wait out the dispute window

        const { bps, detail } = await remeasure(l);
        const { hash, receipt } = await send(w, "resolve", [id, BigInt(bps)]);
        // read the outcome from the emitted event, not a re-read (avoids RPC read-after-write races)
        const ev = findEvent(receipt, "ListingResolved");
        const reproduced = ev ? ev.reproduced : bps + 1000 >= Number(l.claimedFailRateBps);
        const payout = ev ? ev.payoutPerBuyer : 0n;
        log(TAG, `#${id}: "${l.claimSummary}" — ${detail}; claimed ${Number(l.claimedFailRateBps) / 100}% -> ${reproduced ? "REPRODUCED" : "FAILED TO REPRODUCE"}${payout > 0n ? ` (stake slashed: ${formatEther(payout)} ETH/buyer rebate)` : ""}. tx ${txLink(hash)}`);
        done.add(id.toString());
      } catch (e) {
        log(TAG, `#${id}: ${errMsg(e)} — will retry next poll`);
      }
    }
    if (n > 0n && pending === 0 && now() > startedAt + envInt("RESOLVER_GRACE", 300)) {
      log(TAG, "all listings settled — exiting");
      break;
    }
    await sleep(POLL);
  }
  log(TAG, "done");
}

main().catch((e) => { console.error(e); process.exit(1); });
