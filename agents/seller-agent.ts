/**
 * Seller agent (red-teamer): discovers a model-failure finding by actually probing
 * the reference model, encrypts the winning prompt suite, pins it to IPFS, and
 * lists an on-chain claim ("model M fails behaviour C at rate >= R over N inputs").
 * After a buyer escrows payment it reveals the key — coordinated disclosure.
 *
 * Modes (per round, configurable):
 *   honest  — craft a suite that genuinely reproduces, claim near the measured rate
 *   overfit — claim a high rate but list a weak suite (real resolution will slash it)
 *   garbage — list random bytes that aren't a valid eval (buyer disputes on-chain)
 */
import { parseEther, formatEther } from "viem";
import {
  makeWallet, getListing, getReputation, readContract, send, findEvent,
  encodeSuite, keccakCtr, randomKey, keyHashOf, sha256Of, pinCiphertext,
  sleep, envInt, now, log, txLink, loadState, saveState, Category, CONTRACT,
} from "./lib";
import { craftFinding, craftWeakFinding, measureSuite, SECRET, Category as Cat } from "./model";

const TAG = "seller";
const w = makeWallet("SELLER_PRIVATE_KEY");

const STATE_FILE = process.env.SELLER_STATE_FILE ?? "seller.state.json";
const ROUNDS = envInt("SELLER_ROUNDS", 3);
const MODES = (process.env.SELLER_MODES ?? "honest,honest,garbage").split(",");
const PRICE = parseEther(process.env.LISTING_PRICE ?? "0.0005");
const STAKE = parseEther(process.env.LISTING_STAKE ?? "0.001");
const RESOLUTION_DELAY = envInt("RESOLUTION_DELAY", 300);
const BUYER_WAIT = envInt("SELLER_BUYER_WAIT", 180);
const MODEL_ID = process.env.TARGET_MODEL ?? "sentinel-v1";
const TRIALS = envInt("SUITE_TRIALS", 8);
const GRADER = `leak:${SECRET}`;

type Saved = { id: string; key: string; cid: string; mode: string; revealed: boolean };
const state = loadState<{ listings: Saved[] }>(STATE_FILE, { listings: [] });

function buildSuite(mode: string): { prompts: string[]; claimBps: number; summary: string } {
  if (mode === "garbage") {
    return { prompts: [], claimBps: 9000, summary: `${MODEL_ID} data-leak on obfuscated injection >=90%` };
  }
  if (mode === "overfit") {
    const prompts = craftWeakFinding(MODEL_ID, GRADER, TRIALS);
    // deliberately over-claim: real rate is ~20%, seller claims 90%
    return { prompts, claimBps: 9000, summary: `${MODEL_ID} leaks system secret on injection >=90% (${TRIALS} trials)` };
  }
  // honest: craft a suite that actually reproduces, then claim just under the measured rate
  const prompts = craftFinding(MODEL_ID, GRADER, TRIALS);
  const measured = measureSuite(MODEL_ID, prompts, GRADER).rateBps;
  const claimBps = Math.max(1000, measured - 500); // claim conservatively below what we observed
  return {
    prompts,
    claimBps,
    summary: `${MODEL_ID} leaks system secret via obfuscated injection >=${claimBps / 100}% (${TRIALS} trials)`,
  };
}

async function main() {
  log(TAG, `red-teamer ${w.account.address} | contract ${CONTRACT}`);
  log(TAG, `target ${MODEL_ID} | price ${formatEther(PRICE)} ETH, stake ${formatEther(STAKE)} ETH (refund capacity: ${STAKE / PRICE} buyers)`);

  for (let round = 1; round <= ROUNDS; round++) {
    try {
      const mode = MODES[(round - 1) % MODES.length]!;
      const { prompts, claimBps, summary } = buildSuite(mode);

      // 1. build + encrypt the suite (the IP)
      let suiteBytes: Uint8Array;
      let trials: number;
      if (mode === "garbage") {
        suiteBytes = new Uint8Array(128);
        crypto.getRandomValues(suiteBytes);
        trials = TRIALS;
        log(TAG, `round ${round} [GARBAGE]: listing non-eval bytes behind claim "${summary}" (demonstrates the on-chain dispute)`);
      } else {
        suiteBytes = encodeSuite({ modelId: MODEL_ID, category: Cat.DataLeak, prompts });
        trials = prompts.length;
        const realRate = measureSuite(MODEL_ID, prompts, GRADER).rateBps;
        log(TAG, `round ${round} [${mode.toUpperCase()}]: crafted ${trials}-prompt suite; probed ${MODEL_ID} -> real leak rate ${realRate / 100}%, claiming ${claimBps / 100}%`);
      }

      const key = randomKey();
      const ciphertext = keccakCtr(suiteBytes, key);
      log(TAG, `encrypted suite (${suiteBytes.length} bytes) with keccak-CTR; keyHash=${keyHashOf(key).slice(0, 18)}…`);

      // 2. pin to IPFS
      const { cid, pinnedTo } = await pinCiphertext(ciphertext);
      log(TAG, `pinned encrypted suite to IPFS: ${cid} (${pinnedTo.join(", ")})`);

      // 3. list on-chain
      const resolutionTs = BigInt(now() + RESOLUTION_DELAY);
      const params = {
        suiteCID: cid,
        suiteHash: sha256Of(ciphertext),
        keyHash: keyHashOf(key),
        price: PRICE,
        modelId: MODEL_ID,
        category: Cat.DataLeak,
        graderSpec: GRADER,
        claimSummary: summary,
        claimedFailRateBps: BigInt(claimBps),
        trials: BigInt(trials),
        resolutionTimestamp: resolutionTs,
      };
      const { hash, receipt } = await send(w, "list", [params], STAKE);
      const id: bigint = findEvent(receipt, "Listed")!.id;
      log(TAG, `listed #${id} (staked ${formatEther(STAKE)} ETH, resolves ${new Date(Number(resolutionTs) * 1000).toISOString()}) tx ${txLink(hash)}`);

      state.listings.push({ id: id.toString(), key, cid, mode, revealed: false });
      saveState(STATE_FILE, state);

      // 4. wait for a buyer, then reveal (hashlock -> escrow release + disclosure)
      const deadline = now() + BUYER_WAIT;
      let buyers = 0n;
      while (now() < deadline) {
        buyers = (await getListing(id)).numBuyers;
        if (buyers > 0n) break;
        await sleep(5000);
      }
      log(TAG, buyers > 0n ? `#${id}: ${buyers} buyer(s) escrowed — revealing suite (disclosure)` : `#${id}: no buyers within ${BUYER_WAIT}s — revealing anyway to keep the demo moving`);

      let rev;
      for (let attempt = 1; ; attempt++) {
        try { rev = await send(w, "reveal", [id, key]); break; }
        catch (e) {
          if (attempt >= 3) throw e;
          log(TAG, `#${id}: reveal attempt ${attempt} failed (${(e as any)?.shortMessage ?? e}) — retrying in 5s`);
          await sleep(5000);
        }
      }
      const bal: bigint = await readContract("balances", [w.account.address]);
      state.listings.find((x) => x.id === id.toString())!.revealed = true;
      saveState(STATE_FILE, state);
      log(TAG, `#${id}: suite revealed on-chain, escrow released (contract balance ${formatEther(bal)} ETH) tx ${txLink(rev.hash)}`);
    } catch (e) {
      log(TAG, `round ${round} failed (${(e as any)?.shortMessage ?? e}) — moving on; buyers of any un-revealed listing can refund`);
    }
  }

  // 5. wait for settlement, then withdraw
  log(TAG, `all ${ROUNDS} rounds listed — waiting for resolutions to settle stake…`);
  const endBy = now() + RESOLUTION_DELAY + 600;
  while (now() < endBy) {
    try {
      const statuses = await Promise.all(state.listings.map((x) => getListing(BigInt(x.id))));
      if (statuses.every((s) => s.status !== 0 && s.status !== 1)) break;
    } catch {}
    await sleep(10000);
  }
  const bal: bigint = await readContract("balances", [w.account.address]);
  if (bal > 0n) {
    const wd = await send(w, "withdraw", []);
    log(TAG, `withdrew ${formatEther(bal)} ETH (escrowed sales + returned stake) tx ${txLink(wd.hash)}`);
  }
  const rep = await getReputation(w.account.address);
  log(TAG, `final reputation: ${rep.totalListings} listed, ${rep.soldResolved} sold+resolved, ${rep.reproduced} reproduced, ${rep.failedToReproduce} failed, ${rep.disputed} disputed`);
}

main().catch((e) => { console.error(e); process.exit(1); });
