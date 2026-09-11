import {
  createPublicClient,
  createWalletClient,
  fallback,
  http,
  keccak256,
  sha256,
  encodePacked,
  encodeAbiParameters,
  decodeAbiParameters,
  decodeEventLog,
  parseAbiParameters,
  hexToBytes,
  bytesToHex,
  type Hex,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";
import { CID } from "multiformats/cid";
import * as rawCodec from "multiformats/codecs/raw";
import { sha256 as mfSha256 } from "multiformats/hashes/sha2";
import fs from "node:fs";
import path from "node:path";
import artifact from "../out/Jailbreakers.sol/Jailbreakers.json";
import { CategoryName } from "./model";

export const abi = artifact.abi;
export const EXPLORER = "https://sepolia.etherscan.io";

export const CONTRACT = (process.env.JAILBREAKERS_ADDRESS ?? "") as Address;
if (!CONTRACT) throw new Error("JAILBREAKERS_ADDRESS not set in .env (deploy first)");

const primaryRpc = process.env.SEPOLIA_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com";
const transport = primaryRpc.includes("127.0.0.1") || primaryRpc.includes("localhost")
  ? http(primaryRpc) // local rehearsal: never fall back to public RPCs
  : fallback([http(primaryRpc), http("https://sepolia.drpc.org"), http("https://1rpc.io/sepolia")]);

export const publicClient = createPublicClient({ chain: sepolia, transport });

export function makeWallet(envKey: string) {
  const pk = process.env[envKey];
  if (!pk) throw new Error(`${envKey} not set in .env`);
  const account = privateKeyToAccount(pk as Hex);
  const wallet = createWalletClient({ account, chain: sepolia, transport });
  return { account, wallet };
}

export const Status = ["Open", "Revealed", "Invalid", "Resolved", "Expired", "Cancelled"] as const;
export const Category = CategoryName;

// ------------------------------------------------------------ contract I/O

export async function getListing(id: bigint): Promise<any> {
  return publicClient.readContract({ address: CONTRACT, abi, functionName: "getListing", args: [id] });
}

export async function getReputation(seller: Address): Promise<any> {
  return publicClient.readContract({ address: CONTRACT, abi, functionName: "getSellerReputation", args: [seller] });
}

export async function readContract(functionName: string, args: any[] = []): Promise<any> {
  return publicClient.readContract({ address: CONTRACT, abi, functionName, args });
}

/** simulate (to surface revert reasons) -> send -> wait for inclusion */
export async function send(
  w: ReturnType<typeof makeWallet>,
  functionName: string,
  args: any[],
  value?: bigint,
) {
  const { request } = await publicClient.simulateContract({
    account: w.account,
    address: CONTRACT,
    abi,
    functionName,
    args,
    value,
  });
  const hash = await w.wallet.writeContract(request);
  // Sepolia inclusion can lag well past viem's default wait; a timeout here does
  // NOT mean the tx failed, so callers must reconcile against chain state.
  const receipt = await publicClient.waitForTransactionReceipt({
    hash,
    timeout: 300_000,
    pollingInterval: 4_000,
  });
  if (receipt.status !== "success") {
    // simulation passed but chain state moved before inclusion (e.g. a deadline lapsed)
    throw new Error(`${functionName} tx ${hash} reverted on-chain`);
  }
  return { hash, receipt };
}

export function findEvent(receipt: any, eventName: string): any | undefined {
  for (const lg of receipt.logs) {
    try {
      const ev = decodeEventLog({ abi, data: lg.data, topics: lg.topics });
      if (ev.eventName === eventName) return ev.args;
    } catch {}
  }
}

// ------------------------------------------------------- eval-suite payload

// The secret IP is the prompt suite. Schema matches Jailbreakers.parseSuite:
export const SUITE_PARAMS = parseAbiParameters("string modelId, uint8 category, string[] prompts");

export type Suite = { modelId: string; category: number; prompts: string[] };

export function encodeSuite(s: Suite): Uint8Array {
  return hexToBytes(encodeAbiParameters(SUITE_PARAMS, [s.modelId, s.category, s.prompts]));
}

export function decodeSuite(pt: Uint8Array): Suite {
  const [modelId, category, prompts] = decodeAbiParameters(SUITE_PARAMS, bytesToHex(pt));
  return { modelId, category, prompts: prompts as string[] };
}

/** Mirrors Jailbreakers._validEval — run off-chain before deciding to dispute. */
export function validateSuite(
  pt: Uint8Array,
  claim: { modelId: string; category: number; trials: bigint },
): { valid: boolean; reason: string; suite?: Suite } {
  let s: Suite;
  try {
    s = decodeSuite(pt);
  } catch {
    return { valid: false, reason: "suite is not ABI-decodable (schema violation)" };
  }
  if (s.modelId !== claim.modelId) return { valid: false, reason: `suite targets "${s.modelId}", claim says "${claim.modelId}"`, suite: s };
  if (s.category !== claim.category) return { valid: false, reason: "category mismatch vs public claim", suite: s };
  if (BigInt(s.prompts.length) !== claim.trials) return { valid: false, reason: `suite has ${s.prompts.length} prompts, claim declared ${claim.trials} trials`, suite: s };
  if (s.prompts.some((p) => p.length === 0)) return { valid: false, reason: "suite contains an empty prompt", suite: s };
  return { valid: true, reason: "well-formed eval consistent with the on-chain claim", suite: s };
}

// ------------------------------------------- keccak-CTR cipher (== contract)

/** XOR stream cipher; keystream block i = keccak256(key ‖ uint256(i)). Symmetric. */
export function keccakCtr(data: Uint8Array, key: Hex): Uint8Array {
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 32) {
    const ks = hexToBytes(keccak256(encodePacked(["bytes32", "uint256"], [key, BigInt(i / 32 | 0)])));
    for (let j = 0; j < 32 && i + j < data.length; j++) out[i + j] = data[i + j]! ^ ks[j]!;
  }
  return out;
}

export function randomKey(): Hex {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return bytesToHex(b);
}

export function keyHashOf(key: Hex): Hex {
  return keccak256(encodePacked(["bytes32"], [key]));
}

export function sha256Of(bytes: Uint8Array): Hex {
  return sha256(bytes);
}

// ------------------------------------------------------------------- IPFS

const STORE_DIR = path.join(import.meta.dir, "..", "ipfs-store");
const KUBO_API = "http://127.0.0.1:5001/api/v0";

/** CIDv1 / raw codec / sha2-256 — its digest equals the on-chain sha256 commitment. */
export async function computeCid(bytes: Uint8Array): Promise<string> {
  const digest = await mfSha256.digest(bytes);
  return CID.createV1(rawCodec.code, digest).toString();
}

export async function pinCiphertext(bytes: Uint8Array): Promise<{ cid: string; pinnedTo: string[] }> {
  const cid = await computeCid(bytes);
  const pinnedTo: string[] = [];

  fs.mkdirSync(STORE_DIR, { recursive: true });
  fs.writeFileSync(path.join(STORE_DIR, `${cid}.bin`), bytes);
  pinnedTo.push("local-store");

  try {
    const form = new FormData();
    form.append("data", new Blob([bytes]));
    const res = await fetch(`${KUBO_API}/block/put?cid-codec=raw&pin=true`, {
      method: "POST",
      body: form,
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) {
      const j: any = await res.json();
      if (j.Key === cid) pinnedTo.push("kubo");
      else console.warn(`  ! kubo returned unexpected CID ${j.Key} (expected ${cid})`);
    }
  } catch {}

  const jwt = process.env.PINATA_JWT;
  if (jwt) {
    try {
      const form = new FormData();
      form.append("file", new Blob([bytes]), `${cid}.bin`);
      form.append("pinataOptions", JSON.stringify({ cidVersion: 1 }));
      const res = await fetch("https://api.pinata.cloud/pinning/pinFileToIPFS", {
        method: "POST",
        headers: { Authorization: `Bearer ${jwt}` },
        body: form,
        signal: AbortSignal.timeout(20000),
      });
      if (res.ok) {
        const j: any = await res.json();
        if (j.IpfsHash === cid) pinnedTo.push("pinata");
        else console.warn(`  ! pinata returned CID ${j.IpfsHash} (expected ${cid}) — chunking mismatch`);
      } else console.warn(`  ! pinata pin failed: HTTP ${res.status}`);
    } catch (e) {
      console.warn(`  ! pinata pin failed: ${e}`);
    }
  }
  return { cid, pinnedTo };
}

export async function fetchCiphertext(cid: string): Promise<Uint8Array | null> {
  const f = path.join(STORE_DIR, `${cid}.bin`);
  if (fs.existsSync(f)) return new Uint8Array(fs.readFileSync(f));
  try {
    const res = await fetch(`${KUBO_API}/block/get?arg=${cid}`, { method: "POST", signal: AbortSignal.timeout(5000) });
    if (res.ok) return new Uint8Array(await res.arrayBuffer());
  } catch {}
  for (const gw of ["https://ipfs.io/ipfs/", "https://dweb.link/ipfs/"]) {
    try {
      const res = await fetch(gw + cid, { signal: AbortSignal.timeout(15000) });
      if (res.ok) return new Uint8Array(await res.arrayBuffer());
    } catch {}
  }
  return null;
}

// ------------------------------------------------------------------- misc

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function envInt(name: string, dflt: number): number {
  const v = process.env[name];
  return v ? parseInt(v, 10) : dflt;
}

export function now(): number {
  return Math.floor(Date.now() / 1000);
}

/** Latest block timestamp — contracts see this, not wall-clock time. */
export async function chainNow(): Promise<bigint> {
  return (await publicClient.getBlock()).timestamp;
}

export function errMsg(e: any): string {
  return e?.shortMessage ?? e?.message ?? String(e);
}

export function log(tag: string, msg: string) {
  console.log(`[${new Date().toISOString().slice(11, 19)}] [${tag}] ${msg}`);
}

export function txLink(hash: string): string {
  return `${EXPLORER}/tx/${hash}`;
}

export function loadState<T>(file: string, dflt: T): T {
  const p = path.join(import.meta.dir, file);
  if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf8"));
  return dflt;
}

export function saveState(file: string, state: any) {
  fs.writeFileSync(path.join(import.meta.dir, file), JSON.stringify(state, null, 2));
}
