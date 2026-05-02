/**
 * Additional chain verification tests to reach ≥90% coverage.
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { CustodyChain, nodeHash } from "../src/custody.js";

ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

function b64uEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

let privA: Uint8Array;
let privB: Uint8Array;
let pubAB64u: string;

beforeAll(() => {
  privA = ed.utils.randomPrivateKey();
  privB = ed.utils.randomPrivateKey();
  pubAB64u = b64uEncode(ed.getPublicKey(privA));
});

describe("verifyChain — invalid signature detection", () => {
  it("detects tampered node signature", () => {
    const chain = new CustodyChain();
    chain.append({ transformId: "t1", agentDid: "did:a", payload: { x: 1 }, privKey: privA });
    chain.append({ transformId: "t2", agentDid: "did:a", payload: { x: 2 }, privKey: privA });

    // Manually corrupt a node signature by rebuilding chain from nodes
    const nodes = chain.getNodes();
    // Create a second chain that has the correct hash chain but corrupt sig
    const chain2 = new CustodyChain();
    chain2.append({ transformId: "t1", agentDid: "did:a", payload: { x: 1 }, privKey: privA });
    // Append with privB — so signature won't verify against privA's public key
    chain2.append({ transformId: "t2", agentDid: "did:a", payload: { x: 2 }, privKey: privB });

    // Verify with trustedKeys requiring pubA for "did:a"
    const result = chain2.verifyChain({ "did:a": pubAB64u });
    // First node passes (signed by privA), second fails (signed by privB but pubA expected)
    expect(result.valid).toBe(false);
    expect(result.firstInvalidIndex).toBe(1);
    expect(result.reason).toContain("signature invalid");
  });

  it("verifyChain with no trustedKeys uses embedded key_id (TOFU)", () => {
    const chain = new CustodyChain();
    chain.append({ transformId: "t1", agentDid: "did:a", payload: {}, privKey: privA });
    chain.append({ transformId: "t2", agentDid: "did:b", payload: {}, privKey: privB });
    const result = chain.verifyChain(); // TOFU — each node validates its own key_id
    expect(result.valid).toBe(true);
  });

  it("detects invalid key bytes in trustedKeys", () => {
    const chain = new CustodyChain();
    chain.append({ transformId: "t", agentDid: "did:a", payload: {}, privKey: privA });
    // Pass a malformed pubkey — should catch the error and fail
    const result = chain.verifyChain({ "did:a": "!!!invalid!!!" });
    expect(result.valid).toBe(false);
  });
});

describe("verifyChain — hash linkage detection", () => {
  it("independent construction: two chains with same steps have same linkage pattern", () => {
    const chain1 = new CustodyChain();
    const chain2 = new CustodyChain();
    // Both chains add genesis node
    const r1 = chain1.append({ transformId: "t", agentDid: "did:a", payload: {}, privKey: privA });
    const r2 = chain2.append({ transformId: "t", agentDid: "did:a", payload: {}, privKey: privA });
    // Both first nodes have "genesis" as prev_hash
    expect(r1.node.prev_hash).toBe("genesis");
    expect(r2.node.prev_hash).toBe("genesis");
  });

  it("nodeHash changes when agent_did changes", () => {
    const chain = new CustodyChain();
    const { node } = chain.append({ transformId: "t", agentDid: "did:a", payload: {}, privKey: privA });
    const h1 = nodeHash(node);
    const h2 = nodeHash({ ...node, agent_did: "did:z" });
    expect(h1).not.toBe(h2);
  });

  it("nodeHash changes when timestamp changes", () => {
    const chain = new CustodyChain();
    const { node } = chain.append({ transformId: "t", agentDid: "did:a", payload: {}, privKey: privA });
    const h1 = nodeHash(node);
    const h2 = nodeHash({ ...node, timestamp: "2099-01-01T00:00:00.000Z" });
    expect(h1).not.toBe(h2);
  });
});

describe("CustodyChain — timestamp override", () => {
  it("uses provided nowMs for timestamp", () => {
    const chain = new CustodyChain();
    const fixed = new Date("2026-05-02T18:30:00.000Z").getTime();
    const { node } = chain.append({
      transformId: "t", agentDid: "did:a", payload: {}, privKey: privA, nowMs: fixed,
    });
    expect(node.timestamp).toBe("2026-05-02T18:30:00.000Z");
  });
});

describe("CustodyChain — unknown taint propagation edge cases", () => {
  it("clean→unknown→clean verifies with chainTaintStatus=unknown", () => {
    const chain = new CustodyChain();
    chain.append({ transformId: "t1", agentDid: "did:a", payload: {}, taintStatus: "clean", privKey: privA });
    chain.append({ transformId: "t2", agentDid: "did:a", payload: {}, taintStatus: "unknown", privKey: privA });
    chain.append({ transformId: "t3", agentDid: "did:a", payload: {}, taintStatus: "clean", privKey: privA });
    const r = chain.verifyChain();
    expect(r.chainTaintStatus).toBe("unknown");
    expect(r.taintStatuses[0]).toBe("clean");
    expect(r.taintStatuses[1]).toBe("unknown");
  });
});
