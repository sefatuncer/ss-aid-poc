# -*- coding: utf-8 -*-
"""SS-AID communication-cost measurement.

Serializes the objects the PoC actually produces and reports wire sizes.
Run from the poc/ directory.
"""
import base64
import json
import os
import sys

import identity
import credentials
import dct as dctmod
import oauth_baseline


def compact(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def vc_wire(vc):
    """Wire form: the credential JSON with its proof attached, base64 signature."""
    doc = dict(vc.raw)
    doc["proof"] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": vc.issuer_did + "#key-1",
        "proofValue": base64.b64encode(vc.proof).decode(),
    }
    return compact(doc)


def main():
    out = {}

    owner = identity.generate_did_web("example.com", "owner")
    agent = identity.generate_did_web("example.com", "analyst")
    agent_key = identity.generate_did_key()

    out["did_web_document"] = len(compact(agent.did_document))
    out["did_key_document"] = len(compact(agent_key.did_document))

    caps = ["market_analysis"]
    cons = {"maxValue": 50000, "currency": "USD"}
    vc = credentials.issue_credential(owner, agent.did, caps, cons,
                                      max_delegation_depth=5)
    out["capability_vc_body"] = len(compact(vc.raw))
    out["capability_vc_wire"] = len(vc_wire(vc))
    out["ed25519_signature"] = len(vc.proof)

    # delegation chain, five hops
    chain = [vc]
    parent_id, parent_vc = agent, vc
    total = len(vc_wire(vc))
    for hop in range(1, 5):
        child = identity.generate_did_web("example.com", "sub%d" % hop)
        try:
            dvc = credentials.issue_delegation(parent_id, parent_vc, child.did,
                                               caps, cons)
        except TypeError:
            dvc = credentials.issue_delegation(parent_id, parent_vc, child.did, caps)
        chain.append(dvc)
        total += len(vc_wire(dvc))
        parent_id, parent_vc = child, dvc
    out["delegation_vc_per_hop"] = len(vc_wire(chain[1]))
    out["chain_5hop_total"] = total

    # capability token
    wallet = dctmod.IdentityWallet(agent, vc, None) if False else None
    tok = dctmod.DynamicCapabilityToken(
        action_type="market_analysis", agent_did=agent.did,
        expiry=0.0, nonce="a" * 32, signature=agent.sign(b"x"), timestamp=0.0)
    payload = tok.payload_bytes()
    out["dct_payload"] = len(payload)
    out["dct_wire"] = len(compact({
        "payload": json.loads(payload.decode()),
        "sig": base64.b64encode(tok.signature).decode()}))

    # OAuth baseline
    srv = oauth_baseline.OAuthServer()
    srv.register_client("agent-a1", ["market_analysis"])
    t = srv.issue_token("agent-a1", ["market_analysis"])
    resp = {"access_token": t.token_id, "token_type": "Bearer",
            "expires_in": 3600, "scope": " ".join(t.scope)}
    out["oauth_token_response"] = len(compact(resp))
    out["oauth_bearer_header"] = len(("Authorization: Bearer " + t.token_id).encode())

    for k in sorted(out):
        print("%-26s %6d B" % (k, out[k]))
    os.makedirs("results", exist_ok=True)
    json.dump(out, open("results/comm_cost_results.json", "w"), indent=2)
    print("\nwritten: results/comm_cost_results.json")


if __name__ == "__main__":
    sys.exit(main())
