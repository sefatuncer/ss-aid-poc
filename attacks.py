"""
SS-AID PoC — Attack Simulation Module
Tests spoofing, delegation cascade, and revoked credential attacks.
Generates data for Table 2 (Attack Success Rates).
"""

import time
import json
import os
from identity import generate_did_key, generate_did_web, DIDRegistry, AgentIdentity
from credentials import issue_credential, issue_delegation, verify_credential
from pep import PolicyEnforcementPoint, ActionRequest
from dct import IdentityWallet
from revocation import RevocationRegistry
from oauth_baseline import OAuthServer
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder


def attack_spoofing_noauth(iterations=1000):
    """Attack 1a: Spoofing with no authentication — always succeeds."""
    successes = 0
    for _ in range(iterations):
        successes += 1  # No auth = always spoofable
    return successes / iterations * 100


def attack_spoofing_apikey(iterations=1000):
    """Attack 1b: Spoofing with API-Key — brute force / guess."""
    import hashlib
    real_key = hashlib.sha256(b"agent-01-secret-key-12345").hexdigest()
    successes = 0
    for i in range(iterations):
        # Attacker tries random keys
        fake_key = hashlib.sha256(f"guess-{i}".encode()).hexdigest()
        if fake_key == real_key:
            successes += 1
    return successes / iterations * 100


def attack_spoofing_oauth(server: OAuthServer, iterations=1000):
    """Attack 1c: Spoofing against OAuth — forge/replay tokens."""
    successes = 0
    legit_token = server.issue_token("agent-01", ["market_analysis"])

    for i in range(iterations):
        if i % 3 == 0:
            # Strategy 1: Replay captured token (should fail if expired/revoked)
            success = server.verify_token(legit_token) if legit_token else False
        elif i % 3 == 1:
            # Strategy 2: Forge token with wrong signature
            from oauth_baseline import OAuthToken
            import hashlib
            fake_token = OAuthToken(
                token_id=hashlib.sha256(f"fake-{i}".encode()).hexdigest()[:32],
                client_id="agent-01",
                scope=["market_analysis"],
                expires_at=time.time() + 3600,
                signature=os.urandom(32)
            )
            success = server.verify_token(fake_token)
        else:
            # Strategy 3: Token for unregistered client
            fake = server.issue_token("nonexistent-agent", ["market_analysis"])
            success = fake is not None

        if success:
            successes += 1

    return successes / iterations * 100


def attack_spoofing_ssaid(registry: DIDRegistry, iterations=1000):
    """Attack 1d: Spoofing against SS-AID — forge signatures, substitute keys."""
    successes = 0
    victim = generate_did_web("org.example", "victim")
    registry.register(victim)
    msg = b"legitimate action request"

    for i in range(iterations):
        if i % 3 == 0:
            # Strategy 1: Forge signature with random key
            attacker_sk = SigningKey.generate()
            fake_sig = attacker_sk.sign(msg).signature
            success = registry.verify_signature(victim.did, msg, fake_sig)
        elif i % 3 == 1:
            # Strategy 2: Replay valid signature with modified message
            real_sig = victim.sign(msg)
            modified_msg = b"malicious action request"
            success = registry.verify_signature(victim.did, modified_msg, real_sig)
        else:
            # Strategy 3: Register own DID and try to impersonate
            attacker = generate_did_web("evil.example", "fake-victim")
            registry.register(attacker)
            fake_sig = attacker.sign(msg)
            success = registry.verify_signature(victim.did, msg, fake_sig)

        if success:
            successes += 1

    return successes / iterations * 100


def attack_delegation_oauth(server: OAuthServer, iterations=1000):
    """Attack 2: Delegation cascade with OAuth — scope widening."""
    successes = 0
    server.register_client("delegator", ["market_analysis"])

    for i in range(iterations):
        # Try to get a token with wider scope than allowed
        token = server.issue_token("delegator", ["market_analysis", "admin_access"])
        if token is not None:
            successes += 1

    return successes / iterations * 100


def attack_delegation_ssaid(registry: DIDRegistry, iterations=1000):
    """Attack 2: Delegation cascade with SS-AID — scope widening + depth exceeding."""
    successes = 0

    principal = generate_did_web("org.example", "principal")
    agent = generate_did_web("org.example", "agent-a")
    sub_agent = generate_did_web("org.example", "agent-b")

    registry.register(principal)
    registry.register(agent)
    registry.register(sub_agent)

    cred = issue_credential(
        issuer=principal,
        subject_did=agent.did,
        capabilities=["market_analysis"],
        constraints={"maxTransactionValue": 10000},
        max_delegation_depth=2
    )

    for i in range(iterations):
        if i % 2 == 0:
            # Strategy 1: Scope widening — delegate more than received
            result = issue_delegation(
                delegator=agent,
                delegator_credential=cred,
                delegatee_did=sub_agent.did,
                capabilities=["market_analysis", "portfolio_rebalance"],  # wider!
                constraints={"maxTransactionValue": 10000}
            )
            if result is not None:
                successes += 1
        else:
            # Strategy 2: Constraint widening — higher transaction limit
            result = issue_delegation(
                delegator=agent,
                delegator_credential=cred,
                delegatee_did=sub_agent.did,
                capabilities=["market_analysis"],
                constraints={"maxTransactionValue": 99999}  # exceeds parent!
            )
            if result is not None:
                successes += 1

    return successes / iterations * 100


def attack_revoked_credential_oauth(server: OAuthServer, iterations=1000):
    """Attack 3: Use revoked credential — OAuth (centralized, immediate)."""
    successes = 0

    for _ in range(iterations):
        token = server.issue_token("agent-01", ["market_analysis"])
        if token:
            server.revoke_token(token.token_id)
            # Try to use immediately after revocation
            if server.verify_token(token):
                successes += 1

    return successes / iterations * 100


def attack_revoked_credential_ssaid(registry: DIDRegistry, iterations=1000,
                                      propagation_delay: float = 0.001):
    """Attack 3: Use revoked credential — SS-AID (decentralized, with propagation delay)."""
    successes = 0
    revocation_reg = RevocationRegistry(propagation_delay=propagation_delay)

    principal = generate_did_web("org.example", "principal")
    agent = generate_did_web("org.example", "agent-r")
    registry.register(principal)
    registry.register(agent)

    for _ in range(iterations):
        cred = issue_credential(
            issuer=principal,
            subject_did=agent.did,
            capabilities=["market_analysis"],
            constraints={"maxTransactionValue": 50000}
        )
        cred_bytes = cred.canonical_bytes()

        # Revoke the credential
        revocation_reg.revoke(cred_bytes)

        # Immediately try to use it (within propagation window)
        if not revocation_reg.is_revoked(cred_bytes):
            successes += 1

    return successes / iterations * 100


def run_all_attacks(iterations=1000):
    """Run all attack scenarios and return results for Table 2."""
    print(f"\n{'='*60}")
    print(f"ATTACK SIMULATIONS ({iterations} iterations each)")
    print(f"{'='*60}")

    registry = DIDRegistry()
    oauth_server = OAuthServer()
    oauth_server.register_client("agent-01", ["market_analysis", "portfolio_rebalance"])

    results = {}

    # Spoofing attacks
    print("\n--- SPOOFING ATTACKS ---")

    print("[1/4] No-Auth spoofing...")
    results["spoofing_noauth"] = attack_spoofing_noauth(iterations)
    print(f"  Success rate: {results['spoofing_noauth']:.1f}%")

    print("[2/4] API-Key spoofing...")
    results["spoofing_apikey"] = attack_spoofing_apikey(iterations)
    print(f"  Success rate: {results['spoofing_apikey']:.1f}%")

    print("[3/4] OAuth spoofing...")
    results["spoofing_oauth"] = attack_spoofing_oauth(oauth_server, iterations)
    print(f"  Success rate: {results['spoofing_oauth']:.1f}%")

    print("[4/4] SS-AID spoofing...")
    results["spoofing_ssaid"] = attack_spoofing_ssaid(registry, iterations)
    print(f"  Success rate: {results['spoofing_ssaid']:.1f}%")

    # Delegation attacks
    print("\n--- DELEGATION CASCADE ATTACKS ---")

    print("[1/2] OAuth delegation...")
    results["delegation_oauth"] = attack_delegation_oauth(oauth_server, iterations)
    print(f"  Success rate: {results['delegation_oauth']:.1f}%")

    print("[2/2] SS-AID delegation...")
    results["delegation_ssaid"] = attack_delegation_ssaid(registry, iterations)
    print(f"  Success rate: {results['delegation_ssaid']:.1f}%")

    # Revoked credential attacks
    print("\n--- REVOKED CREDENTIAL ATTACKS ---")

    print("[1/2] OAuth revoked credential...")
    results["revoked_oauth"] = attack_revoked_credential_oauth(oauth_server, iterations)
    print(f"  Success rate: {results['revoked_oauth']:.1f}%")

    print("[2/2] SS-AID revoked credential (1ms propagation delay)...")
    results["revoked_ssaid"] = attack_revoked_credential_ssaid(
        registry, iterations, propagation_delay=0.001
    )
    print(f"  Success rate: {results['revoked_ssaid']:.1f}%")

    # Delegation depth analysis
    print("\n--- DELEGATION DEPTH ANALYSIS ---")
    depth_results = {}
    for depth in [1, 2, 3, 4, 5, 6, 8]:
        principal = generate_did_web("org.example", "p")
        registry.register(principal)

        chain_success = True
        current_cred = issue_credential(
            issuer=principal,
            subject_did=f"did:key:agent-depth-0",
            capabilities=["market_analysis"],
            constraints={"maxTransactionValue": 50000},
            max_delegation_depth=depth + 1
        )

        agents = []
        for d in range(depth):
            a = generate_did_web("org.example", f"depth-{d}")
            registry.register(a)
            agents.append(a)

            next_cred = issue_delegation(
                delegator=agents[-1] if d > 0 else principal if d == 0 else agents[d-1],
                delegator_credential=current_cred,
                delegatee_did=a.did,
                capabilities=["market_analysis"],
                constraints={"maxTransactionValue": max(50000 - d * 5000, 1000)}
            )
            if next_cred is None:
                chain_success = False
                break
            current_cred = next_cred

        depth_results[depth] = chain_success
        print(f"  Depth {depth}: {'OK' if chain_success else 'FAILED'}")

    results["delegation_depth"] = depth_results
    results["metadata"] = {
        "iterations": iterations,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    return results


if __name__ == "__main__":
    results = run_all_attacks(1000)

    print(f"\n{'='*60}")
    print("ATTACK RESULTS SUMMARY (Table 2)")
    print(f"{'='*60}")
    print(f"{'Attack':<25} {'No-Auth':>8} {'API-Key':>8} {'OAuth':>8} {'SS-AID':>8}")
    print(f"{'-'*57}")
    print(f"{'Spoofing':<25} {results['spoofing_noauth']:>7.1f}% {results['spoofing_apikey']:>7.1f}% {results['spoofing_oauth']:>7.1f}% {results['spoofing_ssaid']:>7.1f}%")
    print(f"{'Delegation Cascade':<25} {'N/A':>8} {'N/A':>8} {results['delegation_oauth']:>7.1f}% {results['delegation_ssaid']:>7.1f}%")
    print(f"{'Revoked Credential':<25} {'N/A':>8} {'N/A':>8} {results['revoked_oauth']:>7.1f}% {results['revoked_ssaid']:>7.1f}%")

    os.makedirs("results", exist_ok=True)
    with open("results/attack_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to results/attack_results.json")
