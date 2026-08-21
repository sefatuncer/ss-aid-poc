"""
SS-AID PoC — Agent Framework Integration Demo

Demonstrates how SS-AID's PEP integrates with a real agent tool-calling
pattern. Shows the critical architectural point: the PEP sits between
the LLM's tool call decision and the actual execution.

Two integration patterns:
  1. Decorator pattern: @ssaid_protected wraps any tool function
  2. Middleware pattern: PEP middleware intercepts tool calls in a pipeline

This module does NOT require an LLM API key — it simulates the LLM's
tool call output to demonstrate the identity layer integration point.
"""

import json
import time
import functools
from dataclasses import dataclass
from typing import Callable, Optional, Any

from identity import generate_did_web, DIDRegistry
from credentials import issue_credential
from pep import PolicyEnforcementPoint, ActionRequest, PEPDecision
from dct import IdentityWallet


# =============================================================================
# Pattern 1: Decorator-based PEP Integration
# =============================================================================

def ssaid_protected(wallet: 'IdentityWallet', action_type: str):
    """
    Decorator that wraps a tool function with SS-AID PEP enforcement.

    Usage with LangChain-style tools:

        @ssaid_protected(wallet, "market_analysis")
        def analyze_market(market: str, amount: float) -> dict:
            return {"result": f"Analysis of {market}"}

    The decorator:
      1. Checks if the action is within credential scope (PEP)
      2. Generates a DCT if authorized
      3. Executes the tool function
      4. Returns result with DCT audit trail
      5. BLOCKS execution if unauthorized (returns PEPDecision)
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(**kwargs) -> dict:
            # PEP evaluation
            dct, decision = wallet.request_action(action_type, kwargs)

            if not decision.allowed:
                return {
                    "status": "BLOCKED",
                    "reason": decision.reason,
                    "action": action_type,
                    "agent_did": wallet.identity.did,
                }

            # Execute the actual tool
            result = func(**kwargs)

            return {
                "status": "EXECUTED",
                "result": result,
                "dct_nonce": dct.nonce if dct else None,
                "dct_expiry": dct.expiry if dct else None,
                "agent_did": wallet.identity.did,
            }
        return wrapper
    return decorator


# =============================================================================
# Pattern 2: Middleware Pipeline (MCP/A2A compatible)
# =============================================================================

class SSAIDMiddleware:
    """
    Middleware that intercepts tool calls in an agent pipeline.

    Compatible with MCP tool handler pattern:
        middleware = SSAIDMiddleware(wallet)
        result = middleware.execute_tool(tool_name, tool_args)

    The middleware maps tool names to SS-AID capability names and
    enforces PEP authorization before any tool execution.
    """

    def __init__(self, wallet: IdentityWallet,
                 tool_capability_map: Optional[dict] = None):
        """
        Args:
            wallet: Agent's IdentityWallet with credentials
            tool_capability_map: Maps tool names to SS-AID capabilities.
                If None, tool names are used as capability names directly.
        """
        self.wallet = wallet
        self.tool_map = tool_capability_map or {}
        self.tools: dict[str, Callable] = {}
        self.audit_log: list[dict] = []

    def register_tool(self, name: str, func: Callable,
                      capability: Optional[str] = None):
        """Register a tool with optional capability mapping."""
        self.tools[name] = func
        if capability:
            self.tool_map[name] = capability

    def execute_tool(self, tool_name: str, tool_args: dict) -> dict:
        """
        Execute a tool call through SS-AID PEP.

        This is the integration point where an agent framework
        (LangChain, AutoGen, MCP) would call into SS-AID.
        """
        timestamp = time.time()

        # 1. Resolve capability name
        capability = self.tool_map.get(tool_name, tool_name)

        # 2. Check tool exists
        if tool_name not in self.tools:
            entry = {
                "timestamp": timestamp,
                "tool": tool_name,
                "status": "UNKNOWN_TOOL",
                "capability": capability,
            }
            self.audit_log.append(entry)
            return entry

        # 3. PEP evaluation
        dct, decision = self.wallet.request_action(capability, tool_args)

        if not decision.allowed:
            entry = {
                "timestamp": timestamp,
                "tool": tool_name,
                "capability": capability,
                "status": "BLOCKED_BY_PEP",
                "reason": decision.reason,
                "agent_did": self.wallet.identity.did,
            }
            self.audit_log.append(entry)
            return entry

        # 4. Execute tool
        try:
            result = self.tools[tool_name](**tool_args)
            entry = {
                "timestamp": timestamp,
                "tool": tool_name,
                "capability": capability,
                "status": "EXECUTED",
                "result": result,
                "dct_nonce": dct.nonce if dct else None,
                "agent_did": self.wallet.identity.did,
            }
        except Exception as e:
            entry = {
                "timestamp": timestamp,
                "tool": tool_name,
                "capability": capability,
                "status": "EXECUTION_ERROR",
                "error": str(e),
            }

        self.audit_log.append(entry)
        return entry


# =============================================================================
# Demo: Simulated Agent with SS-AID Integration
# =============================================================================

def demo_decorator_pattern():
    """Demonstrate decorator-based PEP integration."""
    print(f"\n{'='*60}")
    print("DEMO 1: Decorator Pattern (@ssaid_protected)")
    print(f"{'='*60}")

    # Setup identity
    registry = DIDRegistry()
    principal = generate_did_web("fintech.example", "principal")
    agent = generate_did_web("fintech.example", "advisor-agent")
    registry.register(principal)
    registry.register(agent)

    cred = issue_credential(
        issuer=principal,
        subject_did=agent.did,
        capabilities=["market_analysis", "portfolio_rebalance"],
        constraints={"maxTransactionValue": 50000,
                     "allowedMarkets": ["NYSE", "NASDAQ"]}
    )
    wallet = IdentityWallet(agent, cred, registry)

    # Define tools with SS-AID protection
    @ssaid_protected(wallet, "market_analysis")
    def analyze_market(market: str, amount: float) -> dict:
        return {"analysis": f"Bullish on {market}", "confidence": 0.85}

    @ssaid_protected(wallet, "admin_access")
    def admin_panel(command: str) -> dict:
        return {"executed": command}  # Should never reach here

    # Test 1: Authorized action
    print("\n[Test 1] Authorized: analyze_market(NYSE, $5000)")
    result = analyze_market(market="NYSE", amount=5000)
    print(f"  Status: {result['status']}")
    print(f"  Result: {result.get('result', 'N/A')}")
    print(f"  DCT nonce: {result.get('dct_nonce', 'N/A')}")

    # Test 2: Unauthorized action (out of scope)
    print("\n[Test 2] Unauthorized: admin_panel('delete_all')")
    result = admin_panel(command="delete_all")
    print(f"  Status: {result['status']}")
    print(f"  Reason: {result.get('reason', 'N/A')}")

    # Test 3: Authorized but constraint violation
    print("\n[Test 3] Constraint violation: analyze_market(NYSE, $999999)")
    result = analyze_market(market="NYSE", amount=999999)
    print(f"  Status: {result['status']}")
    print(f"  Reason: {result.get('reason', 'N/A')}")


def demo_middleware_pattern():
    """Demonstrate middleware pipeline integration."""
    print(f"\n{'='*60}")
    print("DEMO 2: Middleware Pattern (MCP/A2A compatible)")
    print(f"{'='*60}")

    # Setup identity
    registry = DIDRegistry()
    principal = generate_did_web("healthcare.example", "hospital")
    agent = generate_did_web("healthcare.example", "triage-agent")
    registry.register(principal)
    registry.register(agent)

    cred = issue_credential(
        issuer=principal,
        subject_did=agent.did,
        capabilities=["patient_referral", "insurance_verify"],
        constraints={"maxTransactionValue": 100000}
    )
    wallet = IdentityWallet(agent, cred, registry)

    # Create middleware
    middleware = SSAIDMiddleware(wallet, tool_capability_map={
        "refer_patient": "patient_referral",
        "check_insurance": "insurance_verify",
        "prescribe_medication": "prescription_write",  # NOT in capabilities
    })

    # Register tools
    middleware.register_tool("refer_patient",
        lambda patient_id, department, amount: {
            "referral_id": f"REF-{patient_id}",
            "department": department
        })
    middleware.register_tool("check_insurance",
        lambda patient_id, amount: {
            "covered": True, "plan": "Premium"
        })
    middleware.register_tool("prescribe_medication",
        lambda medication, dosage, amount: {
            "prescription_id": "RX-001"
        })

    # Simulate LLM tool calls (as if from reasoning engine)
    llm_tool_calls = [
        {"tool": "refer_patient", "args": {"patient_id": "P-123", "department": "cardiology", "amount": 5000}},
        {"tool": "check_insurance", "args": {"patient_id": "P-123", "amount": 5000}},
        {"tool": "prescribe_medication", "args": {"medication": "aspirin", "dosage": "100mg", "amount": 50}},
        {"tool": "refer_patient", "args": {"patient_id": "P-456", "department": "oncology", "amount": 999999}},
    ]

    for i, call in enumerate(llm_tool_calls):
        print(f"\n[Call {i+1}] {call['tool']}({call['args']})")
        result = middleware.execute_tool(call["tool"], call["args"])
        print(f"  Status: {result['status']}")
        if result["status"] == "BLOCKED_BY_PEP":
            print(f"  Reason: {result['reason']}")
        elif result["status"] == "EXECUTED":
            print(f"  Result: {result.get('result', 'N/A')}")

    # Audit trail
    print(f"\n--- Audit Trail ({len(middleware.audit_log)} entries) ---")
    for entry in middleware.audit_log:
        print(f"  [{entry['status']}] {entry['tool']} → {entry.get('capability', 'N/A')}")


if __name__ == "__main__":
    demo_decorator_pattern()
    demo_middleware_pattern()

    print(f"\n{'='*60}")
    print("SS-AID Agent Integration Demo Complete")
    print(f"{'='*60}")
    print("\nKey takeaway: PEP blocks unauthorized tools deterministically,")
    print("regardless of what the LLM reasoning engine requests.")
