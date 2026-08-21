"""
SS-AID PoC — Policy Enforcement Point
Deterministic scope verification between reasoning engine and action handler.
"""

from dataclasses import dataclass
from typing import Optional
from credentials import VerifiableCredential


@dataclass
class ActionRequest:
    """A proposed action from the reasoning engine."""
    action_type: str           # e.g., "market_analysis", "portfolio_rebalance"
    parameters: dict           # e.g., {"market": "NYSE", "amount": 5000}
    requesting_agent_did: str


@dataclass
class PEPDecision:
    """Result of PEP scope verification."""
    allowed: bool
    reason: str
    action: Optional[ActionRequest] = None


class PolicyEnforcementPoint:
    """
    Deterministic PEP — no LLM involvement.
    Validates every action against the agent's active credential scope.
    """

    def __init__(self, credential: VerifiableCredential):
        self.credential = credential

    def evaluate(self, action: ActionRequest) -> PEPDecision:
        """Evaluate whether an action falls within credential scope."""

        # 1. Check credential expiry
        if self.credential.is_expired():
            return PEPDecision(
                allowed=False,
                reason="Credential expired"
            )

        # 2. Check capability authorization
        capabilities = self.credential.capabilities
        if action.action_type not in capabilities:
            return PEPDecision(
                allowed=False,
                reason=f"Action '{action.action_type}' not in authorized capabilities: {capabilities}"
            )

        # 3. Check constraints
        constraints = self.credential.constraints
        params = action.parameters

        # Check transaction value limit
        if "maxTransactionValue" in constraints and "amount" in params:
            if params["amount"] > constraints["maxTransactionValue"]:
                return PEPDecision(
                    allowed=False,
                    reason=f"Amount {params['amount']} exceeds limit {constraints['maxTransactionValue']}"
                )

        # Check allowed markets
        if "allowedMarkets" in constraints and "market" in params:
            if params["market"] not in constraints["allowedMarkets"]:
                return PEPDecision(
                    allowed=False,
                    reason=f"Market '{params['market']}' not in allowed: {constraints['allowedMarkets']}"
                )

        return PEPDecision(
            allowed=True,
            reason="Action within authorized scope",
            action=action
        )
