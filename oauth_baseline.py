"""
SS-AID PoC — OAuth 2.1 Baseline Simulation
Simulates centralized OAuth 2.1 token issuance and verification for comparison.
"""

import hashlib
import hmac
import json
import time
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class OAuthToken:
    """Simulated OAuth 2.1 bearer token."""
    token_id: str
    client_id: str
    scope: list
    expires_at: float
    signature: bytes


class OAuthServer:
    """
    Simulated centralized OAuth 2.1 authorization server.
    Single-instance, no load balancing (as noted in paper's OAuth baseline config).
    """

    def __init__(self):
        self._server_secret = os.urandom(32)
        self._issued_tokens: dict[str, dict] = {}
        self._revoked_tokens: set = set()
        self._clients: dict[str, dict] = {}

    def register_client(self, client_id: str, allowed_scopes: list):
        self._clients[client_id] = {
            "scopes": allowed_scopes,
            "registered_at": time.time()
        }

    def issue_token(self, client_id: str, requested_scopes: list,
                    ttl_seconds: int = 3600) -> Optional[OAuthToken]:
        """Issue an OAuth 2.1 bearer token with HMAC-SHA256 signature."""
        client = self._clients.get(client_id)
        if not client:
            return None

        # Scope validation
        allowed = set(client["scopes"])
        requested = set(requested_scopes)
        if not requested.issubset(allowed):
            return None

        token_id = hashlib.sha256(
            f"{client_id}{time.time_ns()}{os.urandom(8).hex()}".encode()
        ).hexdigest()[:32]

        payload = json.dumps({
            "tid": token_id,
            "cid": client_id,
            "scope": sorted(requested_scopes),
            "exp": time.time() + ttl_seconds
        }, sort_keys=True, separators=(",", ":")).encode()

        signature = hmac.new(self._server_secret, payload, hashlib.sha256).digest()

        token = OAuthToken(
            token_id=token_id,
            client_id=client_id,
            scope=requested_scopes,
            expires_at=time.time() + ttl_seconds,
            signature=signature
        )

        self._issued_tokens[token_id] = {
            "client_id": client_id,
            "scope": requested_scopes,
            "expires_at": token.expires_at
        }

        return token

    def verify_token(self, token: OAuthToken) -> bool:
        """Verify an OAuth token."""
        # Check revocation (centralized — immediate)
        if token.token_id in self._revoked_tokens:
            return False

        # Check expiry
        if time.time() > token.expires_at:
            return False

        # Verify HMAC signature
        payload = json.dumps({
            "tid": token.token_id,
            "cid": token.client_id,
            "scope": sorted(token.scope),
            "exp": token.expires_at
        }, sort_keys=True, separators=(",", ":")).encode()

        expected_sig = hmac.new(self._server_secret, payload, hashlib.sha256).digest()
        return hmac.compare_digest(token.signature, expected_sig)

    def revoke_token(self, token_id: str):
        """Revoke a token — immediate, no propagation delay."""
        self._revoked_tokens.add(token_id)

    def check_scope(self, token: OAuthToken, required_action: str) -> bool:
        """Check if a token authorizes a specific action."""
        return required_action in token.scope
