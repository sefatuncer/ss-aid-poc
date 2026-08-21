"""
SS-AID PoC — Identity Module
DID generation, Ed25519 key management, DID Document creation.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder


@dataclass
class AgentIdentity:
    """Represents an agent's decentralized identity."""
    did: str
    signing_key: SigningKey
    verify_key: VerifyKey
    did_document: dict
    created_at: float = field(default_factory=time.time)

    def sign(self, message: bytes) -> bytes:
        return self.signing_key.sign(message).signature

    def public_key_hex(self) -> str:
        return self.verify_key.encode(encoder=HexEncoder).decode()


def generate_did_key() -> AgentIdentity:
    """Generate a did:key identity with Ed25519 keypair."""
    sk = SigningKey.generate()
    vk = sk.verify_key
    pk_hex = vk.encode(encoder=HexEncoder).decode()
    did = f"did:key:z6Mk{pk_hex[:32]}"

    did_document = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "authentication": [{
            "id": f"{did}#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyHex": pk_hex
        }],
        "service": []
    }

    return AgentIdentity(
        did=did,
        signing_key=sk,
        verify_key=vk,
        did_document=did_document
    )


def generate_did_web(domain: str, agent_id: str) -> AgentIdentity:
    """Generate a did:web identity with Ed25519 keypair."""
    sk = SigningKey.generate()
    vk = sk.verify_key
    pk_hex = vk.encode(encoder=HexEncoder).decode()
    did = f"did:web:{domain}:{agent_id}"

    did_document = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "authentication": [{
            "id": f"{did}#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyHex": pk_hex
        }],
        "service": [{
            "id": f"{did}#didcomm",
            "type": "DIDCommMessaging",
            "serviceEndpoint": f"https://{domain}/agents/{agent_id}/didcomm"
        }]
    }

    return AgentIdentity(
        did=did,
        signing_key=sk,
        verify_key=vk,
        did_document=did_document
    )


class DIDRegistry:
    """Simulated decentralized identity network (N)."""

    def __init__(self):
        self._registry: dict[str, dict] = {}
        self._resolve_count = 0

    def register(self, identity: AgentIdentity):
        self._registry[identity.did] = {
            "document": identity.did_document,
            "registered_at": time.time(),
            "active": True
        }

    def resolve(self, did: str) -> Optional[dict]:
        self._resolve_count += 1
        entry = self._registry.get(did)
        if entry and entry["active"]:
            return entry["document"]
        return None

    def deactivate(self, did: str):
        if did in self._registry:
            self._registry[did]["active"] = False

    def verify_signature(self, did: str, message: bytes, signature: bytes) -> bool:
        doc = self.resolve(did)
        if not doc:
            return False
        pk_hex = doc["authentication"][0]["publicKeyHex"]
        vk = VerifyKey(bytes.fromhex(pk_hex))
        try:
            vk.verify(message, signature)
            return True
        except Exception:
            return False
