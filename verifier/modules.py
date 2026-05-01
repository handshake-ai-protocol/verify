"""Embedded compliance-module catalog.

Mirrors the Registry's :mod:`handshake_registry.evidence.modules`. We
duplicate the metadata so the verifier is self-contained: an auditor
holding only the pack zip can re-run the assertions without any
Registry connection.

The verifier asserts the pack only contains receipts whose ``action``
matches one of the module's capability prefixes. Anything else means
either (a) the assembler is buggy, or (b) the pack was tampered with.
"""

from __future__ import annotations

from dataclasses import dataclass, field


_AGENT_CALL_PATTERNS = (
    "anthropic.",
    "openai.",
    "langgraph.",
    "agent.",
    "provider.compute",
)
_OPERATOR_PATTERNS = ("operator.",)
_POLICY_PATTERNS = ("policy.", "human.oversight")
_PHI_PATTERNS = ("data.read.phi", "data.write.phi")
_CHD_PATTERNS = ("data.read.cardholder", "data.write.cardholder")
_NPI_PATTERNS = ("data.read.npi", "data.write.npi")
_REGISTRY_WRITE_PATTERNS = ("registry:write", "registry.")


@dataclass(frozen=True)
class ModuleSpec:
    id: str
    name: str
    capability_patterns: tuple[str, ...]
    forbidden_patterns: tuple[str, ...] = field(default=())

    def matches(self, action: str) -> bool:
        return any(action == p or action.startswith(p) for p in self.capability_patterns)

    def is_forbidden(self, action: str) -> bool:
        if not self.forbidden_patterns:
            return False
        return any(action == p or action.startswith(p) for p in self.forbidden_patterns)


MODULES: dict[str, ModuleSpec] = {
    "soc2": ModuleSpec(
        id="soc2",
        name="SOC 2 Type II",
        capability_patterns=_AGENT_CALL_PATTERNS
        + _OPERATOR_PATTERNS
        + _POLICY_PATTERNS
        + _REGISTRY_WRITE_PATTERNS,
    ),
    "eu_ai_act": ModuleSpec(
        id="eu_ai_act",
        name="EU AI Act",
        capability_patterns=_AGENT_CALL_PATTERNS
        + _POLICY_PATTERNS
        + _OPERATOR_PATTERNS,
    ),
    "hipaa": ModuleSpec(
        id="hipaa",
        name="HIPAA Security Rule",
        capability_patterns=_PHI_PATTERNS + _OPERATOR_PATTERNS + _POLICY_PATTERNS,
    ),
    "pci_dss": ModuleSpec(
        id="pci_dss",
        name="PCI-DSS v4.0",
        capability_patterns=_CHD_PATTERNS + _OPERATOR_PATTERNS + _POLICY_PATTERNS,
    ),
    "glba": ModuleSpec(
        id="glba",
        name="GLBA Safeguards Rule",
        capability_patterns=_NPI_PATTERNS + _OPERATOR_PATTERNS + _POLICY_PATTERNS,
    ),
    "nist_ai_rmf": ModuleSpec(
        id="nist_ai_rmf",
        name="NIST AI Risk Management Framework",
        capability_patterns=_AGENT_CALL_PATTERNS
        + _POLICY_PATTERNS
        + _OPERATOR_PATTERNS,
    ),
    "iso_27001": ModuleSpec(
        id="iso_27001",
        name="ISO/IEC 27001:2022",
        capability_patterns=_AGENT_CALL_PATTERNS
        + _OPERATOR_PATTERNS
        + _POLICY_PATTERNS
        + _REGISTRY_WRITE_PATTERNS,
    ),
    "fedramp_moderate": ModuleSpec(
        id="fedramp_moderate",
        name="FedRAMP Moderate (NIST 800-53 Rev 5)",
        capability_patterns=_AGENT_CALL_PATTERNS
        + _OPERATOR_PATTERNS
        + _POLICY_PATTERNS
        + _REGISTRY_WRITE_PATTERNS,
    ),
}


def get_module(module_id: str) -> ModuleSpec:
    if module_id not in MODULES:
        raise KeyError(f"unknown module: {module_id}")
    return MODULES[module_id]


def module_catalog_hash_hex(module_id: str) -> str:
    """SHA-256 over the JCS-canonical ModuleSpec for ``module_id``.

    Mirrors :func:`handshake_registry.evidence.modules.module_catalog_hash_hex`
    byte-for-byte; both implementations canonicalize the same four fields
    (``id``, ``name``, ``capability_patterns``, ``forbidden_patterns``)
    with the same RFC 8259 / JCS-style separators. The verifier asserts
    the manifest's ``module_catalog_hash_hex`` equals this value. Any
    drift (Registry catalog changed, verifier not re-shipped) raises
    ``module_catalog_drift`` rather than silently applying a stale rule.
    """
    import hashlib
    import json

    spec = get_module(module_id)
    payload = {
        "id": spec.id,
        "name": spec.name,
        "capability_patterns": list(spec.capability_patterns),
        "forbidden_patterns": list(spec.forbidden_patterns),
    }
    canonical = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
