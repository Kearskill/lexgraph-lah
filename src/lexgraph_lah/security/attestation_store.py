"""Backward-compatible re-export shim for `lexgraph_lah.security.attestation_ledger`."""

from lexgraph_lah.security.attestation_ledger import (
    GENESIS_CHAIN_HASH,
    AttestationLedger,
    AttestationSigner,
    AttestationStorageBackend,
    Ed25519AttestationSigner,
    PostgresAttestationBackend,
    SQLiteAttestationBackend,
    build_chain_tip_signing_message,
    compute_chain_hash,
    compute_manifest_sha256,
    default_attestation_ledger,
)

__all__ = [
    "GENESIS_CHAIN_HASH",
    "AttestationLedger",
    "AttestationSigner",
    "AttestationStorageBackend",
    "Ed25519AttestationSigner",
    "PostgresAttestationBackend",
    "SQLiteAttestationBackend",
    "build_chain_tip_signing_message",
    "compute_chain_hash",
    "compute_manifest_sha256",
    "default_attestation_ledger",
]
