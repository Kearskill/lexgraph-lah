"""
Idempotent Federal Gazette (`P.U. (A)` / `P.U. (B)`) JSON/XML schema validator and
CLI/API ingestor for `TemporalGraphStore` (memory and Neo4j backends).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from lexgraph_lah.graph.temporal_store import (
    TemporalGraphStore,
    create_temporal_store,
    get_default_temporal_store,
)
from lexgraph_lah.schemas.domain import (
    AuthorityTier,
    DeonticConstraint,
    HierarchyLevel,
    SourceSpan,
    StatutoryNode,
    TerritorialScope,
)

_GAZETTE_REF_RE = re.compile(
    r"^(?:P\.U\.\s*\([AB]\)\s*\d+/\d{4}|Act\s+A?\d+|Akta\s+A?\d+)(?:\s.*)?$",
    re.IGNORECASE,
)


class GazetteProvisionSpec(BaseModel):
    """Schema for an individual gazetted statutory/subsidiary provision."""

    node_id: str = Field(..., min_length=3)
    section_code: str = Field(..., min_length=1)
    text: str = Field(..., min_length=1)
    language: str = Field(default="en")
    version: int = Field(default=1, ge=1)
    hierarchy_level: HierarchyLevel = Field(default=HierarchyLevel.SECTION)
    parent_node_id: str | None = None
    amends_node_id: str | None = None
    repeals_node_id: str | None = None
    bilingual_pair_id: str | None = None
    authoritative_language: bool = True
    cites_node_ids: list[str] = Field(default_factory=list)
    territorial_scope: list[TerritorialScope] = Field(
        default_factory=lambda: [TerritorialScope.ALL_MALAYSIA]
    )
    deontic_constraints: list[DeonticConstraint] = Field(default_factory=list)
    carve_out_metadata: dict[str, Any] | None = None
    source_uri: str = ""
    pdf_page: int = Field(default=1, ge=1)


class GazetteInstrumentPayload(BaseModel):
    """Structured Federal Gazette (`P.U. (A)` / `P.U. (B)`) ingestion payload."""

    gazette_ref: str = Field(..., min_length=3)
    act_name: str = Field(..., min_length=2)
    act_number: str = Field(..., min_length=2)
    gazette_date: date
    effective_from: date
    effective_to: date | None = None
    regime_code: str = Field(default="ACT_709")
    authority_tier: AuthorityTier = Field(
        default=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION
    )
    provisions: list[GazetteProvisionSpec] = Field(..., min_length=1)

    @field_validator("gazette_ref")
    @classmethod
    def _validate_gazette_ref(cls, value: str) -> str:
        cleaned = value.strip()
        if not _GAZETTE_REF_RE.match(cleaned):
            raise ValueError(
                f"Invalid Malaysian gazette_ref '{value}': expected P.U. (A) N/YYYY, P.U. (B) N/YYYY, or Act/Akta ref."
            )
        return cleaned


class GazetteIngestionResult(BaseModel):
    """Idempotent ingestion summary emitted by `ingest_gazette_instrument`."""

    gazette_ref: str
    inserted_node_ids: list[str] = Field(default_factory=list)
    updated_node_ids: list[str] = Field(default_factory=list)
    skipped_unchanged_node_ids: list[str] = Field(default_factory=list)
    repealed_node_ids: list[str] = Field(default_factory=list)
    edges_recorded: int = 0


def parse_gazette_json(raw: str | bytes) -> GazetteInstrumentPayload:
    """Validates and parses a JSON gazette payload into `GazetteInstrumentPayload`."""
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    data = json.loads(text)
    return GazetteInstrumentPayload.model_validate(data)


def parse_gazette_xml(raw: str | bytes) -> GazetteInstrumentPayload:
    """Validates and parses a structured XML gazette payload into `GazetteInstrumentPayload`."""
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    root = ET.fromstring(text)
    if root.tag not in {"gazette_instrument", "GazetteInstrument"}:
        raise ValueError(f"Unexpected XML root tag '{root.tag}' for gazette payload.")

    def _req_text(elem: ET.Element, tag: str) -> str:
        child = elem.find(tag)
        if child is None or child.text is None or not child.text.strip():
            raise ValueError(
                f"Missing required XML element <{tag}> in gazette payload."
            )
        return child.text.strip()

    def _opt_text(elem: ET.Element, tag: str) -> str | None:
        child = elem.find(tag)
        if child is None or child.text is None:
            return None
        val = child.text.strip()
        return val or None

    provisions: list[GazetteProvisionSpec] = []
    prov_container = root.find("provisions")
    prov_elems = (
        list(prov_container.findall("provision"))
        if prov_container is not None
        else list(root.findall("provision"))
    )
    for pe in prov_elems:
        constraints: list[DeonticConstraint] = []
        c_container = pe.find("deontic_constraints")
        if c_container is not None:
            for ce in c_container.findall("constraint"):
                raw_val = _req_text(ce, "threshold_value")
                parsed_val: float | str | bool
                if raw_val.lower() in {"true", "false"}:
                    parsed_val = raw_val.lower() == "true"
                else:
                    try:
                        parsed_val = float(raw_val)
                    except ValueError:
                        parsed_val = raw_val
                op_raw = _opt_text(ce, "operator") or "<="
                mod_raw = _opt_text(ce, "modality") or "OBLIGATION"
                constraints.append(
                    DeonticConstraint(
                        constraint_id=_opt_text(ce, "constraint_id") or "",
                        regime_id=_opt_text(ce, "regime_id")
                        or _opt_text(root, "regime_code")
                        or "ACT_709",
                        modality=mod_raw,  # type: ignore[arg-type]
                        metric_key=_req_text(ce, "metric_key"),
                        operator=op_raw,  # type: ignore[arg-type]
                        threshold_value=parsed_val,
                        unit=_opt_text(ce, "unit") or "",
                        recipient=_opt_text(ce, "recipient"),
                        notice_stage=_opt_text(ce, "notice_stage"),
                        description=_opt_text(ce, "description") or "",
                    )
                )

        cites = [
            c.text.strip()
            for c in pe.findall("cites/node_id")
            if c.text and c.text.strip()
        ]
        scopes = [
            TerritorialScope(s.text.strip())
            for s in pe.findall("territorial_scope/scope")
            if s.text and s.text.strip()
        ] or [TerritorialScope.ALL_MALAYSIA]

        provisions.append(
            GazetteProvisionSpec(
                node_id=_req_text(pe, "node_id"),
                section_code=_req_text(pe, "section_code"),
                text=_req_text(pe, "text"),
                language=_opt_text(pe, "language") or "en",
                version=int(_opt_text(pe, "version") or "1"),
                hierarchy_level=HierarchyLevel(
                    _opt_text(pe, "hierarchy_level") or "Section"
                ),
                parent_node_id=_opt_text(pe, "parent_node_id"),
                amends_node_id=_opt_text(pe, "amends_node_id"),
                repeals_node_id=_opt_text(pe, "repeals_node_id"),
                bilingual_pair_id=_opt_text(pe, "bilingual_pair_id"),
                authoritative_language=(
                    (_opt_text(pe, "authoritative_language") or "true").lower()
                    == "true"
                ),
                cites_node_ids=cites,
                territorial_scope=scopes,
                deontic_constraints=constraints,
                source_uri=_opt_text(pe, "source_uri") or "",
                pdf_page=int(_opt_text(pe, "pdf_page") or "1"),
            )
        )

    eff_to_raw = _opt_text(root, "effective_to")
    tier_raw = _opt_text(root, "authority_tier")
    return GazetteInstrumentPayload(
        gazette_ref=_req_text(root, "gazette_ref"),
        act_name=_req_text(root, "act_name"),
        act_number=_req_text(root, "act_number"),
        gazette_date=date.fromisoformat(_req_text(root, "gazette_date")),
        effective_from=date.fromisoformat(_req_text(root, "effective_from")),
        effective_to=date.fromisoformat(eff_to_raw) if eff_to_raw else None,
        regime_code=_opt_text(root, "regime_code") or "ACT_709",
        authority_tier=AuthorityTier(int(tier_raw))
        if tier_raw
        else AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        provisions=provisions,
    )


def ingest_gazette_instrument(
    payload: GazetteInstrumentPayload,
    store: TemporalGraphStore | None = None,
) -> GazetteIngestionResult:
    """
    Idempotently ingests a validated `GazetteInstrumentPayload` into `store`.
    Re-ingesting identical provision content leaves existing nodes and edge counts unchanged.
    """
    target_store = store or get_default_temporal_store()
    inserted: list[str] = []
    updated: list[str] = []
    skipped: list[str] = []
    repealed: list[str] = []
    edges_before = len(target_store.edges)

    for spec in payload.provisions:
        clean_text = spec.text.strip()
        content_hash = hashlib.sha256(clean_text.encode("utf-8")).hexdigest()
        existing = target_store.nodes.get(spec.node_id)

        if (
            existing is not None
            and existing.content_hash == content_hash
            and existing.gazette_ref == payload.gazette_ref
            and existing.effective_from == payload.effective_from
            and existing.effective_to == payload.effective_to
            and existing.deontic_constraints == spec.deontic_constraints
        ):
            skipped.append(spec.node_id)
            continue

        span = SourceSpan(
            span_id=f"SPAN-{spec.node_id}",
            doc_id=payload.act_number.lower().replace(" ", "-"),
            source_uri=spec.source_uri
            or f"https://lom.agc.gov.my/ilims/{spec.node_id.lower()}",
            act_number=payload.act_number,
            section_id=spec.section_code,
            canonical_citation=f"{payload.gazette_ref} {spec.section_code}".strip(),
            language=spec.language,
            pdf_page=spec.pdf_page,
            start_char=0,
            end_char=max(1, len(clean_text)),
            content_sha256=content_hash,
            text=spec.text,
        )
        node = StatutoryNode(
            node_id=spec.node_id,
            act_name=payload.act_name,
            act_number=payload.act_number,
            section_code=spec.section_code,
            version=spec.version,
            hierarchy_level=spec.hierarchy_level,
            parent_node_id=spec.parent_node_id,
            language=spec.language,
            authoritative_language=spec.authoritative_language,
            text=spec.text,
            valid_from=payload.effective_from,
            effective_from=payload.effective_from,
            effective_to=payload.effective_to,
            gazette_ref=payload.gazette_ref,
            gazette_date=payload.gazette_date,
            authority_tier=payload.authority_tier,
            territorial_scope=spec.territorial_scope,
            regime_code=payload.regime_code,
            deontic_constraints=spec.deontic_constraints,
            carve_out_metadata=spec.carve_out_metadata,
            source_spans=[span],
        )
        target_store.upsert_node(node, amends_node_id=spec.amends_node_id)
        if existing is None:
            inserted.append(spec.node_id)
        else:
            updated.append(spec.node_id)

        if spec.repeals_node_id and spec.repeals_node_id in target_store.nodes:
            target_store.repeal_node(
                target_node_id=spec.repeals_node_id,
                repealing_node_id=spec.node_id,
                effective_date=payload.effective_from,
                gazette_ref=payload.gazette_ref,
            )
            repealed.append(spec.repeals_node_id)

        for cite_id in spec.cites_node_ids:
            target_store.add_citation(
                source_id=spec.node_id,
                target_id=cite_id,
                effective_date=payload.effective_from,
                gazette_ref=payload.gazette_ref,
            )

        if spec.bilingual_pair_id and spec.bilingual_pair_id in target_store.nodes:
            partner = target_store.nodes[spec.bilingual_pair_id]
            if node.normalized_language == "en":
                en_id, bm_id = node.node_id, partner.node_id
            else:
                en_id, bm_id = partner.node_id, node.node_id
            auth_id = node.node_id if spec.authoritative_language else partner.node_id
            target_store.link_translation(
                en_node_id=en_id,
                bm_node_id=bm_id,
                authoritative_node_id=auth_id,
                effective_date=payload.effective_from,
                gazette_ref=payload.gazette_ref,
            )

    return GazetteIngestionResult(
        gazette_ref=payload.gazette_ref,
        inserted_node_ids=inserted,
        updated_node_ids=updated,
        skipped_unchanged_node_ids=skipped,
        repealed_node_ids=repealed,
        edges_recorded=len(target_store.edges) - edges_before,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Idempotent Malaysian Federal Gazette (P.U. (A)/P.U. (B)) Ingestor CLI"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to JSON or XML gazette instrument file.",
    )
    parser.add_argument(
        "--backend",
        choices=["memory", "neo4j"],
        default="memory",
        help="Graph backend target (default: memory).",
    )
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    raw = input_path.read_text(encoding="utf-8")
    if input_path.suffix.lower() == ".xml" or raw.lstrip().startswith("<"):
        payload = parse_gazette_xml(raw)
    else:
        payload = parse_gazette_json(raw)

    store = create_temporal_store(backend_mode=args.backend, seed_defaults=True)
    result = ingest_gazette_instrument(payload, store=store)
    print(result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
