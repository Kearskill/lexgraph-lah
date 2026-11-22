import difflib
import re
from datetime import date
from typing import TYPE_CHECKING, Any, Literal

from lexgraph_lah.ingestion.contract_ast import extract_numeric_sla_from_text
from lexgraph_lah.middleware.pii_scrubber import scrub_malaysian_pii
from lexgraph_lah.schemas.domain import (
    DEFAULT_LEGAL_DISCLAIMER,
    ClauseDiffSegment,
    ContractDeltaAuditRequest,
    ContractDeltaAuditResponse,
    ContractDeltaFinding,
    PDPAComplianceScanRequest,
    PDPAGapItem,
    RiskSeverity,
    StatutoryNode,
    StatutoryStatus,
    StatutoryTransitionStep,
    StatutoryVersionDiff,
    TemporalEdgeType,
    TerritorialScope,
)
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary
from lexgraph_lah.telemetry.tracer import measure_latency_ms

if TYPE_CHECKING:
    from lexgraph_lah.graph.temporal_store import TemporalGraphStore

_SEVERITY_RANK: dict[RiskSeverity, int] = {
    RiskSeverity.LOW: 1,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.HIGH: 3,
    RiskSeverity.CRITICAL: 4,
}

_ABBREV_PROTECTION: tuple[tuple[str, str], ...] = (
    ("P.U.", "P__U__"),
    ("p.u.", "p__u__"),
    ("Cap.", "Cap__"),
    ("Art.", "Art__"),
    ("Reg.", "Reg__"),
    ("Sek.", "Sek__"),
    ("Sec.", "Sec__"),
    ("ss.", "ss__"),
    ("s.", "s__"),
    ("No.", "No__"),
)


def _split_clauses(text: str) -> list[str]:
    clean = text.strip()
    if not clean:
        return []
    masked = clean
    for raw_abbr, token in _ABBREV_PROTECTION:
        masked = masked.replace(raw_abbr, token)
    parts = [p.strip() for p in re.split(r"(?<=[.;?!])\s+|\n+", masked) if p.strip()]
    restored: list[str] = []
    for p in parts:
        item = p
        for raw_abbr, token in _ABBREV_PROTECTION:
            item = item.replace(token, raw_abbr)
        restored.append(item)
    return restored


def _resolve_seed_node(store: "TemporalGraphStore", provision_id: str) -> StatutoryNode:
    nodes = store.nodes
    if provision_id in nodes:
        return nodes[provision_id]
    low = provision_id.strip().lower()
    for nid, node in nodes.items():
        if nid.lower() == low:
            return node
    raise KeyError(
        f"Statutory provision '{provision_id}' not found in TemporalGraphStore."
    )


def _collect_same_provision_versions(
    store: "TemporalGraphStore",
    seed: StatutoryNode,
) -> list[StatutoryNode]:
    """
    Collects all historical/successor StatutoryNodes representing versions of the same
    provision (excluding unrelated repealing Acts linked solely via REPEALED_BY).
    """
    amend_edges = {
        TemporalEdgeType.AMENDED_BY,
        TemporalEdgeType.SUPERSEDED_BY,
        TemporalEdgeType.AMENDS,
    }
    visited: set[str] = {seed.node_id}
    queue: list[str] = [seed.node_id]
    edges = store.edges
    nodes = store.nodes

    while queue:
        cur = queue.pop(0)
        for edge in edges:
            if edge.edge_type not in amend_edges:
                continue
            if (
                edge.source_id == cur
                and edge.target_id in nodes
                and edge.target_id not in visited
            ):
                visited.add(edge.target_id)
                queue.append(edge.target_id)
            elif (
                edge.target_id == cur
                and edge.source_id in nodes
                and edge.source_id not in visited
            ):
                visited.add(edge.source_id)
                queue.append(edge.source_id)

    for nid, candidate in nodes.items():
        if (
            candidate.act_number == seed.act_number
            and candidate.section_code == seed.section_code
            and candidate.normalized_language == seed.normalized_language
            and candidate.hierarchy_level == seed.hierarchy_level
        ):
            visited.add(nid)

    return sorted(
        (nodes[nid] for nid in visited),
        key=lambda n: (n.version, n.effective_from or n.valid_from, n.node_id),
    )


def _active_version_on(
    store: "TemporalGraphStore",
    versions: list[StatutoryNode],
    target_date: date,
) -> StatutoryNode | None:
    active = [n for n in versions if store._is_node_valid_on(n, target_date)]
    if not active:
        return None
    active.sort(
        key=lambda n: (n.version, n.effective_from or n.valid_from), reverse=True
    )
    return active[0]


def _collect_related_gazettes(
    store: "TemporalGraphStore",
    version_nodes: list[StatutoryNode],
    transitions: list[StatutoryTransitionStep],
    from_date: date,
    to_date: date,
) -> list[str]:
    gazettes: list[str] = []
    seen: set[str] = set()

    def _add(ref: str | None) -> None:
        if ref and ref.strip() and ref.strip() not in seen:
            seen.add(ref.strip())
            gazettes.append(ref.strip())

    version_ids = {n.node_id for n in version_nodes}
    act_numbers = {n.act_number for n in version_nodes}

    for n in version_nodes:
        eff_from = n.effective_from or n.valid_from
        if from_date < eff_from <= to_date or n.is_active_on(to_date):
            _add(n.gazette_ref or n.amendment_act_ref)

    for tr in transitions:
        _add(tr.gazette_ref)

    for edge in store.edges:
        if (
            edge.source_id in version_ids
            and edge.edge_type == TemporalEdgeType.CITES
            and edge.effective_date <= to_date
        ):
            target = store.nodes.get(edge.target_id)
            if target:
                _add(target.gazette_ref or target.act_number)
            _add(edge.gazette_ref)

    # Also capture P.U. (A) / P.U. (B) commencement gazettes for the same regime commencing in window
    regimes = {n.regime_code for n in version_nodes if n.regime_code}
    for cand in store.nodes.values():
        eff = cand.effective_from or cand.valid_from
        if (
            from_date < eff <= to_date
            and (
                cand.act_number.startswith("P.U.")
                or (cand.gazette_ref or "").startswith("P.U.")
            )
            and (cand.regime_code in regimes or cand.act_number in act_numbers)
        ):
            _add(cand.gazette_ref or cand.act_number)

    return gazettes


def diff_statute_lineage(
    provision_id: str,
    from_date: date,
    to_date: date,
    store: "TemporalGraphStore | None" = None,
) -> StatutoryVersionDiff:
    """
    Zero-token deterministic bi-temporal statutory diff engine comparing `provision_id`
    across `AMENDED_BY` / `SUPERSEDED_BY` / `REPEALED_BY` chains between `from_date`
    and `to_date` ($0.00 USD / RM 0.00 MYR).
    """
    if from_date > to_date:
        raise ValueError(
            f"from_date ({from_date.isoformat()}) must be on or before to_date ({to_date.isoformat()})."
        )

    if store is None:
        from lexgraph_lah.graph.temporal_store import get_default_temporal_store

        store = get_default_temporal_store()

    with measure_latency_ms() as elapsed_holder:
        seed = _resolve_seed_node(store, provision_id)
        versions = _collect_same_provision_versions(store, seed)
        version_ids = {n.node_id for n in versions}

        from_node = _active_version_on(store, versions, from_date)
        to_node = _active_version_on(store, versions, to_date)

        # Collect transitions inside (from_date, to_date]
        transition_edge_types = {
            TemporalEdgeType.AMENDED_BY,
            TemporalEdgeType.SUPERSEDED_BY,
            TemporalEdgeType.REPEALED_BY,
        }
        transitions: list[StatutoryTransitionStep] = []
        seen_tr: set[tuple[str, str, str, date]] = set()
        for edge in store.edges:
            if (
                edge.source_id in version_ids
                and edge.edge_type in transition_edge_types
                and from_date < edge.effective_date <= to_date
            ):
                key = (
                    edge.source_id,
                    edge.target_id,
                    edge.edge_type.value,
                    edge.effective_date,
                )
                if key not in seen_tr:
                    seen_tr.add(key)
                    transitions.append(
                        StatutoryTransitionStep(
                            source_node_id=edge.source_id,
                            target_node_id=edge.target_id,
                            edge_type=edge.edge_type,
                            effective_date=edge.effective_date,
                            gazette_ref=edge.gazette_ref,
                        )
                    )
        transitions.sort(
            key=lambda t: (t.effective_date, t.edge_type.value, t.source_node_id)
        )

        transition_dates_set: set[date] = {t.effective_date for t in transitions}
        for v in versions:
            v_eff = v.effective_from or v.valid_from
            if from_date < v_eff <= to_date:
                transition_dates_set.add(v_eff)
        transition_dates = sorted(transition_dates_set)

        has_repeal_transition = any(
            t.edge_type == TemporalEdgeType.REPEALED_BY for t in transitions
        ) or any(
            store._is_repealed_on_or_before(n.node_id, to_date)
            and not store._is_repealed_on_or_before(n.node_id, from_date)
            for n in versions
        )

        change_status: Literal[
            "UNCHANGED",
            "AMENDED",
            "NEWLY_ENACTED",
            "REPEALED",
            "NOT_IN_FORCE",
        ]
        if from_node is None and to_node is None:
            change_status = "REPEALED" if has_repeal_transition else "NOT_IN_FORCE"
        elif from_node is None and to_node is not None:
            change_status = "NEWLY_ENACTED"
        elif from_node is not None and to_node is None:
            change_status = "REPEALED"
        elif from_node is not None and to_node is not None:
            if from_node.node_id == to_node.node_id and from_node.text == to_node.text:
                change_status = "UNCHANGED"
            else:
                change_status = "AMENDED"
        else:
            change_status = "NOT_IN_FORCE"

        from_text = from_node.text if from_node else ""
        to_text = to_node.text if to_node else ""
        from_spans = list(from_node.source_spans) if from_node else []
        to_spans = list(to_node.source_spans) if to_node else []
        from_span_id = from_spans[0].span_id if from_spans else None
        to_span_id = to_spans[0].span_id if to_spans else None

        from_clauses = _split_clauses(from_text)
        to_clauses = _split_clauses(to_text)

        added_clauses: list[str] = []
        removed_clauses: list[str] = []
        modified_clauses: list[ClauseDiffSegment] = []
        unified_redline: list[ClauseDiffSegment] = []

        matcher = difflib.SequenceMatcher(None, from_clauses, to_clauses)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                for idx in range(i2 - i1):
                    fc = from_clauses[i1 + idx]
                    tc = to_clauses[j1 + idx]
                    unified_redline.append(
                        ClauseDiffSegment(
                            change_type="UNCHANGED",
                            from_text=fc,
                            to_text=tc,
                            from_span_id=from_span_id,
                            to_span_id=to_span_id,
                        )
                    )
            elif tag == "delete":
                for fc in from_clauses[i1:i2]:
                    removed_clauses.append(fc)
                    unified_redline.append(
                        ClauseDiffSegment(
                            change_type="REMOVED",
                            from_text=fc,
                            to_text="",
                            from_span_id=from_span_id,
                            to_span_id=None,
                        )
                    )
            elif tag == "insert":
                for tc in to_clauses[j1:j2]:
                    added_clauses.append(tc)
                    unified_redline.append(
                        ClauseDiffSegment(
                            change_type="ADDED",
                            from_text="",
                            to_text=tc,
                            from_span_id=None,
                            to_span_id=to_span_id,
                        )
                    )
            elif tag == "replace":
                del_slice = from_clauses[i1:i2]
                ins_slice = to_clauses[j1:j2]
                common_len = min(len(del_slice), len(ins_slice))
                for idx in range(common_len):
                    fc = del_slice[idx]
                    tc = ins_slice[idx]
                    sim = difflib.SequenceMatcher(None, fc.lower(), tc.lower()).ratio()
                    if sim >= 0.40:
                        seg = ClauseDiffSegment(
                            change_type="MODIFIED",
                            from_text=fc,
                            to_text=tc,
                            from_span_id=from_span_id,
                            to_span_id=to_span_id,
                        )
                        modified_clauses.append(seg)
                        unified_redline.append(seg)
                    else:
                        removed_clauses.append(fc)
                        added_clauses.append(tc)
                        unified_redline.append(
                            ClauseDiffSegment(
                                change_type="REMOVED",
                                from_text=fc,
                                to_text="",
                                from_span_id=from_span_id,
                                to_span_id=None,
                            )
                        )
                        unified_redline.append(
                            ClauseDiffSegment(
                                change_type="ADDED",
                                from_text="",
                                to_text=tc,
                                from_span_id=None,
                                to_span_id=to_span_id,
                            )
                        )
                for fc in del_slice[common_len:]:
                    removed_clauses.append(fc)
                    unified_redline.append(
                        ClauseDiffSegment(
                            change_type="REMOVED",
                            from_text=fc,
                            to_text="",
                            from_span_id=from_span_id,
                            to_span_id=None,
                        )
                    )
                for tc in ins_slice[common_len:]:
                    added_clauses.append(tc)
                    unified_redline.append(
                        ClauseDiffSegment(
                            change_type="ADDED",
                            from_text="",
                            to_text=tc,
                            from_span_id=None,
                            to_span_id=to_span_id,
                        )
                    )

        related_gazettes = _collect_related_gazettes(
            store=store,
            version_nodes=versions,
            transitions=transitions,
            from_date=from_date,
            to_date=to_date,
        )

    telemetry = compute_telemetry_summary(
        prompt_tokens=0,
        completion_tokens=0,
        latency_ms=elapsed_holder[0],
        retry_count=0,
        is_verified_grounded=True,
        trace_id=f"diff-{seed.node_id.lower()}",
    )

    from_status = (
        StatutoryStatus.REPEALED
        if from_node is None and has_repeal_transition
        else (from_node.status if from_node else None)
    )
    to_status = (
        StatutoryStatus.REPEALED
        if to_node is None and has_repeal_transition
        else (to_node.status if to_node else None)
    )

    return StatutoryVersionDiff(
        provision_id=seed.node_id,
        act_name=seed.act_name,
        act_number=seed.act_number,
        section_code=seed.section_code,
        language=seed.normalized_language,
        from_date=from_date,
        to_date=to_date,
        change_status=change_status,
        from_node_id=from_node.node_id if from_node else None,
        to_node_id=to_node.node_id if to_node else None,
        from_status=from_status,
        to_status=to_status,
        from_text=from_text,
        to_text=to_text,
        from_source_spans=from_spans,
        to_source_spans=to_spans,
        transition_dates=transition_dates,
        transitions=transitions,
        added_clauses=added_clauses,
        removed_clauses=removed_clauses,
        modified_clauses=modified_clauses,
        unified_redline=unified_redline,
        related_gazettes=related_gazettes,
        telemetry=telemetry,
        disclaimer=DEFAULT_LEGAL_DISCLAIMER,
    )


def _gap_map(gaps: list[PDPAGapItem]) -> dict[str, PDPAGapItem]:
    return {g.rule_id: g for g in gaps}


def compute_statutory_window_context(
    *,
    from_date: date,
    to_date: date,
    regimes: list[str] | None = None,
    act_filter: str | None = None,
    territorial_scope: TerritorialScope = TerritorialScope.ALL_MALAYSIA,
    store: "TemporalGraphStore | None" = None,
) -> dict[str, Any]:
    """
    Precomputes contract-independent bi-temporal statutory envelopes and intervening
    `diff_statute_lineage` changes across `(from_date, to_date]` for bulk portfolio scans.
    """
    if store is None:
        from lexgraph_lah.graph.temporal_store import get_default_temporal_store

        store = get_default_temporal_store()

    from lexgraph_lah.graph.deontic_solver import (
        DeonticEnvelopeResolver,
        normalize_regimes,
    )

    target_regimes = normalize_regimes(regimes) if regimes else ["ACT_709"]
    resolver = DeonticEnvelopeResolver(store)
    env_from = resolver.resolve(
        regimes=target_regimes,
        as_of_date=from_date,
        territorial_scope=territorial_scope,
    )
    env_to = resolver.resolve(
        regimes=target_regimes,
        as_of_date=to_date,
        territorial_scope=territorial_scope,
    )

    intervening_diffs: list[StatutoryVersionDiff] = []
    seen_diff_keys: set[tuple[str, str]] = set()
    newly_commenced_gazettes: list[str] = []
    seen_gazettes: set[str] = set()

    candidate_nodes = sorted(
        store.nodes.values(),
        key=lambda n: (
            n.normalized_language != "en",
            n.act_number,
            n.section_code,
            n.node_id,
        ),
    )
    for node in candidate_nodes:
        if node.normalized_language != "en":
            continue
        if act_filter and node.act_name != act_filter:
            continue
        if regimes and node.regime_code not in target_regimes:
            continue
        dedup_key = (node.act_number, node.section_code)
        if dedup_key in seen_diff_keys:
            continue
        seen_diff_keys.add(dedup_key)

        vdiff = diff_statute_lineage(
            provision_id=node.node_id,
            from_date=from_date,
            to_date=to_date,
            store=store,
        )
        if vdiff.change_status in {"AMENDED", "NEWLY_ENACTED", "REPEALED"}:
            intervening_diffs.append(vdiff)
            for g in vdiff.related_gazettes:
                if g not in seen_gazettes:
                    seen_gazettes.add(g)
                    newly_commenced_gazettes.append(g)

    return {
        "env_from": env_from,
        "env_to": env_to,
        "intervening_diffs": intervening_diffs,
        "newly_commenced_gazettes": newly_commenced_gazettes,
    }


def evaluate_contract_delta_impact(
    req: ContractDeltaAuditRequest,
    store: "TemporalGraphStore | None" = None,
    *,
    precomputed_window: dict[str, Any] | None = None,
) -> ContractDeltaAuditResponse:
    """
    Zero-token Contract Delta-Audit evaluator: compares contract compliance at `from_date`
    against `to_date` to determine whether intervening statutory amendments or P.U. gazette
    commencements render a previously compliant agreement non-compliant ($0.00 USD / RM 0.00 MYR).
    """
    if req.from_date > req.to_date:
        raise ValueError(
            f"from_date ({req.from_date.isoformat()}) must be on or before to_date ({req.to_date.isoformat()})."
        )

    if store is None:
        from lexgraph_lah.graph.temporal_store import get_default_temporal_store

        store = get_default_temporal_store()

    from lexgraph_lah.compliance.pdpa_scanner import scan_pdpa_compliance

    with measure_latency_ms() as elapsed_holder:
        pii_scrub = scrub_malaysian_pii(req.raw_text)
        safe_text = pii_scrub.masked_text

        scan_from = scan_pdpa_compliance(
            PDPAComplianceScanRequest(
                document_id=f"{req.document_id}-FROM",
                raw_text=safe_text,
                as_of_date=req.from_date,
                territorial_scope=req.territorial_scope,
                persona=req.persona,
            ),
            store=store,
            record_telemetry=False,
        )
        scan_to = scan_pdpa_compliance(
            PDPAComplianceScanRequest(
                document_id=f"{req.document_id}-TO",
                raw_text=safe_text,
                as_of_date=req.to_date,
                territorial_scope=req.territorial_scope,
                persona=req.persona,
            ),
            store=store,
            record_telemetry=False,
        )

        win = precomputed_window or compute_statutory_window_context(
            from_date=req.from_date,
            to_date=req.to_date,
            regimes=req.regimes,
            act_filter=req.act_filter,
            territorial_scope=req.territorial_scope,
            store=store,
        )
        env_from = win["env_from"]
        env_to = win["env_to"]
        intervening_diffs = list(win["intervening_diffs"])
        newly_commenced_gazettes = list(win["newly_commenced_gazettes"])

        delta_findings: list[ContractDeltaFinding] = []
        from_gaps = _gap_map(scan_from.gaps)
        to_gaps = _gap_map(scan_to.gaps)

        from_max_rank = _SEVERITY_RANK[scan_from.overall_risk]
        to_max_rank = _SEVERITY_RANK[scan_to.overall_risk]

        for rule_id, g_to in to_gaps.items():
            g_from = from_gaps.get(rule_id)
            if g_to.status == "COMPLIANT":
                continue

            if g_from is None:
                delta_findings.append(
                    ContractDeltaFinding(
                        rule_id=rule_id,
                        section_ref=g_to.section_ref,
                        impact_type="NEW_STATUTORY_MANDATE",
                        from_status="NOT_IN_FORCE",
                        to_status=g_to.status,
                        from_severity=None,
                        to_severity=g_to.severity,
                        exact_quote=g_to.exact_quote,
                        triggering_statute_ids=[
                            d.to_node_id for d in intervening_diffs if d.to_node_id
                        ][:3],
                        triggering_gazettes=[g_to.gazette_ref]
                        if g_to.gazette_ref
                        else [],
                        source_spans=list(g_to.source_spans),
                        explanation_practitioner=(
                            f"New statutory obligation ({g_to.section_ref}) commenced between "
                            f"{req.from_date.isoformat()} and {req.to_date.isoformat()}: {g_to.gap_description}"
                        ),
                        explanation_rakyat=(
                            f"A new Malaysian rule ({g_to.principle_name}) took effect after "
                            f"{req.from_date.isoformat()}, making this clause non-compliant today."
                        ),
                    )
                )
            elif g_from.status == "COMPLIANT" and g_to.status != "COMPLIANT":
                delta_findings.append(
                    ContractDeltaFinding(
                        rule_id=rule_id,
                        section_ref=g_to.section_ref,
                        impact_type="NEWLY_NON_COMPLIANT",
                        from_status=g_from.status,
                        to_status=g_to.status,
                        from_severity=g_from.severity,
                        to_severity=g_to.severity,
                        exact_quote=g_to.exact_quote,
                        triggering_statute_ids=[],
                        triggering_gazettes=[g_to.gazette_ref]
                        if g_to.gazette_ref
                        else [],
                        source_spans=list(g_to.source_spans),
                        explanation_practitioner=(
                            f"Clause compliant at {req.from_date.isoformat()} became {g_to.status} "
                            f"by {req.to_date.isoformat()} under {g_to.section_ref}."
                        ),
                        explanation_rakyat=(
                            f"This clause met the law on {req.from_date.isoformat()}, but updated rules "
                            f"now classify it as a compliance gap."
                        ),
                    )
                )
            elif _SEVERITY_RANK[g_to.severity] > _SEVERITY_RANK[g_from.severity]:
                delta_findings.append(
                    ContractDeltaFinding(
                        rule_id=rule_id,
                        section_ref=g_to.section_ref,
                        impact_type="SEVERITY_ESCALATED",
                        from_status=g_from.status,
                        to_status=g_to.status,
                        from_severity=g_from.severity,
                        to_severity=g_to.severity,
                        exact_quote=g_to.exact_quote,
                        triggering_statute_ids=[],
                        triggering_gazettes=[g_to.gazette_ref]
                        if g_to.gazette_ref
                        else [],
                        source_spans=list(g_to.source_spans),
                        explanation_practitioner=(
                            f"Exposure escalated from {g_from.severity.value} to {g_to.severity.value} "
                            f"under {g_to.section_ref} as of {req.to_date.isoformat()}."
                        ),
                        explanation_rakyat=(
                            f"Legal risk for {g_to.principle_name} increased from {g_from.severity.value} "
                            f"to {g_to.severity.value} under amended Malaysian law."
                        ),
                    )
                )

        # Evaluate multi-regime deontic SLA tightening (e.g. P.U. (A) 220/2024 6h rule commencing 2024-08-26)
        contract_h, contract_d = extract_numeric_sla_from_text(safe_text)
        if (
            "incident_notice_max_hours" in env_to.resolved_bounds
            and contract_h is not None
        ):
            bound_to = env_to.resolved_bounds["incident_notice_max_hours"]
            limit_to = float(bound_to.strictest_value)
            bound_from = env_from.resolved_bounds.get("incident_notice_max_hours")
            was_compliant_from = bound_from is None or contract_h <= float(
                bound_from.strictest_value
            )
            if contract_h > limit_to and was_compliant_from:
                to_max_rank = max(to_max_rank, _SEVERITY_RANK[RiskSeverity.HIGH])
                dom_node = store.nodes.get(bound_to.dominating_node_id)
                delta_findings.append(
                    ContractDeltaFinding(
                        rule_id=f"DELTA-{bound_to.dominating_regime}-NOTICE",
                        section_ref=bound_to.dominating_citation,
                        impact_type="NEW_STATUTORY_MANDATE",
                        from_status="COMPLIANT"
                        if bound_from is None
                        else f"WITHIN_{bound_from.strictest_value}H",
                        to_status="NON_COMPLIANT",
                        from_severity=RiskSeverity.LOW,
                        to_severity=RiskSeverity.HIGH,
                        exact_quote=safe_text,
                        triggering_statute_ids=[bound_to.dominating_node_id],
                        triggering_gazettes=[
                            g for g in [dom_node.gazette_ref if dom_node else None] if g
                        ],
                        source_spans=list(dom_node.source_spans) if dom_node else [],
                        explanation_practitioner=(
                            f"Contract SLA ({contract_h:g}h) satisfied {req.from_date.isoformat()}, but "
                            f"{bound_to.dominating_regime} ({bound_to.dominating_citation}) introduced "
                            f"strictest bound <= {limit_to:g}h by {req.to_date.isoformat()}."
                        ),
                        explanation_rakyat=(
                            f"Your {contract_h:g}-hour incident reporting deadline was acceptable on "
                            f"{req.from_date.isoformat()}, but newer rules require reporting within {limit_to:g} hours."
                        ),
                    )
                )

        if "full_report_max_days" in env_to.resolved_bounds and contract_d is not None:
            bound_d_to = env_to.resolved_bounds["full_report_max_days"]
            limit_d_to = float(bound_d_to.strictest_value)
            bound_d_from = env_from.resolved_bounds.get("full_report_max_days")
            was_d_ok = bound_d_from is None or contract_d <= float(
                bound_d_from.strictest_value
            )
            if contract_d > limit_d_to and was_d_ok:
                to_max_rank = max(to_max_rank, _SEVERITY_RANK[RiskSeverity.HIGH])
                dom_node = store.nodes.get(bound_d_to.dominating_node_id)
                delta_findings.append(
                    ContractDeltaFinding(
                        rule_id=f"DELTA-{bound_d_to.dominating_regime}-REPORT",
                        section_ref=bound_d_to.dominating_citation,
                        impact_type="NEW_STATUTORY_MANDATE",
                        from_status="COMPLIANT",
                        to_status="NON_COMPLIANT",
                        from_severity=RiskSeverity.LOW,
                        to_severity=RiskSeverity.HIGH,
                        exact_quote=safe_text,
                        triggering_statute_ids=[bound_d_to.dominating_node_id],
                        triggering_gazettes=[
                            g for g in [dom_node.gazette_ref if dom_node else None] if g
                        ],
                        source_spans=list(dom_node.source_spans) if dom_node else [],
                        explanation_practitioner=(
                            f"Full report timeline ({contract_d:g}d) violates {bound_d_to.dominating_citation} "
                            f"<= {limit_d_to:g}d active as of {req.to_date.isoformat()}."
                        ),
                        explanation_rakyat=(
                            f"Full incident reports must now be filed within {limit_d_to:g} days."
                        ),
                    )
                )

        low_safe = safe_text.lower()

        def _append_regime_mandate_delta(
            metric_key: str,
            rule_id: str,
            severity: RiskSeverity,
            practitioner_msg: str,
            rakyat_msg: str,
        ) -> None:
            nonlocal to_max_rank
            if metric_key not in env_to.resolved_bounds:
                return
            if metric_key in env_from.resolved_bounds:
                return
            bound = env_to.resolved_bounds[metric_key]
            dom_node = store.nodes.get(bound.dominating_node_id)
            to_max_rank = max(to_max_rank, _SEVERITY_RANK[severity])
            delta_findings.append(
                ContractDeltaFinding(
                    rule_id=rule_id,
                    section_ref=bound.dominating_citation,
                    impact_type="NEW_STATUTORY_MANDATE",
                    from_status="NOT_IN_FORCE",
                    to_status="NON_COMPLIANT",
                    from_severity=RiskSeverity.LOW,
                    to_severity=severity,
                    exact_quote=safe_text,
                    triggering_statute_ids=[bound.dominating_node_id],
                    triggering_gazettes=[
                        g for g in [dom_node.gazette_ref if dom_node else None] if g
                    ],
                    source_spans=list(dom_node.source_spans) if dom_node else [],
                    explanation_practitioner=practitioner_msg,
                    explanation_rakyat=rakyat_msg,
                )
            )

        # Act 854 P.U. (A) 221/2024 MSSP SOC & Penetration Testing Licensing
        if any(
            kw in low_safe
            for kw in (
                "unlicensed",
                "without nacsa license",
                "without nacsa licence",
                "no nacsa licence",
                "tanpa lesen nacsa",
            )
        ) and any(
            kw in low_safe
            for kw in (
                "soc",
                "managed security",
                "penetration test",
                "pentest",
                "mssp",
            )
        ):
            _append_regime_mandate_delta(
                "mssp_soc_pentest_nacsa_license_required",
                "DELTA-ACT_854-PUA221-MSSP",
                RiskSeverity.HIGH,
                "Managed SOC monitoring / penetration testing vendor lacks mandatory NACSA licence under Act 854 s. 27 & P.U. (A) 221/2024.",
                "Cyber security monitoring and testing vendors must hold a valid NACSA licence.",
            )

        # Act 864 Section 17(1) Public-Sector Third-Party Shared Data Duties
        if any(
            kw in low_safe
            for kw in (
                "public sector",
                "public-sector",
                "government agency",
                "shared data",
                "agensi awam",
                "data dikongsi",
            )
        ) and any(
            kw in low_safe
            for kw in (
                "no statutory duty",
                "disclaims",
                "waives",
                "exempt from act 864",
                "not bound",
                "tiada kewajipan berkanun",
            )
        ):
            _append_regime_mandate_delta(
                "public_sector_third_party_data_protection",
                "DELTA-ACT_864-SEC17-VENDOR",
                RiskSeverity.CRITICAL,
                "Public-sector vendor/contractor cannot disclaim Data Sharing Act 2025 [Act 864] s. 17(1) shared-data protection duties.",
                "Vendors handling Malaysian government shared data must protect it directly under Act 864.",
            )

        # Act 873 Consumer Credit Act 2025 (Rule-of-78 / Flat-Rate & SKP Licensing)
        if any(
            kw in low_safe
            for kw in (
                "rule of 78",
                "rule-of-78",
                "flat-rate interest",
                "flat rate interest",
                "peraturan 78",
                "kadar rata",
            )
        ):
            _append_regime_mandate_delta(
                "rule_of_78_interest_prohibition",
                "DELTA-ACT_873-RULE78",
                RiskSeverity.HIGH,
                "Rule-of-78 / flat-rate interest calculation clauses are prohibited under Consumer Credit Act 2025 [Act 873] s. 35.",
                "BNPL and credit contracts cannot charge Rule-of-78 or flat-rate interest.",
            )
        if any(
            kw in low_safe
            for kw in (
                "bnpl",
                "buy now pay later",
                "debt collection",
                "non-bank credit",
            )
        ) and any(
            kw in low_safe
            for kw in (
                "without skp",
                "unlicensed",
                "no skp license",
                "no skp licence",
                "exempt from skp",
            )
        ):
            _append_regime_mandate_delta(
                "skp_non_bank_credit_license_required",
                "DELTA-ACT_873-SKP-LIC",
                RiskSeverity.CRITICAL,
                "Non-bank credit / BNPL / debt-collection operator requires Suruhanjaya Kredit Pengguna (SKP) licence from 2026-06-01 under Act 873.",
                "BNPL and credit agencies must be licensed by SKP.",
            )

        # Act 866 Online Safety Act 2025
        if any(
            kw in low_safe for kw in ("under-16", "under 16", "child", "kanak-kanak")
        ) and any(
            kw in low_safe
            for kw in (
                "no age verification",
                "without age verification",
                "skip mykad",
                "self-declaration only",
            )
        ):
            _append_regime_mandate_delta(
                "online_safety_under_16_age_verification",
                "DELTA-ACT_866-U16-AGE",
                RiskSeverity.HIGH,
                "Platform lacks mandatory under-16 MyKad/passport age verification under Act 866 Codes effective 2026-06-01.",
                "Platforms must verify under-16 users with MyKad or passport checks.",
            )

        # PDPA Phase 3 (2025-06-01): Affected data subject 7d breach notice & 2-year register
        subj_delay_m = re.search(
            r"(?:data\s+subject|affected\s+individuals?|subjek\s+data)[^.;\n]{0,80}?(\d+)\s*(?:days?|hari)",
            low_safe,
        )
        if (subj_delay_m and float(subj_delay_m.group(1)) > 7.0) or any(
            kw in low_safe
            for kw in (
                "need not notify affected data subjects",
                "no notice to affected data subjects",
                "waives data subject breach notification",
            )
        ):
            _append_regime_mandate_delta(
                "data_subject_breach_notice_max_days",
                "DELTA-ACT709-P3-SUBJECT-7D",
                RiskSeverity.HIGH,
                "Affected data-subject breach notification exceeds or omits the 7-day mandate effective 2025-06-01 (PDPD Guideline No. 02/2025).",
                "Affected individuals must also be notified within 7 days of significant harm data breaches.",
            )

        reg_ret_m = re.search(
            r"(?:breach\s+register|daftar\s+pelanggaran)[^.;\n]{0,60}?(\d+)\s*(?:months?|bulan)",
            low_safe,
        )
        if (
            reg_ret_m and float(reg_ret_m.group(1)) < 24.0
        ) or "no breach register" in low_safe:
            _append_regime_mandate_delta(
                "breach_register_min_retention_years",
                "DELTA-ACT709-P3-REGISTER-2Y",
                RiskSeverity.MEDIUM,
                "Data breach register retention is below the mandatory 2-year minimum effective 2025-06-01.",
                "Companies must keep a personal data breach log for at least 2 years.",
            )

        inv_rank_to_sev = {v: k for k, v in _SEVERITY_RANK.items()}
        from_overall = inv_rank_to_sev[from_max_rank]
        to_overall = inv_rank_to_sev[to_max_rank]

        became_non_compliant = (
            from_overall == RiskSeverity.LOW and to_overall != RiskSeverity.LOW
        ) or any(
            f.impact_type in {"NEWLY_NON_COMPLIANT", "NEW_STATUTORY_MANDATE"}
            and f.from_severity in {None, RiskSeverity.LOW}
            for f in delta_findings
        )
        regression_detected = (
            became_non_compliant
            or (to_max_rank > from_max_rank)
            or bool(delta_findings)
        )

        if regression_detected:
            summary_pract = (
                f"DELTA REGRESSION DETECTED ({req.from_date.isoformat()} -> {req.to_date.isoformat()}): "
                f"Risk shifted {from_overall.value} -> {to_overall.value} across {len(delta_findings)} "
                f"finding(s) triggered by {len(intervening_diffs)} statutory/gazette transition(s) "
                f"({', '.join(newly_commenced_gazettes) or 'Act 709'})."
            )
            summary_rak = (
                f"Update needed: This contract was compliant on {req.from_date.isoformat()} ({from_overall.value}), "
                f"but new Malaysian laws taking effect by {req.to_date.isoformat()} raise risk to {to_overall.value}."
            )
        else:
            summary_pract = (
                f"NO COMPLIANCE REGRESSION ({req.from_date.isoformat()} -> {req.to_date.isoformat()}): "
                f"Risk remains {to_overall.value} across {len(intervening_diffs)} intervening statutory update(s)."
            )
            summary_rak = (
                f"No new compliance regressions were caused by law changes between "
                f"{req.from_date.isoformat()} and {req.to_date.isoformat()}."
            )

    telemetry = compute_telemetry_summary(
        prompt_tokens=0,
        completion_tokens=0,
        latency_ms=elapsed_holder[0],
        retry_count=0,
        is_verified_grounded=True,
        trace_id=f"delta-{req.document_id.lower()}",
    )

    return ContractDeltaAuditResponse(
        document_id=req.document_id,
        from_date=req.from_date,
        to_date=req.to_date,
        territorial_scope=req.territorial_scope,
        persona=req.persona,
        from_overall_risk=from_overall,
        to_overall_risk=to_overall,
        became_non_compliant=became_non_compliant,
        compliance_regression_detected=regression_detected,
        pii_scrub=pii_scrub,
        intervening_statutory_diffs=intervening_diffs,
        newly_commenced_gazettes=newly_commenced_gazettes,
        delta_findings=delta_findings,
        summary_practitioner=summary_pract,
        summary_rakyat=summary_rak,
        telemetry=telemetry,
        disclaimer=DEFAULT_LEGAL_DISCLAIMER,
    )
