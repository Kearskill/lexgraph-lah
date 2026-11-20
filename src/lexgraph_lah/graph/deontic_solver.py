import hashlib
import json
from datetime import date

from lexgraph_lah.graph.reranker import filter_by_territorial_scope
from lexgraph_lah.graph.temporal_store import (
    TemporalGraphStore,
    get_default_temporal_store,
)
from lexgraph_lah.schemas.domain import (
    CompositeDeonticEnvelope,
    DeonticConstraint,
    InterRegimeConflictDelta,
    RegimeConstraintCandidate,
    ResolvedMetricBound,
    StatutoryNode,
    TerritorialScope,
)

ALL_SUPPORTED_REGIMES: tuple[str, ...] = (
    "ACT_709",
    "ACT_854",
    "BNM_RMIT",
    "ACT_265",
    "SABAH_CAP67",
    "SARAWAK_CAP76",
    "ACT_704",
    "ACT_136",
    "ACT_658",
)

_REGIME_ALIASES: dict[str, str] = {
    "act_709": "ACT_709",
    "act 709": "ACT_709",
    "act709": "ACT_709",
    "pdpa": "ACT_709",
    "pdpa 2010": "ACT_709",
    "personal data protection act 2010": "ACT_709",
    "akta 709": "ACT_709",
    "act_854": "ACT_854",
    "act 854": "ACT_854",
    "act854": "ACT_854",
    "csa": "ACT_854",
    "csa 2024": "ACT_854",
    "cyber security act 2024": "ACT_854",
    "akta 854": "ACT_854",
    "p.u.(a) 220/2024": "ACT_854",
    "p.u. (a) 220/2024": "ACT_854",
    "bnm_rmit": "BNM_RMIT",
    "bnm rmit": "BNM_RMIT",
    "rmit": "BNM_RMIT",
    "bnm": "BNM_RMIT",
    "bnm/rh/pd 028-98": "BNM_RMIT",
    "act_265": "ACT_265",
    "act 265": "ACT_265",
    "act265": "ACT_265",
    "ea 1955": "ACT_265",
    "employment act 1955": "ACT_265",
    "akta 265": "ACT_265",
    "akta kerja 1955": "ACT_265",
    "sabah_cap67": "SABAH_CAP67",
    "sabah cap 67": "SABAH_CAP67",
    "sabah cap. 67": "SABAH_CAP67",
    "cap. 67": "SABAH_CAP67",
    "cap 67": "SABAH_CAP67",
    "sabah labour ordinance": "SABAH_CAP67",
    "ordinan buruh sabah": "SABAH_CAP67",
    "sarawak_cap76": "SARAWAK_CAP76",
    "sarawak cap 76": "SARAWAK_CAP76",
    "sarawak cap. 76": "SARAWAK_CAP76",
    "cap. 76": "SARAWAK_CAP76",
    "cap 76": "SARAWAK_CAP76",
    "sarawak labour ordinance": "SARAWAK_CAP76",
    "ordinan buruh sarawak": "SARAWAK_CAP76",
    "act_704": "ACT_704",
    "act 704": "ACT_704",
    "akta 704": "ACT_704",
    "labuan fsa": "ACT_704",
    "act_136": "ACT_136",
    "act 136": "ACT_136",
    "act136": "ACT_136",
    "akta 136": "ACT_136",
    "contracts act": "ACT_136",
    "contracts act 1950": "ACT_136",
    "akta kontrak 1950": "ACT_136",
    "act_658": "ACT_658",
    "act 658": "ACT_658",
    "act658": "ACT_658",
    "eca": "ACT_658",
    "eca 2006": "ACT_658",
    "electronic commerce act 2006": "ACT_658",
    "akta 658": "ACT_658",
    "akta perdagangan elektronik 2006": "ACT_658",
}

_CONDITION_STRICTNESS_RANK: dict[str, int] = {
    "bnm_oversight_and_exit_plan_required": 3,
    "consent_or_adequacy_required": 2,
    "consent_only": 1,
}


def normalize_regime_key(raw: str) -> str:
    """Normalizes free-form Malaysian regime names into canonical identifiers."""
    cleaned = raw.strip().lower()
    if cleaned in _REGIME_ALIASES:
        return _REGIME_ALIASES[cleaned]
    if "854" in cleaned or "220/2024" in cleaned or "cyber" in cleaned:
        return "ACT_854"
    if "rmit" in cleaned or "bnm" in cleaned:
        return "BNM_RMIT"
    if "709" in cleaned or "pdpa" in cleaned or "data peribadi" in cleaned:
        return "ACT_709"
    if "658" in cleaned or "electronic commerce" in cleaned or "perdagangan elektronik" in cleaned:
        return "ACT_658"
    if "sabah" in cleaned or "cap. 67" in cleaned or "cap 67" in cleaned:
        return "SABAH_CAP67"
    if "sarawak" in cleaned or "cap. 76" in cleaned or "cap 76" in cleaned:
        return "SARAWAK_CAP76"
    if "265" in cleaned or "employment act" in cleaned or "akta kerja" in cleaned:
        return "ACT_265"
    if "704" in cleaned or "labuan" in cleaned:
        return "ACT_704"
    if "136" in cleaned or "contracts act" in cleaned or "akta kontrak" in cleaned:
        return "ACT_136"
    return raw.strip().upper().replace(" ", "_")


def normalize_regimes(regimes: list[str] | None) -> list[str]:
    """Deduplicates and normalizes requested regulatory regimes in deterministic order."""
    if not regimes:
        return ["ACT_709"]
    seen: set[str] = set()
    ordered: list[str] = []
    for item in regimes:
        cleaned = item.strip().lower()
        if cleaned in {"labour", "employment", "east_malaysia_labour", "labour_ordinance"}:
            candidates = ["ACT_265", "SABAH_CAP67", "SARAWAK_CAP76"]
        elif cleaned in {"territorial", "5_territory", "all_territories"}:
            candidates = ["ACT_265", "SABAH_CAP67", "SARAWAK_CAP76", "ACT_704", "ACT_136"]
        elif cleaned == "all":
            candidates = list(ALL_SUPPORTED_REGIMES)
        else:
            candidates = [normalize_regime_key(item)]
        for code in candidates:
            if code and code not in seen:
                seen.add(code)
                ordered.append(code)
    return ordered or ["ACT_709"]


def infer_node_regime(node: StatutoryNode) -> str:
    """Determines the canonical regulatory regime code of a StatutoryNode."""
    if node.regime_code:
        return normalize_regime_key(node.regime_code)
    blob = f"{node.node_id} {node.act_name} {node.act_number} {node.gazette_ref or ''}".lower()
    return normalize_regime_key(blob)


def _constraint_rank_key(cand: RegimeConstraintCandidate) -> tuple[float, int, str]:
    """
    Produces a deterministic comparison key where SMALLER tuple means STRICTER bound
    (wins the composite envelope).
    """
    c = cand.constraint
    tier = int(cand.authority_tier)
    val = c.threshold_value

    if c.operator == "<=" and isinstance(val, (int, float)) and not isinstance(val, bool):
        return (float(val), tier, cand.node_id)
    if c.operator == ">=" and isinstance(val, (int, float)) and not isinstance(val, bool):
        return (-float(val), tier, cand.node_id)
    if c.operator == "FORBIDDEN_CLAUSE":
        return (0.0, tier, cand.node_id)
    if isinstance(val, bool):
        # True obligation is stricter than False permission
        return (0.0 if val else 1.0, tier, cand.node_id)
    if isinstance(val, str):
        rank = _CONDITION_STRICTNESS_RANK.get(val, 1)
        return (-float(rank), tier, cand.node_id)
    return (0.0, tier, cand.node_id)


def _format_bound(constraint: DeonticConstraint) -> str:
    val = constraint.threshold_value
    unit = f" {constraint.unit}" if constraint.unit else ""
    if constraint.operator == "FORBIDDEN_CLAUSE":
        return f"FORBIDDEN({val})"
    return f"{constraint.operator} {val}{unit}".strip()


class DeonticEnvelopeResolver:
    """
    Zero-token O(V + E) Multi-Regime Deontic Conflict Solver.

    Traverses point-in-time statutes, bi-temporal P.U. gazettes, and BM/EN crosswalks
    to synthesize the Strictest Composite Statutory Envelope across colliding regimes
    (e.g., Act 709 [72h] vs Act 854 P.U.(A) 220/2024 [6h] vs BNM RMiT [1h]).
    """

    def __init__(self, store: TemporalGraphStore | None = None) -> None:
        self._store = store or get_default_temporal_store()

    def filter_active_nodes_for_regimes(
        self,
        regimes: list[str] | None,
        as_of_date: date,
        territorial_scope: TerritorialScope | str | None = None,
        act_filter: str | None = None,
    ) -> list[StatutoryNode]:
        """Returns active StatutoryNodes matching `regimes`, `as_of_date`, and `territorial_scope`."""
        active_nodes = self._store.query_point_in_time(
            as_of_date=as_of_date,
            act_name=act_filter,
            include_citations=True,
            include_translations=True,
            territorial_scope=territorial_scope,
        )
        if not regimes:
            return active_nodes

        target_regimes = set(normalize_regimes(regimes))
        matched = [
            node for node in active_nodes if infer_node_regime(node) in target_regimes
        ]
        # Preserve backward-compatible citation targets (e.g., Act 709 Sec 130) if matched
        return matched

    def resolve(
        self,
        regimes: list[str] | None,
        as_of_date: date,
        territorial_scope: TerritorialScope | str | None = None,
    ) -> CompositeDeonticEnvelope:
        """
        Resolves the Strictest Composite Statutory Envelope across `regimes` on `as_of_date`
        for `territorial_scope` in O(V + E) with 0 LLM tokens.
        """
        target_regimes = normalize_regimes(regimes)
        scope_enum = (
            territorial_scope
            if isinstance(territorial_scope, TerritorialScope)
            else TerritorialScope(territorial_scope)
            if territorial_scope
            else TerritorialScope.ALL_MALAYSIA
        )

        active_nodes = self.filter_active_nodes_for_regimes(
            regimes=target_regimes,
            as_of_date=as_of_date,
            territorial_scope=scope_enum,
        )

        # Group constraints by metric_key while avoiding EN/BM duplicate noise for the same node pair
        candidates_by_metric: dict[str, list[RegimeConstraintCandidate]] = {}
        seen_per_regime_section: set[tuple[str, str, str, str]] = set()

        for node in active_nodes:
            if not node.deontic_constraints:
                continue
            regime_id = infer_node_regime(node)
            if regime_id not in target_regimes:
                continue
            # Prefer English canonical nodes for numeric/constraint evaluation when bilingual pair shares identical constraints
            if node.normalized_language == "ms" and node.translation_node_id in {
                n.node_id for n in active_nodes
            }:
                continue

            for constraint in node.deontic_constraints:
                scoped_match = filter_by_territorial_scope(
                    [
                        node.model_copy(
                            update={"territorial_scope": constraint.territorial_scope}
                        )
                    ],
                    scope_enum,
                )
                if not scoped_match:
                    continue

                dedup_key = (
                    regime_id,
                    node.act_number,
                    node.section_code,
                    constraint.metric_key,
                )
                if dedup_key in seen_per_regime_section:
                    continue
                seen_per_regime_section.add(dedup_key)

                candidates_by_metric.setdefault(constraint.metric_key, []).append(
                    RegimeConstraintCandidate(
                        regime_id=regime_id,
                        node_id=node.node_id,
                        act_name=node.act_name,
                        act_number=node.act_number,
                        section_code=node.section_code,
                        gazette_ref=node.gazette_ref,
                        authority_tier=node.authority_tier,
                        constraint=constraint,
                    )
                )

        resolved_bounds: dict[str, ResolvedMetricBound] = {}
        conflicts: list[InterRegimeConflictDelta] = []

        for metric_key in sorted(candidates_by_metric.keys()):
            candidates = sorted(
                candidates_by_metric[metric_key], key=_constraint_rank_key
            )
            winner = candidates[0]
            win_c = winner.constraint
            resolved_bounds[metric_key] = ResolvedMetricBound(
                metric_key=metric_key,
                modality=win_c.modality,
                operator=win_c.operator,
                strictest_value=win_c.threshold_value,
                unit=win_c.unit,
                dominating_regime=winner.regime_id,
                dominating_node_id=winner.node_id,
                dominating_citation=f"{winner.act_number} {winner.section_code}",
                provenance_chain=candidates,
            )

            seen_conflict_regimes: set[str] = {winner.regime_id}
            for other in candidates[1:]:
                if (
                    other.regime_id not in seen_conflict_regimes
                    and other.constraint.threshold_value != win_c.threshold_value
                ):
                    seen_conflict_regimes.add(other.regime_id)
                    conflicts.append(
                        InterRegimeConflictDelta(
                            metric_key=metric_key,
                            winning_regime=winner.regime_id,
                            winning_node_id=winner.node_id,
                            winning_bound=win_c.threshold_value,
                            superseded_regime=other.regime_id,
                            superseded_node_id=other.node_id,
                            superseded_bound=other.constraint.threshold_value,
                            delta_summary=(
                                f"{winner.regime_id} ({winner.node_id}: {_format_bound(win_c)}) "
                                f"overrides looser {other.regime_id} ({other.node_id}: {_format_bound(other.constraint)}) "
                                f"for '{metric_key}'."
                            ),
                        )
                    )

        digest_basis = json.dumps(
            {
                "as_of_date": as_of_date.isoformat(),
                "territorial_scope": scope_enum.value,
                "regimes": target_regimes,
                "bounds": {
                    k: {
                        "val": v.strictest_value,
                        "op": v.operator,
                        "node": v.dominating_node_id,
                    }
                    for k, v in resolved_bounds.items()
                },
            },
            sort_keys=True,
        )
        envelope_hash = hashlib.sha256(digest_basis.encode("utf-8")).hexdigest()

        return CompositeDeonticEnvelope(
            as_of_date=as_of_date,
            territorial_scope=scope_enum,
            regimes_evaluated=target_regimes,
            active_node_ids=[n.node_id for n in active_nodes],
            resolved_bounds=resolved_bounds,
            inter_regime_conflicts=conflicts,
            envelope_hash=envelope_hash,
        )
