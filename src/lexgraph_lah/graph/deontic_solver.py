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
    RecipientNoticeObligation,
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
    "ACT_864",
    "ACT_866",
    "ACT_872",
    "ACT_873",
    "ACT_882",
    "ACT_562",
    "ACT_563",
    "ACT_378",
    "ACT_53",
    "MOSTI_AIGE",
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
    "p.u.(a) 219/2024": "ACT_854",
    "p.u. (a) 219/2024": "ACT_854",
    "p.u.(a) 221/2024": "ACT_854",
    "p.u. (a) 221/2024": "ACT_854",
    "p.u.(a) 222/2024": "ACT_854",
    "p.u. (a) 222/2024": "ACT_854",
    "p.u.(a) 47/2025": "ACT_854",
    "p.u. (a) 47/2025": "ACT_854",
    "p.u.(b) 522/2024": "ACT_709",
    "p.u. (b) 522/2024": "ACT_709",
    "cbpdt": "ACT_709",
    "act_864": "ACT_864",
    "act 864": "ACT_864",
    "act864": "ACT_864",
    "akta 864": "ACT_864",
    "data sharing act": "ACT_864",
    "data sharing act 2025": "ACT_864",
    "akta perkongsian data 2025": "ACT_864",
    "act_866": "ACT_866",
    "act 866": "ACT_866",
    "act866": "ACT_866",
    "akta 866": "ACT_866",
    "onsa": "ACT_866",
    "online safety act": "ACT_866",
    "online safety act 2025": "ACT_866",
    "akta keselamatan dalam talian 2025": "ACT_866",
    "act_873": "ACT_873",
    "act 873": "ACT_873",
    "act873": "ACT_873",
    "akta 873": "ACT_873",
    "skp": "ACT_873",
    "bnpl": "ACT_873",
    "consumer credit act": "ACT_873",
    "consumer credit act 2025": "ACT_873",
    "akta kredit pengguna 2025": "ACT_873",
    "act_562": "ACT_562",
    "act 562": "ACT_562",
    "act562": "ACT_562",
    "akta 562": "ACT_562",
    "dsa 1997": "ACT_562",
    "digital signature act 1997": "ACT_562",
    "akta tandatangan digital 1997": "ACT_562",
    "act_563": "ACT_563",
    "act 563": "ACT_563",
    "act563": "ACT_563",
    "akta 563": "ACT_563",
    "cca 1997": "ACT_563",
    "computer crimes act 1997": "ACT_563",
    "akta jenayah komputer 1997": "ACT_563",
    "act_378": "ACT_378",
    "act 378": "ACT_378",
    "act378": "ACT_378",
    "akta 378": "ACT_378",
    "stamp act": "ACT_378",
    "stamp act 1949": "ACT_378",
    "akta setem": "ACT_378",
    "akta setem 1949": "ACT_378",
    "sdsas": "ACT_378",
    "stamp duty": "ACT_378",
    "duti setem": "ACT_378",
    "act_53": "ACT_53",
    "act 53": "ACT_53",
    "act53": "ACT_53",
    "akta 53": "ACT_53",
    "income tax act 1967": "ACT_53",
    "akta cukai pendapatan 1967": "ACT_53",
    "myinvois": "ACT_53",
    "e-invoice": "ACT_53",
    "e-invoicing": "ACT_53",
    "s. 82c": "ACT_53",
    "82c": "ACT_53",
    "mosti_aige": "MOSTI_AIGE",
    "mosti aige": "MOSTI_AIGE",
    "aige": "MOSTI_AIGE",
    "mosti": "MOSTI_AIGE",
    "ai governance": "MOSTI_AIGE",
    "ai ethics": "MOSTI_AIGE",
    "bnm outsourcing": "BNM_RMIT",
    "bnm/rh/pd 028-99": "BNM_RMIT",
    "act_872": "ACT_872",
    "act 872": "ACT_872",
    "act872": "ACT_872",
    "akta 872": "ACT_872",
    "gig workers": "ACT_872",
    "gig workers act": "ACT_872",
    "pekerja gig": "ACT_872",
    "perkeso gig": "ACT_872",
    "act_882": "ACT_882",
    "act 882": "ACT_882",
    "act882": "ACT_882",
    "akta 882": "ACT_882",
    "government procurement": "ACT_882",
    "perolehan kerajaan": "ACT_882",
    "procurement appeal tribunal": "ACT_882",
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
    if "864" in cleaned or "data sharing" in cleaned or "perkongsian data" in cleaned:
        return "ACT_864"
    if (
        "866" in cleaned
        or "online safety" in cleaned
        or "keselamatan dalam talian" in cleaned
        or "onsa" in cleaned
    ):
        return "ACT_866"
    if (
        "873" in cleaned
        or "consumer credit" in cleaned
        or "kredit pengguna" in cleaned
        or "bnpl" in cleaned
        or "skp" in cleaned
    ):
        return "ACT_873"
    if (
        "562" in cleaned
        or "digital signature" in cleaned
        or "tandatangan digital" in cleaned
    ):
        return "ACT_562"
    if (
        "563" in cleaned
        or "computer crimes" in cleaned
        or "jenayah komputer" in cleaned
    ):
        return "ACT_563"
    if (
        "378" in cleaned
        or "stamp act" in cleaned
        or "akta setem" in cleaned
        or "sdsas" in cleaned
        or "stamp duty" in cleaned
    ):
        return "ACT_378"
    if (
        "act 53" in cleaned
        or "act_53" in cleaned
        or "akta 53" in cleaned
        or "income tax" in cleaned
        or "cukai pendapatan" in cleaned
        or "myinvois" in cleaned
        or "82c" in cleaned
        or "120(1)(d)" in cleaned
    ):
        return "ACT_53"
    if "aige" in cleaned or "mosti" in cleaned or "ai governance" in cleaned:
        return "MOSTI_AIGE"
    if "872" in cleaned or "gig worker" in cleaned or "pekerja gig" in cleaned:
        return "ACT_872"
    if (
        "882" in cleaned
        or "government procurement" in cleaned
        or "perolehan kerajaan" in cleaned
        or "procurement appeal tribunal" in cleaned
    ):
        return "ACT_882"
    if (
        "854" in cleaned
        or "219/2024" in cleaned
        or "220/2024" in cleaned
        or "221/2024" in cleaned
        or "222/2024" in cleaned
        or "47/2025" in cleaned
        or "cyber" in cleaned
    ):
        return "ACT_854"
    if "rmit" in cleaned or "bnm" in cleaned:
        return "BNM_RMIT"
    if (
        "709" in cleaned
        or "pdpa" in cleaned
        or "data peribadi" in cleaned
        or "522/2024" in cleaned
        or "cbpdt" in cleaned
    ):
        return "ACT_709"
    if (
        "658" in cleaned
        or "electronic commerce" in cleaned
        or "perdagangan elektronik" in cleaned
    ):
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
        if cleaned in {
            "labour",
            "employment",
            "east_malaysia_labour",
            "labour_ordinance",
        }:
            candidates = ["ACT_265", "SABAH_CAP67", "SARAWAK_CAP76"]
        elif cleaned in {"territorial", "5_territory", "all_territories"}:
            candidates = [
                "ACT_265",
                "SABAH_CAP67",
                "SARAWAK_CAP76",
                "ACT_704",
                "ACT_136",
            ]
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


def _constraint_rank_key(
    cand: RegimeConstraintCandidate,
) -> tuple[int, float, int, str]:
    """
    Produces a deterministic comparison key where SMALLER tuple means STRICTER bound
    (wins the composite envelope). Mandatory obligations/prohibitions strictly outrank
    voluntary guidelines (`VOLUNTARY_GUIDELINE`) on shared metric keys.
    """
    c = cand.constraint
    if c.modality == "PRE_COMMENCEMENT_ADVISORY":
        modality_rank = 2
    elif c.modality == "VOLUNTARY_GUIDELINE":
        modality_rank = 1
    else:
        modality_rank = 0
    tier = int(cand.authority_tier)
    val = c.threshold_value

    if (
        c.operator == "<="
        and isinstance(val, (int, float))
        and not isinstance(val, bool)
    ):
        return (modality_rank, float(val), tier, cand.node_id)
    if (
        c.operator == ">="
        and isinstance(val, (int, float))
        and not isinstance(val, bool)
    ):
        return (modality_rank, -float(val), tier, cand.node_id)
    if c.operator == "FORBIDDEN_CLAUSE":
        return (modality_rank, 0.0, tier, cand.node_id)
    if isinstance(val, bool):
        # True obligation is stricter than False permission
        return (modality_rank, 0.0 if val else 1.0, tier, cand.node_id)
    if isinstance(val, str):
        rank = _CONDITION_STRICTNESS_RANK.get(val, 1)
        return (modality_rank, -float(rank), tier, cand.node_id)
    return (modality_rank, 0.0, tier, cand.node_id)


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

        def _collect_candidates(
            nodes: list[StatutoryNode],
            *,
            override_modality: str | None = None,
            filter_to_target_regimes: bool = True,
        ) -> tuple[
            dict[str, list[RegimeConstraintCandidate]],
            dict[str, list[RegimeConstraintCandidate]],
            list[str],
        ]:
            node_ids_in_scope: list[str] = []
            by_metric: dict[str, list[RegimeConstraintCandidate]] = {}
            by_recipient: dict[str, list[RegimeConstraintCandidate]] = {}
            seen: set[tuple[str, str, str, str]] = set()
            all_node_ids = {n.node_id for n in nodes}

            for node in nodes:
                regime_id = infer_node_regime(node)
                if filter_to_target_regimes and regime_id not in target_regimes:
                    continue
                node_ids_in_scope.append(node.node_id)
                if not node.deontic_constraints:
                    continue
                # Prefer English canonical nodes for numeric/constraint evaluation when bilingual pair shares identical constraints
                if (
                    node.normalized_language == "ms"
                    and node.translation_node_id in all_node_ids
                ):
                    continue

                for constraint in node.deontic_constraints:
                    scoped_match = filter_by_territorial_scope(
                        [
                            node.model_copy(
                                update={
                                    "territorial_scope": constraint.territorial_scope
                                }
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
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    eff_constraint = (
                        constraint.model_copy(update={"modality": override_modality})
                        if override_modality is not None
                        else constraint
                    )
                    candidate = RegimeConstraintCandidate(
                        regime_id=regime_id,
                        node_id=node.node_id,
                        act_name=node.act_name,
                        act_number=node.act_number,
                        section_code=node.section_code,
                        gazette_ref=node.gazette_ref,
                        authority_tier=node.authority_tier,
                        constraint=eff_constraint,
                    )
                    by_metric.setdefault(eff_constraint.metric_key, []).append(
                        candidate
                    )
                    if eff_constraint.recipient and override_modality is None:
                        stage = eff_constraint.notice_stage or eff_constraint.metric_key
                        recip_key = f"{eff_constraint.recipient}:{stage}"
                        by_recipient.setdefault(recip_key, []).append(candidate)

            return by_metric, by_recipient, node_ids_in_scope

        candidates_by_metric, recipient_candidates, _ = _collect_candidates(
            active_nodes
        )

        pending_nodes: list[StatutoryNode] = []
        if hasattr(self._store, "query_pending_commencement"):
            pending_nodes = self._store.query_pending_commencement(
                as_of_date=as_of_date,
                territorial_scope=scope_enum,
                include_translations=True,
            )
        pending_by_metric, _, pending_node_ids = _collect_candidates(
            pending_nodes,
            override_modality="PRE_COMMENCEMENT_ADVISORY",
        )

        resolved_bounds: dict[str, ResolvedMetricBound] = {}
        recipient_obligations: dict[str, RecipientNoticeObligation] = {}
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

        pre_commencement_advisories: dict[str, ResolvedMetricBound] = {}
        for metric_key in sorted(pending_by_metric.keys()):
            p_cands = sorted(pending_by_metric[metric_key], key=_constraint_rank_key)
            p_win = p_cands[0]
            pw_c = p_win.constraint
            adv_bound = ResolvedMetricBound(
                metric_key=metric_key,
                modality="PRE_COMMENCEMENT_ADVISORY",
                operator=pw_c.operator,
                strictest_value=pw_c.threshold_value,
                unit=pw_c.unit,
                dominating_regime=p_win.regime_id,
                dominating_node_id=p_win.node_id,
                dominating_citation=f"{p_win.act_number} {p_win.section_code}",
                provenance_chain=p_cands,
            )
            pre_commencement_advisories[metric_key] = adv_bound
            resolved_bounds.setdefault(metric_key, adv_bound)

        for recip_key in sorted(recipient_candidates.keys()):
            r_cands = sorted(recipient_candidates[recip_key], key=_constraint_rank_key)
            r_win = r_cands[0]
            rc = r_win.constraint
            recipient_obligations[recip_key] = RecipientNoticeObligation(
                recipient=rc.recipient or recip_key.split(":", 1)[0],
                notice_stage=rc.notice_stage or rc.metric_key,
                regime_id=r_win.regime_id,
                node_id=r_win.node_id,
                citation=f"{r_win.act_number} {r_win.section_code}",
                metric_key=rc.metric_key,
                operator=rc.operator,
                threshold_value=rc.threshold_value,
                unit=rc.unit,
                description=rc.description,
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
                "recipient_obligations": {
                    k: {
                        "val": v.threshold_value,
                        "op": v.operator,
                        "node": v.node_id,
                    }
                    for k, v in recipient_obligations.items()
                },
                "pending_commencement_node_ids": pending_node_ids,
                "pre_commencement_advisories": {
                    k: {
                        "val": v.strictest_value,
                        "op": v.operator,
                        "node": v.dominating_node_id,
                    }
                    for k, v in pre_commencement_advisories.items()
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
            pending_commencement_node_ids=pending_node_ids,
            resolved_bounds=resolved_bounds,
            pre_commencement_advisories=pre_commencement_advisories,
            recipient_obligations=recipient_obligations,
            inter_regime_conflicts=conflicts,
            envelope_hash=envelope_hash,
        )
