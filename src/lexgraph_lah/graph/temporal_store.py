import uuid
from datetime import date, timedelta
from typing import Any, Literal

from pydantic import BaseModel, Field

from lexgraph_lah.graph.bilingual_router import normalize_and_expand_query
from lexgraph_lah.graph.reranker import (
    AUTHORITY_LABELS,
    AUTHORITY_WEIGHTS,
    compute_hybrid_relevance_score,
    filter_by_territorial_scope,
    rerank_statutes_and_spans,
)
from lexgraph_lah.schemas.domain import (
    DEFAULT_LEGAL_DISCLAIMER,
    AmendmentTimelineEntry,
    AuthorityBreakdownItem,
    AuthorityTier,
    BilingualClausePair,
    GroundedClaim,
    HierarchyLevel,
    JudicialTreatmentItem,
    PointInTimeResearchRequest,
    PointInTimeResearchResponse,
    ProvisionLineageResponse,
    RetrievalSearchResponse,
    SourceSpan,
    StatutoryEdge,
    StatutoryNode,
    StatutoryStatus,
    SubgraphVisualizationData,
    TemporalEdgeType,
    TerritorialScope,
)
from lexgraph_lah.telemetry.cost_tracker import compute_telemetry_summary
from lexgraph_lah.telemetry.tracer import measure_latency_ms


class CypherQueryBundle(BaseModel):
    """Encapsulates a parameterized Cypher query and its parameter dictionary."""

    query: str
    params: dict[str, Any] = Field(default_factory=dict)


def build_upsert_amendment_cypher(
    new_node: StatutoryNode,
    predecessor_node_id: str | None = None,
) -> CypherQueryBundle:
    """
    Generates a parameterized Cypher query to insert/merge a StatutoryNode version,
    optionally closing out a predecessor version's VALID_TO / effective_to window and
    creating AMENDED_BY, SUPERSEDED_BY, and AMENDS edges with gazette/authority metadata.
    """
    eff_from_date = new_node.effective_from or new_node.valid_from
    eff_from = eff_from_date.isoformat()
    eff_to_val = new_node.effective_to or new_node.valid_to
    eff_to = eff_to_val.isoformat() if eff_to_val else None
    prev_eff_to = (eff_from_date - timedelta(days=1)).isoformat()

    params: dict[str, Any] = {
        "node_id": new_node.node_id,
        "act_name": new_node.act_name,
        "act_number": new_node.act_number,
        "section_code": new_node.section_code,
        "hierarchy_level": new_node.hierarchy_level.value,
        "language": new_node.language,
        "version": new_node.version,
        "text": new_node.text,
        "valid_from": eff_from,
        "valid_to": eff_to,
        "effective_from": eff_from,
        "effective_to": eff_to,
        "prev_effective_to": prev_eff_to,
        "is_in_force": new_node.is_in_force,
        "amendment_act_ref": new_node.amendment_act_ref or new_node.gazette_ref,
        "gazette_ref": new_node.gazette_ref,
        "authority_tier": int(new_node.authority_tier),
        "territorial_scope": [s.value for s in new_node.territorial_scope],
        "status": new_node.status.value,
        "content_hash": new_node.content_hash,
        "predecessor_id": predecessor_node_id,
    }

    if predecessor_node_id:
        query = (
            "MERGE (n:StatutoryNode {node_id: $node_id})\n"
            "SET n.act_name = $act_name,\n"
            "    n.act_number = $act_number,\n"
            "    n.section_code = $section_code,\n"
            "    n.hierarchy_level = $hierarchy_level,\n"
            "    n.language = $language,\n"
            "    n.version = $version,\n"
            "    n.text = $text,\n"
            "    n.valid_from = date($valid_from),\n"
            "    n.valid_to = CASE WHEN $valid_to IS NOT NULL THEN date($valid_to) ELSE null END,\n"
            "    n.effective_from = date($effective_from),\n"
            "    n.effective_to = CASE WHEN $effective_to IS NOT NULL THEN date($effective_to) ELSE null END,\n"
            "    n.is_in_force = $is_in_force,\n"
            "    n.amendment_act_ref = $amendment_act_ref,\n"
            "    n.gazette_ref = $gazette_ref,\n"
            "    n.authority_tier = $authority_tier,\n"
            "    n.territorial_scope = $territorial_scope,\n"
            "    n.status = $status,\n"
            "    n.content_hash = $content_hash\n"
            "WITH n\n"
            "MATCH (prev:StatutoryNode {node_id: $predecessor_id})\n"
            "SET prev.valid_to = date($valid_from),\n"
            "    prev.effective_to = date($prev_effective_to),\n"
            "    prev.is_in_force = false,\n"
            "    prev.status = 'AMENDED'\n"
            "MERGE (prev)-[r:AMENDED_BY]->(n)\n"
            "SET r.effective_date = date($valid_from),\n"
            "    r.gazette_ref = $gazette_ref\n"
            "MERGE (prev)-[rs:SUPERSEDED_BY]->(n)\n"
            "SET rs.effective_date = date($valid_from),\n"
            "    rs.gazette_ref = $gazette_ref\n"
            "MERGE (n)-[ra:AMENDS]->(prev)\n"
            "SET ra.effective_date = date($valid_from),\n"
            "    ra.gazette_ref = $gazette_ref\n"
            "RETURN n, prev"
        )
    else:
        query = (
            "MERGE (n:StatutoryNode {node_id: $node_id})\n"
            "SET n.act_name = $act_name,\n"
            "    n.act_number = $act_number,\n"
            "    n.section_code = $section_code,\n"
            "    n.hierarchy_level = $hierarchy_level,\n"
            "    n.language = $language,\n"
            "    n.version = $version,\n"
            "    n.text = $text,\n"
            "    n.valid_from = date($valid_from),\n"
            "    n.valid_to = CASE WHEN $valid_to IS NOT NULL THEN date($valid_to) ELSE null END,\n"
            "    n.effective_from = date($effective_from),\n"
            "    n.effective_to = CASE WHEN $effective_to IS NOT NULL THEN date($effective_to) ELSE null END,\n"
            "    n.is_in_force = $is_in_force,\n"
            "    n.amendment_act_ref = $amendment_act_ref,\n"
            "    n.gazette_ref = $gazette_ref,\n"
            "    n.authority_tier = $authority_tier,\n"
            "    n.territorial_scope = $territorial_scope,\n"
            "    n.status = $status,\n"
            "    n.content_hash = $content_hash\n"
            "RETURN n"
        )

    return CypherQueryBundle(query=query, params=params)


def build_repeal_cypher(
    target_node_id: str,
    repealing_node_id: str,
    effective_date: date,
    gazette_ref: str | None = None,
) -> CypherQueryBundle:
    """
    Generates a parameterized Cypher query marking a statutory node as REPEALED_BY / REPEALS
    another statutory instrument as of effective_date.
    """
    prev_eff_to = (effective_date - timedelta(days=1)).isoformat()
    query = (
        "MATCH (target:StatutoryNode {node_id: $target_node_id})\n"
        "MATCH (rep:StatutoryNode {node_id: $repealing_node_id})\n"
        "SET target.valid_to = date($effective_date),\n"
        "    target.effective_to = date($prev_effective_to),\n"
        "    target.is_in_force = false,\n"
        "    target.status = 'REPEALED'\n"
        "MERGE (target)-[r:REPEALED_BY]->(rep)\n"
        "SET r.effective_date = date($effective_date),\n"
        "    r.gazette_ref = $gazette_ref\n"
        "MERGE (rep)-[rr:REPEALS]->(target)\n"
        "SET rr.effective_date = date($effective_date),\n"
        "    rr.gazette_ref = $gazette_ref\n"
        "RETURN target, rep"
    )
    return CypherQueryBundle(
        query=query,
        params={
            "target_node_id": target_node_id,
            "repealing_node_id": repealing_node_id,
            "effective_date": effective_date.isoformat(),
            "prev_effective_to": prev_eff_to,
            "gazette_ref": gazette_ref,
        },
    )


def build_point_in_time_cypher(
    as_of_date: date,
    act_name: str | None = None,
    max_citation_hops: int = 2,
    territorial_scope: str | None = None,
) -> CypherQueryBundle:
    """
    Generates a point-in-time Graph-RAG Cypher traversal query that retrieves only
    statutes active on `as_of_date`, filters by territorial scope if supplied, and
    resolves multi-hop CITES / BM_EN_EQUIVALENT / HAS_TRANSLATION / judicial edges.
    """
    hops = max(1, min(max_citation_hops, 4))
    act_clause = "AND s.act_name = $act_name\n" if act_name else ""
    scope_clause = (
        "AND ($territorial_scope IN s.territorial_scope OR 'All Malaysia' IN s.territorial_scope)\n"
        if territorial_scope and territorial_scope != TerritorialScope.ALL_MALAYSIA.value
        else ""
    )
    query = (
        "MATCH (s:StatutoryNode)\n"
        "WHERE s.valid_from <= date($as_of_date)\n"
        "  AND (s.valid_to IS NULL OR s.valid_to > date($as_of_date))\n"
        f"  {act_clause}"
        f"  {scope_clause}"
        "  AND NOT EXISTS {\n"
        "    MATCH (s)-[r:REPEALED_BY]->(:StatutoryNode)\n"
        "    WHERE r.effective_date <= date($as_of_date)\n"
        "  }\n"
        f"OPTIONAL MATCH (s)-[:CITES|BM_EN_EQUIVALENT|HAS_TRANSLATION*1..{hops}]-(cited:StatutoryNode)\n"
        "WHERE cited.valid_from <= date($as_of_date)\n"
        "  AND (cited.valid_to IS NULL OR cited.valid_to > date($as_of_date))\n"
        "  AND NOT EXISTS {\n"
        "    MATCH (cited)-[cr:REPEALED_BY]->(:StatutoryNode)\n"
        "    WHERE cr.effective_date <= date($as_of_date)\n"
        "  }\n"
        "OPTIONAL MATCH (c:StatutoryNode)-[jt:INTERPRETS|APPLIES|DISTINGUISHES]->(s)\n"
        "WHERE c.effective_from <= date($as_of_date)\n"
        "RETURN s, collect(DISTINCT cited) AS cited_context, collect(DISTINCT c) AS judicial_context\n"
        "ORDER BY s.authority_tier ASC, s.act_name, s.section_code"
    )
    params: dict[str, Any] = {"as_of_date": as_of_date.isoformat()}
    if act_name:
        params["act_name"] = act_name
    if territorial_scope and territorial_scope != TerritorialScope.ALL_MALAYSIA.value:
        params["territorial_scope"] = territorial_scope
    return CypherQueryBundle(query=query, params=params)


class TemporalGraphStore:
    """
    Bi-temporal, bilingual, hierarchy-aware Malaysian legal knowledge graph store
    supporting Act -> Part -> Chapter -> Section -> Subsection -> Proviso/Illustration ->
    SourceSpan provenance, BM/EN crosswalk, Gazette versioning, and judicial treatment.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, StatutoryNode] = {}
        self._edges: list[StatutoryEdge] = []

    @property
    def nodes(self) -> dict[str, StatutoryNode]:
        return dict(self._nodes)

    @property
    def edges(self) -> list[StatutoryEdge]:
        return list(self._edges)

    def upsert_node(
        self,
        node: StatutoryNode,
        amends_node_id: str | None = None,
    ) -> CypherQueryBundle:
        """
        Inserts or updates a statutory or judicial node. If `amends_node_id` is provided,
        closes the predecessor's `valid_to` at `eff_date` and sets `effective_to` to
        `eff_date - 1 day`, sets `is_in_force = False`, and records `AMENDED_BY`,
        `SUPERSEDED_BY`, and `AMENDS` edges.
        """
        eff_date = node.effective_from or node.valid_from
        if amends_node_id and amends_node_id in self._nodes:
            prev = self._nodes[amends_node_id]
            prev_eff_to = eff_date - timedelta(days=1)
            updated_prev = prev.model_copy(
                update={
                    "valid_to": eff_date,
                    "effective_to": prev_eff_to if prev_eff_to >= (prev.effective_from or prev.valid_from) else eff_date,
                    "is_in_force": False,
                    "status": StatutoryStatus.AMENDED,
                }
            )
            self._nodes[amends_node_id] = updated_prev
            self.add_edge(
                StatutoryEdge(
                    source_id=amends_node_id,
                    target_id=node.node_id,
                    edge_type=TemporalEdgeType.AMENDED_BY,
                    effective_date=eff_date,
                    gazette_ref=node.amendment_act_ref or node.gazette_ref,
                )
            )
            self.add_edge(
                StatutoryEdge(
                    source_id=amends_node_id,
                    target_id=node.node_id,
                    edge_type=TemporalEdgeType.SUPERSEDED_BY,
                    effective_date=eff_date,
                    gazette_ref=node.amendment_act_ref or node.gazette_ref,
                )
            )
            self.add_edge(
                StatutoryEdge(
                    source_id=node.node_id,
                    target_id=amends_node_id,
                    edge_type=TemporalEdgeType.AMENDS,
                    effective_date=eff_date,
                    gazette_ref=node.amendment_act_ref or node.gazette_ref,
                )
            )

        self._nodes[node.node_id] = node

        if node.parent_node_id and node.parent_node_id in self._nodes:
            self.add_edge(
                StatutoryEdge(
                    source_id=node.node_id,
                    target_id=node.parent_node_id,
                    edge_type=TemporalEdgeType.PART_OF,
                    effective_date=eff_date,
                    gazette_ref=node.gazette_ref,
                )
            )
            edge_map = {
                HierarchyLevel.PART: TemporalEdgeType.HAS_PART,
                HierarchyLevel.CHAPTER: TemporalEdgeType.HAS_CHAPTER,
                HierarchyLevel.SECTION: TemporalEdgeType.HAS_SECTION,
                HierarchyLevel.SUBSECTION: TemporalEdgeType.HAS_SUBSECTION,
                HierarchyLevel.PROVISO: TemporalEdgeType.HAS_PROVISO,
                HierarchyLevel.ILLUSTRATION: TemporalEdgeType.HAS_ILLUSTRATION,
                HierarchyLevel.SOURCE_SPAN: TemporalEdgeType.HAS_SOURCE_SPAN,
            }
            rel_type = edge_map.get(node.hierarchy_level)
            if rel_type:
                self.add_edge(
                    StatutoryEdge(
                        source_id=node.parent_node_id,
                        target_id=node.node_id,
                        edge_type=rel_type,
                        effective_date=eff_date,
                        gazette_ref=node.gazette_ref,
                    )
                )

        return build_upsert_amendment_cypher(node, predecessor_node_id=amends_node_id)

    def repeal_node(
        self,
        target_node_id: str,
        repealing_node_id: str,
        effective_date: date,
        gazette_ref: str | None = None,
    ) -> CypherQueryBundle:
        """Marks `target_node_id` as repealed by `repealing_node_id` on `effective_date`."""
        if target_node_id not in self._nodes:
            raise KeyError(
                f"Target statutory node '{target_node_id}' not found in graph."
            )
        if repealing_node_id not in self._nodes:
            raise KeyError(
                f"Repealing statutory node '{repealing_node_id}' not found in graph."
            )

        target = self._nodes[target_node_id]
        prev_eff_to = effective_date - timedelta(days=1)
        self._nodes[target_node_id] = target.model_copy(
            update={
                "valid_to": effective_date,
                "effective_to": prev_eff_to if prev_eff_to >= (target.effective_from or target.valid_from) else effective_date,
                "is_in_force": False,
                "status": StatutoryStatus.REPEALED,
            }
        )
        self.add_edge(
            StatutoryEdge(
                source_id=target_node_id,
                target_id=repealing_node_id,
                edge_type=TemporalEdgeType.REPEALED_BY,
                effective_date=effective_date,
                gazette_ref=gazette_ref,
            )
        )
        self.add_edge(
            StatutoryEdge(
                source_id=repealing_node_id,
                target_id=target_node_id,
                edge_type=TemporalEdgeType.REPEALS,
                effective_date=effective_date,
                gazette_ref=gazette_ref,
            )
        )
        return build_repeal_cypher(
            target_node_id, repealing_node_id, effective_date, gazette_ref=gazette_ref
        )

    def add_edge(self, edge: StatutoryEdge) -> None:
        if edge not in self._edges:
            self._edges.append(edge)

    def add_citation(
        self,
        source_id: str,
        target_id: str,
        effective_date: date,
        gazette_ref: str | None = None,
    ) -> None:
        self.add_edge(
            StatutoryEdge(
                source_id=source_id,
                target_id=target_id,
                edge_type=TemporalEdgeType.CITES,
                effective_date=effective_date,
                gazette_ref=gazette_ref,
            )
        )

    def add_judicial_treatment(
        self,
        case_node_id: str,
        target_node_id: str,
        edge_type: TemporalEdgeType,
        effective_date: date,
        gazette_ref: str | None = None,
    ) -> None:
        """Records INTERPRETS, APPLIES, DISTINGUISHES, or OVERRULES edges from a case node."""
        allowed = {
            TemporalEdgeType.INTERPRETS,
            TemporalEdgeType.APPLIES,
            TemporalEdgeType.DISTINGUISHES,
            TemporalEdgeType.OVERRULES,
        }
        if edge_type not in allowed:
            raise ValueError(f"Unsupported judicial treatment edge type: {edge_type}")
        self.add_edge(
            StatutoryEdge(
                source_id=case_node_id,
                target_id=target_node_id,
                edge_type=edge_type,
                effective_date=effective_date,
                gazette_ref=gazette_ref,
            )
        )

    def link_translation(
        self,
        en_node_id: str,
        bm_node_id: str,
        authoritative_node_id: str,
        effective_date: date,
        gazette_ref: str | None = None,
    ) -> None:
        """
        Links parallel English and Bahasa Melayu nodes with bidirectional BM_EN_EQUIVALENT,
        HAS_TRANSLATION, and AUTHORITATIVE_TEXT edges.
        """
        if en_node_id in self._nodes:
            self._nodes[en_node_id] = self._nodes[en_node_id].model_copy(
                update={
                    "translation_node_id": bm_node_id,
                    "authoritative_language": authoritative_node_id == en_node_id,
                }
            )
        if bm_node_id in self._nodes:
            self._nodes[bm_node_id] = self._nodes[bm_node_id].model_copy(
                update={
                    "translation_node_id": en_node_id,
                    "authoritative_language": authoritative_node_id == bm_node_id,
                }
            )

        for rel_type in (
            TemporalEdgeType.HAS_TRANSLATION,
            TemporalEdgeType.BM_EN_EQUIVALENT,
        ):
            self.add_edge(
                StatutoryEdge(
                    source_id=en_node_id,
                    target_id=bm_node_id,
                    edge_type=rel_type,
                    effective_date=effective_date,
                    gazette_ref=gazette_ref,
                )
            )
            self.add_edge(
                StatutoryEdge(
                    source_id=bm_node_id,
                    target_id=en_node_id,
                    edge_type=rel_type,
                    effective_date=effective_date,
                    gazette_ref=gazette_ref,
                )
            )
        other_id = bm_node_id if authoritative_node_id == en_node_id else en_node_id
        self.add_edge(
            StatutoryEdge(
                source_id=other_id,
                target_id=authoritative_node_id,
                edge_type=TemporalEdgeType.AUTHORITATIVE_TEXT,
                effective_date=effective_date,
                gazette_ref=gazette_ref,
            )
        )

    def _is_repealed_on_or_before(self, node_id: str, as_of_date: date) -> bool:
        return any(
            (
                (
                    edge.source_id == node_id
                    and edge.edge_type == TemporalEdgeType.REPEALED_BY
                )
                or (
                    edge.target_id == node_id
                    and edge.edge_type == TemporalEdgeType.REPEALS
                )
            )
            and edge.effective_date <= as_of_date
            for edge in self._edges
        )

    def _is_node_valid_on(self, node: StatutoryNode, as_of_date: date) -> bool:
        return node.is_active_on(as_of_date) and not self._is_repealed_on_or_before(
            node.node_id, as_of_date
        )

    def _overruling_case_on(self, node_id: str, as_of_date: date) -> str | None:
        for edge in self._edges:
            if (
                edge.target_id == node_id
                and edge.edge_type == TemporalEdgeType.OVERRULES
                and edge.effective_date <= as_of_date
            ):
                return edge.source_id
        return None

    def query_point_in_time(
        self,
        as_of_date: date,
        act_name: str | None = None,
        include_citations: bool = True,
        max_hops: int = 2,
        language: str | None = None,
        territorial_scope: TerritorialScope | str | None = None,
        include_containers: bool = False,
        include_translations: bool = False,
        include_cases: bool = False,
    ) -> list[StatutoryNode]:
        """
        Resolves StatutoryNodes active on `as_of_date`, optionally filtered by `act_name`,
        `language`, and `territorial_scope`, and traverses multi-hop `CITES` (and optionally
        `HAS_TRANSLATION` / `BM_EN_EQUIVALENT`) edges valid on `as_of_date`.
        """
        excluded_levels: set[HierarchyLevel] = set()
        if not include_containers:
            excluded_levels.update(
                {
                    HierarchyLevel.ACT,
                    HierarchyLevel.PART,
                    HierarchyLevel.CHAPTER,
                    HierarchyLevel.PROVISO,
                    HierarchyLevel.ILLUSTRATION,
                }
            )
        if not include_cases:
            excluded_levels.add(HierarchyLevel.CASE)

        seed_candidates = [
            node
            for node in self._nodes.values()
            if self._is_node_valid_on(node, as_of_date)
            and (act_name is None or node.act_name == act_name)
            and (
                language is None
                or node.language == language
                or node.normalized_language == ("ms" if language in {"bm", "ms"} else language)
            )
            and node.hierarchy_level not in excluded_levels
        ]
        seed_nodes = filter_by_territorial_scope(seed_candidates, territorial_scope)

        resolved: dict[str, StatutoryNode] = {n.node_id: n for n in seed_nodes}

        if include_citations and max_hops > 0:
            allowed_edges = {TemporalEdgeType.CITES}
            if include_translations:
                allowed_edges.update(
                    {TemporalEdgeType.HAS_TRANSLATION, TemporalEdgeType.BM_EN_EQUIVALENT}
                )

            frontier = {n.node_id for n in seed_nodes}
            for _ in range(max_hops):
                next_frontier: set[str] = set()
                for src_id in frontier:
                    for edge in self._edges:
                        if (
                            edge.source_id == src_id
                            and edge.edge_type in allowed_edges
                            and edge.effective_date <= as_of_date
                        ):
                            cited_node = self._nodes.get(edge.target_id)
                            if (
                                cited_node
                                and cited_node.node_id not in resolved
                                and self._is_node_valid_on(cited_node, as_of_date)
                                and cited_node.hierarchy_level not in excluded_levels
                                and (
                                    language is None
                                    or cited_node.language == language
                                    or cited_node.normalized_language
                                    == ("ms" if language in {"bm", "ms"} else language)
                                )
                            ):
                                scoped = filter_by_territorial_scope(
                                    [cited_node], territorial_scope
                                )
                                if scoped:
                                    resolved[cited_node.node_id] = cited_node
                                    next_frontier.add(cited_node.node_id)
                if not next_frontier:
                    break
                frontier = next_frontier

        return sorted(
            resolved.values(),
            key=lambda n: (int(n.authority_tier), n.act_name, n.section_code, n.version),
        )

    def get_bilingual_pair(self, node_id: str) -> BilingualClausePair | None:
        """Returns paired English and Bahasa Melayu StatutoryNodes + SourceSpans for a node."""
        node = self._nodes.get(node_id)
        if not node:
            return None

        partner = (
            self._nodes.get(node.translation_node_id)
            if node.translation_node_id
            else None
        )
        en_node = (
            node
            if node.normalized_language == "en"
            else (partner if partner and partner.normalized_language == "en" else None)
        )
        bm_node = (
            node
            if node.normalized_language == "ms"
            else (partner if partner and partner.normalized_language == "ms" else None)
        )

        auth_id = node.node_id
        if partner and partner.authoritative_language and not node.authoritative_language:
            auth_id = partner.node_id

        spans: list[SourceSpan] = []
        if en_node:
            spans.extend(en_node.source_spans)
        if bm_node:
            spans.extend(bm_node.source_spans)

        return BilingualClausePair(
            section_code=node.section_code,
            act_name=node.act_name,
            act_number=node.act_number,
            en_node=en_node,
            bm_node=bm_node,
            authoritative_node_id=auth_id,
            gazette_ref=node.gazette_ref,
            source_spans=spans,
        )

    def get_hierarchy_chain(self, node_id: str) -> list[StatutoryNode]:
        """Walks parent pointers up to Act level and returns ordered hierarchy chain."""
        chain: list[StatutoryNode] = []
        cursor = self._nodes.get(node_id)
        seen: set[str] = set()
        while cursor and cursor.node_id not in seen:
            seen.add(cursor.node_id)
            chain.append(cursor)
            cursor = (
                self._nodes.get(cursor.parent_node_id)
                if cursor.parent_node_id
                else None
            )
        chain.reverse()
        return chain

    def search_with_abstention(
        self,
        query: str,
        as_of_date: date | None = None,
        territorial_scope: TerritorialScope | str | None = None,
        abstention_threshold: float = 0.78,
        act_name: str | None = None,
    ) -> RetrievalSearchResponse:
        """
        Hybrid bi-temporal + bilingual + 5-tier authority reranked retrieval with
        deterministic Abstention Gate at `abstention_threshold` (default 0.78).
        """
        effective_date = as_of_date or date.today()
        active_nodes = self.query_point_in_time(
            as_of_date=effective_date,
            act_name=act_name,
            include_citations=True,
            include_translations=True,
            territorial_scope=territorial_scope,
        )
        (
            is_abstained,
            max_score,
            normalized_query,
            detected_lang,
            ranked_spans,
        ) = rerank_statutes_and_spans(
            query=query,
            nodes=active_nodes,
            abstention_threshold=abstention_threshold,
            territorial_scope=territorial_scope,
        )

        if is_abstained:
            return RetrievalSearchResponse(
                query=query,
                normalized_query=normalized_query,
                detected_language=detected_lang,
                as_of_date=effective_date,
                territorial_scope=(
                    territorial_scope.value
                    if isinstance(territorial_scope, TerritorialScope)
                    else territorial_scope
                ),
                abstention_threshold=abstention_threshold,
                is_abstained=True,
                abstention_reason=(
                    f"ABSTAINED: Verified Malaysian statutory retrieval returned 0 SourceSpans "
                    f"above relevance threshold {abstention_threshold:.2f} "
                    f"(max_score={max_score:.4f}). Refusing ungrounded generation."
                ),
                max_relevance_score=max_score,
                results=[],
                bilingual_pairs=[],
            )

        pairs_by_key: dict[str, BilingualClausePair] = {}
        for item in ranked_spans:
            pair = self.get_bilingual_pair(item.node_id)
            if pair:
                dedup_key = f"{pair.act_number}:{pair.section_code}"
                if dedup_key not in pairs_by_key:
                    pairs_by_key[dedup_key] = pair

        return RetrievalSearchResponse(
            query=query,
            normalized_query=normalized_query,
            detected_language=detected_lang,
            as_of_date=effective_date,
            territorial_scope=(
                territorial_scope.value
                if isinstance(territorial_scope, TerritorialScope)
                else territorial_scope
            ),
            abstention_threshold=abstention_threshold,
            is_abstained=False,
            abstention_reason=None,
            max_relevance_score=max_score,
            results=ranked_spans,
            bilingual_pairs=list(pairs_by_key.values()),
        )

    def _collect_lineage_node_ids(self, seed_node_id: str) -> list[str]:
        """Collects all historical/successor node IDs in the same statutory lineage chain."""
        seed = self._nodes.get(seed_node_id)
        if not seed:
            return []

        lineage_edges = {
            TemporalEdgeType.SUPERSEDED_BY,
            TemporalEdgeType.AMENDS,
            TemporalEdgeType.AMENDED_BY,
            TemporalEdgeType.REPEALED_BY,
            TemporalEdgeType.REPEALS,
        }
        visited: set[str] = {seed_node_id}
        queue: list[str] = [seed_node_id]
        while queue:
            cur = queue.pop(0)
            for edge in self._edges:
                if edge.edge_type not in lineage_edges:
                    continue
                if edge.source_id == cur and edge.target_id in self._nodes and edge.target_id not in visited:
                    visited.add(edge.target_id)
                    queue.append(edge.target_id)
                elif edge.target_id == cur and edge.source_id in self._nodes and edge.source_id not in visited:
                    visited.add(edge.source_id)
                    queue.append(edge.source_id)

        for nid, candidate in self._nodes.items():
            if (
                candidate.act_number == seed.act_number
                and candidate.section_code == seed.section_code
                and candidate.normalized_language == seed.normalized_language
                and candidate.hierarchy_level == seed.hierarchy_level
            ):
                visited.add(nid)

        ordered = sorted(
            (self._nodes[nid] for nid in visited),
            key=lambda n: (n.version, n.effective_from or n.valid_from, n.node_id),
        )
        return [n.node_id for n in ordered]

    def _collect_judicial_treatments(
        self,
        target_node_ids: set[str],
        as_of_date: date,
    ) -> list[JudicialTreatmentItem]:
        """
        Traverses INTERPRETS, APPLIES, DISTINGUISHES, and OVERRULES edges targeting any
        provision in `target_node_ids` (including BM/EN equivalents) valid as of `as_of_date`.
        """
        treatment_edges = {
            TemporalEdgeType.INTERPRETS,
            TemporalEdgeType.APPLIES,
            TemporalEdgeType.DISTINGUISHES,
            TemporalEdgeType.OVERRULES,
        }
        items: list[JudicialTreatmentItem] = []
        seen_keys: set[tuple[str, str, str]] = set()

        for edge in self._edges:
            if (
                edge.edge_type in treatment_edges
                and edge.target_id in target_node_ids
                and edge.effective_date <= as_of_date
            ):
                case_node = self._nodes.get(edge.source_id)
                if not case_node or case_node.hierarchy_level != HierarchyLevel.CASE:
                    continue
                if not self._is_node_valid_on(case_node, as_of_date):
                    continue
                dedup = (case_node.node_id, edge.edge_type.value, edge.target_id)
                if dedup in seen_keys:
                    continue
                seen_keys.add(dedup)

                overruled_by = self._overruling_case_on(case_node.node_id, as_of_date)
                is_overruled = overruled_by is not None or (
                    case_node.is_overruled and overruled_by is not None
                )
                if case_node.is_overruled and overruled_by is None:
                    # Only treat static is_overruled=True if no future-dated OVERRULES edge exists
                    has_future_overrule = any(
                        e.target_id == case_node.node_id
                        and e.edge_type == TemporalEdgeType.OVERRULES
                        and e.effective_date > as_of_date
                        for e in self._edges
                    )
                    is_overruled = not has_future_overrule

                items.append(
                    JudicialTreatmentItem(
                        case_node_id=case_node.node_id,
                        case_title=case_node.act_name,
                        case_citation=case_node.case_citation or case_node.act_number,
                        court_name=case_node.court_name or AUTHORITY_LABELS.get(case_node.authority_tier, "Court"),
                        authority_tier=case_node.authority_tier,
                        authority_label=AUTHORITY_LABELS.get(
                            case_node.authority_tier, "Tier 6: High Court"
                        ),
                        treatment_type=edge.edge_type,
                        target_node_id=edge.target_id,
                        decision_date=case_node.effective_from or case_node.valid_from,
                        is_overruled=is_overruled,
                        overruled_by_node_id=overruled_by,
                        extract_text=case_node.text,
                        source_spans=list(case_node.source_spans),
                    )
                )

        items.sort(
            key=lambda it: (
                it.is_overruled,
                int(it.authority_tier),
                -it.decision_date.toordinal(),
                it.case_node_id,
            )
        )
        return items

    def _to_timeline_entry(
        self,
        node: StatutoryNode,
        as_of_date: date,
    ) -> AmendmentTimelineEntry:
        eff_from = node.effective_from or node.valid_from
        eff_to = node.effective_to
        if eff_to is None and node.valid_to is not None:
            eff_to = node.valid_to - timedelta(days=1)
        is_active_at_query = self._is_node_valid_on(node, as_of_date)
        return AmendmentTimelineEntry(
            node_id=node.node_id,
            act_name=node.act_name,
            act_number=node.act_number,
            section_code=node.section_code,
            version=node.version,
            language=node.normalized_language,
            effective_from=eff_from,
            effective_to=eff_to,
            is_in_force=node.is_in_force,
            is_active_at_query_date=is_active_at_query,
            status=node.status,
            amendment_act_ref=node.amendment_act_ref or node.gazette_ref,
            text=node.text,
            source_spans=list(node.source_spans),
        )

    def get_provision_lineage(
        self,
        provision_id: str,
        as_of_date: date | None = None,
        include_repealed_lineage: bool = True,
    ) -> ProvisionLineageResponse:
        """
        Returns the full chronological amendment history, linked BM/EN counterpart text,
        judicial treatments, and lineage edges for a provision node.
        """
        seed = self._nodes.get(provision_id)
        if not seed:
            raise KeyError(f"Provision '{provision_id}' not found.")

        effective_date = as_of_date or date.today()
        lineage_ids = self._collect_lineage_node_ids(provision_id)
        timeline: list[AmendmentTimelineEntry] = []
        active_node_id: str | None = None

        for nid in lineage_ids:
            node = self._nodes[nid]
            entry = self._to_timeline_entry(node, effective_date)
            if entry.is_active_at_query_date:
                active_node_id = node.node_id
            if include_repealed_lineage or entry.is_active_at_query_date:
                timeline.append(entry)

        pair_target = active_node_id or provision_id
        bilingual_equiv = self.get_bilingual_pair(pair_target)

        treatment_targets: set[str] = set(lineage_ids)
        if bilingual_equiv:
            if bilingual_equiv.en_node:
                treatment_targets.update(
                    self._collect_lineage_node_ids(bilingual_equiv.en_node.node_id)
                )
            if bilingual_equiv.bm_node:
                treatment_targets.update(
                    self._collect_lineage_node_ids(bilingual_equiv.bm_node.node_id)
                )

        treatments = self._collect_judicial_treatments(treatment_targets, effective_date)
        subgraph_ids = set(treatment_targets) | {t.case_node_id for t in treatments}
        lineage_edges = [
            e
            for e in self._edges
            if e.source_id in subgraph_ids and e.target_id in subgraph_ids
        ]

        return ProvisionLineageResponse(
            provision_id=provision_id,
            act_name=seed.act_name,
            act_number=seed.act_number,
            section_code=seed.section_code,
            as_of_date=effective_date,
            current_active_node_id=active_node_id,
            amendment_timeline=timeline,
            bilingual_equivalent=bilingual_equiv,
            judicial_treatments=treatments,
            lineage_edges=lineage_edges,
        )

    def execute_point_in_time_research(
        self,
        req: PointInTimeResearchRequest,
    ) -> PointInTimeResearchResponse:
        """
        Executes the 4-stage Point-in-Time Graph-First Retrieval & Zero-Hallucination Guardrail:
        1. Temporal Graph Traversal (strict effective_from <= as_of_date <= effective_to)
        2. Bilingual Graph Expansion (BM_EN_EQUIVALENT & judicial INTERPRETS/APPLIES/OVERRULES)
        3. Hybrid/Semantic Fallback & 7-Tier Malaysian Authority Reranking
        4. Grounded Evidence Pack & Deterministic Refusal Guardrail
        """
        effective_date = req.as_of_date or date.today()
        raw_mode = req.language_mode.lower()
        lang_mode: Literal["ms", "en", "bilingual"] = (
            "ms" if raw_mode in {"ms", "bm"} else ("en" if raw_mode == "en" else "bilingual")
        )
        threshold = req.abstention_threshold if req.abstention_threshold is not None else 0.65

        with measure_latency_ms() as elapsed_holder:
            normalized_query, detected_lang, expanded_terms = normalize_and_expand_query(req.query)

            # Stage 1: Active statutory nodes on as_of_date
            candidate_statutes = self.query_point_in_time(
                as_of_date=effective_date,
                include_citations=False,
                include_translations=False,
                include_containers=False,
                include_cases=False,
                territorial_scope=req.territorial_scope,
            )

            statute_scores: dict[str, float] = {}
            matched_statutes: list[StatutoryNode] = []
            for node in candidate_statutes:
                score = compute_hybrid_relevance_score(
                    query=req.query,
                    normalized_query=normalized_query,
                    expanded_terms=expanded_terms,
                    node=node,
                )
                statute_scores[node.node_id] = score
                if score >= threshold:
                    matched_statutes.append(node)

            # Fallback: check active judicial precedent nodes directly if no statute matched
            matched_cases: dict[str, tuple[StatutoryNode, float]] = {}
            if not matched_statutes:
                candidate_cases = [
                    n
                    for n in self._nodes.values()
                    if n.hierarchy_level == HierarchyLevel.CASE
                    and self._is_node_valid_on(n, effective_date)
                ]
                for cnode in filter_by_territorial_scope(candidate_cases, req.territorial_scope):
                    cscore = compute_hybrid_relevance_score(
                        query=req.query,
                        normalized_query=normalized_query,
                        expanded_terms=expanded_terms,
                        node=cnode,
                    )
                    if cscore >= threshold:
                        matched_cases[cnode.node_id] = (cnode, cscore)

            if not matched_statutes and not matched_cases:
                telemetry = compute_telemetry_summary(
                    prompt_tokens=0,
                    completion_tokens=0,
                    latency_ms=elapsed_holder[0],
                    retry_count=0,
                    is_verified_grounded=True,
                    trace_id=f"pit-{uuid.uuid4().hex[:8]}",
                )
                cypher_bundle = build_point_in_time_cypher(
                    as_of_date=effective_date,
                    territorial_scope=(
                        req.territorial_scope.value
                        if isinstance(req.territorial_scope, TerritorialScope)
                        else req.territorial_scope
                    ),
                )
                refusal_msg = (
                    f"INSUFFICIENT_EVIDENCE: Verified Malaysian statutory and judicial graph traversal "
                    f"returned 0 SourceSpans above threshold {threshold:.2f} as of {effective_date.isoformat()}. "
                    "Refusing ungrounded generation."
                )
                return PointInTimeResearchResponse(
                    status="insufficient_evidence",
                    query=req.query,
                    normalized_query=normalized_query,
                    detected_language=detected_lang,
                    language_mode=lang_mode,
                    as_of_date=effective_date,
                    include_repealed_lineage=req.include_repealed_lineage,
                    is_abstained=True,
                    refusal_reason=refusal_msg,
                    answer=refusal_msg,
                    claims=[],
                    citations=[],
                    authority_breakdown=[],
                    amendment_timeline=[],
                    bilingual_crosswalk=[],
                    judicial_treatments=[],
                    subgraph=SubgraphVisualizationData(
                        nodes=[],
                        edges=[],
                        cypher_query=cypher_bundle.query,
                    ),
                    telemetry=telemetry,
                    disclaimer=DEFAULT_LEGAL_DISCLAIMER,
                )

            # Stage 2: Bilingual Graph Expansion (BM_EN_EQUIVALENT & CITES & Judicial Edges)
            expanded_statutes: dict[str, StatutoryNode] = {n.node_id: n for n in matched_statutes}
            bilingual_pairs_map: dict[str, BilingualClausePair] = {}
            traversal_target_ids: set[str] = set()

            for node in matched_statutes:
                traversal_target_ids.add(node.node_id)
                pair = self.get_bilingual_pair(node.node_id)
                if pair:
                    dedup_key = f"{pair.act_number}:{pair.section_code}"
                    if dedup_key not in bilingual_pairs_map:
                        bilingual_pairs_map[dedup_key] = pair
                    if pair.en_node and self._is_node_valid_on(pair.en_node, effective_date):
                        expanded_statutes.setdefault(pair.en_node.node_id, pair.en_node)
                        statute_scores.setdefault(
                            pair.en_node.node_id, statute_scores.get(node.node_id, threshold)
                        )
                        traversal_target_ids.add(pair.en_node.node_id)
                    if pair.bm_node and self._is_node_valid_on(pair.bm_node, effective_date):
                        expanded_statutes.setdefault(pair.bm_node.node_id, pair.bm_node)
                        statute_scores.setdefault(
                            pair.bm_node.node_id, statute_scores.get(node.node_id, threshold)
                        )
                        traversal_target_ids.add(pair.bm_node.node_id)

            # Follow 1-hop CITES edges from active statutes
            for src_id in list(expanded_statutes.keys()):
                for edge in self._edges:
                    if (
                        edge.source_id == src_id
                        and edge.edge_type == TemporalEdgeType.CITES
                        and edge.effective_date <= effective_date
                    ):
                        cited = self._nodes.get(edge.target_id)
                        if cited and self._is_node_valid_on(cited, effective_date):
                            expanded_statutes.setdefault(cited.node_id, cited)
                            statute_scores.setdefault(
                                cited.node_id,
                                max(
                                    0.70,
                                    compute_hybrid_relevance_score(
                                        req.query, normalized_query, expanded_terms, cited
                                    ),
                                ),
                            )
                            traversal_target_ids.add(cited.node_id)

            # Collect full amendment timeline for matched statutes (and their equivalents)
            timeline_map: dict[str, AmendmentTimelineEntry] = {}
            lineage_all_ids: set[str] = set(traversal_target_ids)
            for sid in list(expanded_statutes.keys()):
                for lid in self._collect_lineage_node_ids(sid):
                    lineage_all_ids.add(lid)
                    lnode = self._nodes[lid]
                    entry = self._to_timeline_entry(lnode, effective_date)
                    if (
                        req.include_repealed_lineage or entry.is_active_at_query_date
                    ) and (
                        lang_mode == "bilingual" or lnode.normalized_language == lang_mode
                    ):
                        timeline_map[lid] = entry

            if not timeline_map:
                for lid in lineage_all_ids:
                    lnode = self._nodes[lid]
                    entry = self._to_timeline_entry(lnode, effective_date)
                    if req.include_repealed_lineage or entry.is_active_at_query_date:
                        timeline_map[lid] = entry

            amendment_timeline = sorted(
                timeline_map.values(),
                key=lambda e: (e.act_number, e.section_code, e.language, e.version, e.effective_from),
            )

            # Gather judicial treatments interpreting/applying any node in the matched set,
            # its bilingual counterpart, or (when include_repealed_lineage=True) its lineage chain
            judicial_targets = (
                lineage_all_ids if req.include_repealed_lineage else traversal_target_ids
            )
            judicial_treatments = self._collect_judicial_treatments(
                judicial_targets, effective_date
            )
            # Also include any directly matched fallback case nodes
            seen_case_ids = {jt.case_node_id for jt in judicial_treatments}
            for cid, (cnode, _) in matched_cases.items():
                if cid not in seen_case_ids:
                    overruled_by = self._overruling_case_on(cid, effective_date)
                    judicial_treatments.append(
                        JudicialTreatmentItem(
                            case_node_id=cid,
                            case_title=cnode.act_name,
                            case_citation=cnode.case_citation or cnode.act_number,
                            court_name=cnode.court_name or "Court",
                            authority_tier=cnode.authority_tier,
                            authority_label=AUTHORITY_LABELS.get(
                                cnode.authority_tier, "Tier 6: High Court"
                            ),
                            treatment_type=TemporalEdgeType.INTERPRETS,
                            target_node_id=cid,
                            decision_date=cnode.effective_from or cnode.valid_from,
                            is_overruled=overruled_by is not None or cnode.is_overruled,
                            overruled_by_node_id=overruled_by,
                            extract_text=cnode.text,
                            source_spans=list(cnode.source_spans),
                        )
                    )

            # Stage 3: 7-Tier Malaysian Authority Reranking
            selected_statutes = [
                n
                for n in expanded_statutes.values()
                if lang_mode == "bilingual" or n.normalized_language == lang_mode
            ]
            if not selected_statutes:
                selected_statutes = list(expanded_statutes.values())

            authority_breakdown: list[AuthorityBreakdownItem] = []
            for snode in selected_statutes:
                rel_score = statute_scores.get(snode.node_id, threshold)
                auth_w = AUTHORITY_WEIGHTS.get(snode.authority_tier, 0.70)
                final_score = round(
                    max(0.0, min(1.0, 0.75 * auth_w + 0.25 * rel_score)),
                    4,
                )
                eff_to = snode.effective_to
                if eff_to is None and snode.valid_to is not None:
                    eff_to = snode.valid_to - timedelta(days=1)
                authority_breakdown.append(
                    AuthorityBreakdownItem(
                        node_id=snode.node_id,
                        title=f"{snode.act_name} ({snode.section_code} v{snode.version})",
                        canonical_citation=f"{snode.act_number} {snode.section_code}",
                        hierarchy_level=snode.hierarchy_level,
                        authority_tier=snode.authority_tier,
                        authority_label=AUTHORITY_LABELS.get(
                            snode.authority_tier, "Tier 2: Acts of Parliament (Akta) & State Enactments"
                        ),
                        authority_weight=auth_w,
                        relevance_score=round(rel_score, 4),
                        final_score=final_score,
                        language=snode.normalized_language,
                        effective_from=snode.effective_from or snode.valid_from,
                        effective_to=eff_to,
                        treatment_type=None,
                        is_overruled=False,
                        overruled_by_node_id=None,
                        source_span_ids=[sp.span_id for sp in snode.source_spans],
                    )
                )

            added_case_breakdown: set[str] = set()
            for jt in judicial_treatments:
                if jt.case_node_id in added_case_breakdown:
                    continue
                added_case_breakdown.add(jt.case_node_id)
                cnode = self._nodes[jt.case_node_id]
                rel_score = matched_cases.get(jt.case_node_id, (cnode, 0.85))[1]
                auth_w = AUTHORITY_WEIGHTS.get(jt.authority_tier, 0.50)
                penalty = 0.25 if jt.is_overruled else 0.0
                final_score = round(
                    max(0.0, min(1.0, 0.75 * auth_w + 0.25 * rel_score - penalty)),
                    4,
                )
                authority_breakdown.append(
                    AuthorityBreakdownItem(
                        node_id=jt.case_node_id,
                        title=jt.case_title,
                        canonical_citation=jt.case_citation,
                        hierarchy_level=HierarchyLevel.CASE,
                        authority_tier=jt.authority_tier,
                        authority_label=jt.authority_label,
                        authority_weight=auth_w,
                        relevance_score=round(rel_score, 4),
                        final_score=final_score,
                        language=cnode.normalized_language,
                        effective_from=jt.decision_date,
                        effective_to=None,
                        treatment_type=jt.treatment_type.value,
                        is_overruled=jt.is_overruled,
                        overruled_by_node_id=jt.overruled_by_node_id,
                        source_span_ids=[sp.span_id for sp in jt.source_spans],
                    )
                )

            authority_breakdown.sort(
                key=lambda item: (
                    item.is_overruled,
                    int(item.authority_tier),
                    0.0 if item.hierarchy_level == HierarchyLevel.CASE else -item.relevance_score,
                    -item.effective_from.toordinal(),
                    -item.final_score,
                    item.node_id,
                )
            )

            # Stage 4: Collect immutable SourceSpans & construct grounded claims
            citations_by_id: dict[str, SourceSpan] = {}
            for snode in expanded_statutes.values():
                for sp in snode.source_spans:
                    citations_by_id.setdefault(sp.span_id, sp)
            for jt in judicial_treatments:
                for sp in jt.source_spans:
                    citations_by_id.setdefault(sp.span_id, sp)

            citations = list(citations_by_id.values())
            if not citations:
                telemetry = compute_telemetry_summary(
                    prompt_tokens=0,
                    completion_tokens=0,
                    latency_ms=elapsed_holder[0],
                    retry_count=0,
                    is_verified_grounded=True,
                    trace_id=f"pit-{uuid.uuid4().hex[:8]}",
                )
                return PointInTimeResearchResponse(
                    status="insufficient_evidence",
                    query=req.query,
                    normalized_query=normalized_query,
                    detected_language=detected_lang,
                    language_mode=lang_mode,
                    as_of_date=effective_date,
                    include_repealed_lineage=req.include_repealed_lineage,
                    is_abstained=True,
                    refusal_reason=(
                        "INSUFFICIENT_EVIDENCE: 0 verified SourceSpans available for synthesis."
                    ),
                    answer="INSUFFICIENT_EVIDENCE: 0 verified SourceSpans available for synthesis.",
                    claims=[],
                    citations=[],
                    authority_breakdown=[],
                    amendment_timeline=[],
                    bilingual_crosswalk=[],
                    judicial_treatments=[],
                    subgraph=SubgraphVisualizationData(),
                    telemetry=telemetry,
                    disclaimer=DEFAULT_LEGAL_DISCLAIMER,
                )

            claims: list[GroundedClaim] = []
            for idx, snode in enumerate(
                sorted(
                    selected_statutes,
                    key=lambda n: (
                        int(n.authority_tier),
                        -statute_scores.get(n.node_id, 0.0),
                        n.node_id,
                    ),
                )[:3],
                start=1,
            ):
                s_span_ids = [sp.span_id for sp in snode.source_spans if sp.span_id in citations_by_id]
                if s_span_ids:
                    claims.append(
                        GroundedClaim(
                            claim_id=f"CLAIM-STAT-{idx}",
                            statement=(
                                f"As of {effective_date.isoformat()}, {snode.act_name} [{snode.act_number}] "
                                f"{snode.section_code} (v{snode.version}, {snode.normalized_language.upper()}) "
                                f"is in force: {snode.text}"
                            ),
                            source_span_ids=s_span_ids,
                            node_ids=[snode.node_id],
                            authority_tier=snode.authority_tier,
                        )
                    )

            for idx, jt in enumerate(judicial_treatments[:4], start=1):
                c_span_ids = [sp.span_id for sp in jt.source_spans if sp.span_id in citations_by_id]
                if c_span_ids:
                    overruled_tag = (
                        f" [OVERRULED by {jt.overruled_by_node_id}]" if jt.is_overruled else ""
                    )
                    claims.append(
                        GroundedClaim(
                            claim_id=f"CLAIM-CASE-{idx}",
                            statement=(
                                f"{jt.court_name} ({jt.case_citation}){overruled_tag} "
                                f"{jt.treatment_type.value.lower()} {jt.target_node_id}: {jt.extract_text}"
                            ),
                            source_span_ids=c_span_ids,
                            node_ids=[jt.case_node_id, jt.target_node_id],
                            authority_tier=jt.authority_tier,
                        )
                    )

            superseded_entries = [e for e in amendment_timeline if not e.is_active_at_query_date]
            if superseded_entries:
                hist = superseded_entries[0]
                for h_span in hist.source_spans:
                    citations_by_id.setdefault(h_span.span_id, h_span)
                citations = list(citations_by_id.values())
                hist_spans = [sp.span_id for sp in hist.source_spans if sp.span_id in citations_by_id]
                if hist_spans:
                    claims.append(
                        GroundedClaim(
                            claim_id="CLAIM-LINEAGE-1",
                            statement=(
                                f"Statutory lineage includes {hist.node_id} (v{hist.version}, effective "
                                f"{hist.effective_from.isoformat()} to "
                                f"{hist.effective_to.isoformat() if hist.effective_to else 'PRESENT'}, "
                                f"status={hist.status.value})."
                            ),
                            source_span_ids=hist_spans,
                            node_ids=[hist.node_id],
                            authority_tier=AuthorityTier.TIER_2_ACT_OF_PARLIAMENT,
                        )
                    )

            answer_parts = [f"[{c.claim_id}] {c.statement} (Sources: {', '.join(c.source_span_ids)})" for c in claims]
            answer_text = "\n".join(answer_parts)

            subgraph_node_ids = (
                lineage_all_ids
                | {jt.case_node_id for jt in judicial_treatments}
                | {jt.overruled_by_node_id for jt in judicial_treatments if jt.overruled_by_node_id}
            )
            subgraph_nodes = [
                self._nodes[nid] for nid in sorted(subgraph_node_ids) if nid in self._nodes
            ]
            subgraph_edges = [
                e
                for e in self._edges
                if e.source_id in subgraph_node_ids and e.target_id in subgraph_node_ids
            ]
            cypher_bundle = build_point_in_time_cypher(
                as_of_date=effective_date,
                territorial_scope=(
                    req.territorial_scope.value
                    if isinstance(req.territorial_scope, TerritorialScope)
                    else req.territorial_scope
                ),
            )

            telemetry = compute_telemetry_summary(
                prompt_tokens=0,
                completion_tokens=0,
                latency_ms=elapsed_holder[0],
                retry_count=0,
                is_verified_grounded=True,
                trace_id=f"pit-{uuid.uuid4().hex[:8]}",
            )

            return PointInTimeResearchResponse(
                status="grounded",
                query=req.query,
                normalized_query=normalized_query,
                detected_language=detected_lang,
                language_mode=lang_mode,
                as_of_date=effective_date,
                include_repealed_lineage=req.include_repealed_lineage,
                is_abstained=False,
                refusal_reason=None,
                answer=answer_text,
                claims=claims,
                citations=citations,
                authority_breakdown=authority_breakdown,
                amendment_timeline=amendment_timeline,
                bilingual_crosswalk=list(bilingual_pairs_map.values()),
                judicial_treatments=judicial_treatments,
                subgraph=SubgraphVisualizationData(
                    nodes=subgraph_nodes,
                    edges=subgraph_edges,
                    cypher_query=cypher_bundle.query,
                ),
                telemetry=telemetry,
                disclaimer=DEFAULT_LEGAL_DISCLAIMER,
            )


def _add_bilingual_pair(
    store: TemporalGraphStore,
    en_node: StatutoryNode,
    bm_node: StatutoryNode,
    authoritative: str = "bm",
    amends_en_id: str | None = None,
    amends_bm_id: str | None = None,
) -> None:
    store.upsert_node(en_node, amends_node_id=amends_en_id)
    store.upsert_node(bm_node, amends_node_id=amends_bm_id)
    auth_id = bm_node.node_id if authoritative == "bm" else en_node.node_id
    store.link_translation(
        en_node_id=en_node.node_id,
        bm_node_id=bm_node.node_id,
        authoritative_node_id=auth_id,
        effective_date=en_node.valid_from,
        gazette_ref=en_node.gazette_ref,
    )


def get_default_temporal_store() -> TemporalGraphStore:
    """
    Returns a pre-populated Malaysian Legal Knowledge Graph containing:
    - Tier 1: Federal Constitution (Art 8)
    - Tier 2: PDPA 2010 [Act 709] (2010 baseline vs 2024 Amendment [Act A1727]),
              Employment Act 1955 [Act 265] (Peninsular & FT)
    - Tier 3: Sabah Labour Ordinance [Cap. 67], Sarawak Labour Ordinance [Cap. 76]
    - Tier 4: P.U. (A) 342/2024 & P.U. (B) 512/2024 Subsidiary Gazettes
    - Tier 5: JPDP Circular / Guideline 01/2025
    with full Act -> Part -> Section -> Subsection -> SourceSpan hierarchy and
    synchronized EN <-> BM translations.
    """
    store = TemporalGraphStore()

    # =========================================================================
    # Hierarchy Containers for Act 709 (PDPA 2010)
    # =========================================================================
    pdpa_act = StatutoryNode(
        node_id="PDPA-2010-ACT",
        act_name="Personal Data Protection Act 2010",
        act_number="Act 709",
        section_code="ACT-709",
        hierarchy_level=HierarchyLevel.ACT,
        text="Personal Data Protection Act 2010 [Act 709]: An Act to regulate the processing of personal data in commercial transactions.",
        valid_from=date(2013, 11, 15),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 709",
    )
    store.upsert_node(pdpa_act)

    pdpa_part_ii = StatutoryNode(
        node_id="PDPA-2010-PART-II",
        act_name="Personal Data Protection Act 2010",
        act_number="Act 709",
        section_code="PART-II",
        part_code="PART-II",
        hierarchy_level=HierarchyLevel.PART,
        parent_node_id="PDPA-2010-ACT",
        text="Part II — Personal Data Protection Principles (Sections 5 to 12B).",
        valid_from=date(2013, 11, 15),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 709",
    )
    store.upsert_node(pdpa_part_ii)

    # =========================================================================
    # Tier 1: Federal Constitution (Article 8 - Equality)
    # =========================================================================
    fc_art8_en = StatutoryNode(
        node_id="FC-ART-8-V1",
        act_name="Federal Constitution",
        act_number="Federal Constitution",
        section_code="ART-8",
        hierarchy_level=HierarchyLevel.SECTION,
        language="en",
        text=(
            "Article 8 (Equality): All persons are equal before the law and entitled to the "
            "equal protection of the law. There shall be no discrimination against citizens on "
            "the ground of religion, race, descent, place of birth or gender."
        ),
        valid_from=date(1957, 8, 31),
        authority_tier=AuthorityTier.TIER_1_FEDERAL_CONSTITUTION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Federal Constitution Art. 8",
        source_spans=[
            SourceSpan(
                span_id="SPAN-FC-ART-8-EN",
                act_number="Federal Constitution",
                section_id="ART-8",
                language="en",
                pdf_page=19,
                char_offset_start=120,
                char_offset_end=338,
                text=(
                    "Article 8 (Equality): All persons are equal before the law and entitled to the "
                    "equal protection of the law."
                ),
            )
        ],
    )
    fc_art8_bm = StatutoryNode(
        node_id="FC-ART-8-V1-BM",
        act_name="Perlembagaan Persekutuan",
        act_number="Federal Constitution",
        section_code="ART-8",
        hierarchy_level=HierarchyLevel.SECTION,
        language="bm",
        text=(
            "Perkara 8 (Kesamarataan): Semua orang adalah sama rata di sisi undang-undang dan "
            "berhak mendapat perlindungan yang sama rata di sisi undang-undang tanpa diskriminasi."
        ),
        valid_from=date(1957, 8, 31),
        authority_tier=AuthorityTier.TIER_1_FEDERAL_CONSTITUTION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Perlembagaan Persekutuan Perkara 8",
        source_spans=[
            SourceSpan(
                span_id="SPAN-FC-ART-8-BM",
                act_number="Federal Constitution",
                section_id="PERKARA-8",
                language="bm",
                pdf_page=19,
                char_offset_start=120,
                char_offset_end=295,
                text=(
                    "Perkara 8 (Kesamarataan): Semua orang adalah sama rata di sisi undang-undang dan "
                    "berhak mendapat perlindungan yang sama rata di sisi undang-undang tanpa diskriminasi."
                ),
            )
        ],
    )
    _add_bilingual_pair(store, fc_art8_en, fc_art8_bm, authoritative="en")

    # =========================================================================
    # Tier 2: PDPA 2010 [Act 709] Core Sections (EN + BM Bilingual Pairs)
    # =========================================================================
    # Section 9 V1 (2013-11-15 to 2025-01-01)
    pdpa_sec9_v1_en = StatutoryNode(
        node_id="PDPA-2010-SEC-9-V1",
        act_name="Personal Data Protection Act 2010",
        act_number="Act 709",
        section_code="SEC-9",
        part_code="PART-II",
        parent_node_id="PDPA-2010-PART-II",
        version=1,
        language="en",
        text=(
            "Section 9 (Security Principle - 2010): A data user shall take practical steps "
            "to protect personal data from any loss, misuse, modification, unauthorized or "
            "accidental access or disclosure. No mandatory statutory breach notification "
            "timeline is prescribed under the 2010 baseline."
        ),
        valid_from=date(2013, 11, 15),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 709 (P.U. (B) 464/2013)",
        source_spans=[
            SourceSpan(
                span_id="SPAN-PDPA-SEC-9-V1-EN",
                act_number="Act 709",
                section_id="SEC-9",
                language="en",
                pdf_page=17,
                char_offset_start=412,
                char_offset_end=675,
                text=(
                    "Section 9 (Security Principle - 2010): A data user shall take practical steps "
                    "to protect personal data from any loss, misuse, modification, unauthorized or "
                    "accidental access or disclosure."
                ),
            )
        ],
    )
    pdpa_sec9_v1_bm = StatutoryNode(
        node_id="PDPA-2010-SEC-9-V1-BM",
        act_name="Akta Perlindungan Data Peribadi 2010",
        act_number="Act 709",
        section_code="SEC-9",
        part_code="PART-II",
        parent_node_id="PDPA-2010-PART-II",
        version=1,
        language="bm",
        text=(
            "Seksyen 9 (Prinsip Keselamatan - 2010): Seseorang pengguna data hendaklah mengambil "
            "langkah praktikal untuk melindungi data peribadi daripada apa-apa kehilangan, salah guna, "
            "ubah suaian, akses atau penzahiran tanpa kebenaran atau secara tidak sengaja."
        ),
        valid_from=date(2013, 11, 15),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 709 (P.U. (B) 464/2013)",
        source_spans=[
            SourceSpan(
                span_id="SPAN-PDPA-SEC-9-V1-BM",
                act_number="Act 709",
                section_id="SEKSYEN-9",
                language="bm",
                pdf_page=17,
                char_offset_start=390,
                char_offset_end=642,
                text=(
                    "Seksyen 9 (Prinsip Keselamatan - 2010): Seseorang pengguna data hendaklah mengambil "
                    "langkah praktikal untuk melindungi data peribadi."
                ),
            )
        ],
    )
    _add_bilingual_pair(store, pdpa_sec9_v1_en, pdpa_sec9_v1_bm, authoritative="bm")

    # Section 9 V2 (PDPA Amendment Act 2024 [Act A1727], effective 2025-01-01)
    pdpa_sec9_v2_en = StatutoryNode(
        node_id="PDPA-2010-SEC-9-V2",
        act_name="Personal Data Protection Act 2010",
        act_number="Act 709",
        section_code="SEC-9",
        part_code="PART-II",
        parent_node_id="PDPA-2010-PART-II",
        version=2,
        language="en",
        text=(
            "Section 9 & 12B (Security Principle & Mandatory Breach Notification - 2024 Amendment): "
            "Both data users and data processors are directly bound by the Security Principle. "
            "A data user MUST notify the Commissioner within 72 hours of becoming aware of a "
            "personal data breach, and penalties are increased up to RM 1,000,000."
        ),
        valid_from=date(2025, 1, 1),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act A1727 / P.U. (B) 512/2024",
        source_spans=[
            SourceSpan(
                span_id="SPAN-PDPA-SEC-9-V2-EN",
                act_number="Act 709",
                section_id="SEC-9",
                language="en",
                pdf_page=6,
                char_offset_start=88,
                char_offset_end=372,
                text=(
                    "Both data users and data processors are directly bound by the Security Principle. "
                    "A data user MUST notify the Commissioner within 72 hours of becoming aware of a "
                    "personal data breach, and penalties are increased up to RM 1,000,000."
                ),
            )
        ],
    )
    pdpa_sec9_v2_bm = StatutoryNode(
        node_id="PDPA-2010-SEC-9-V2-BM",
        act_name="Akta Perlindungan Data Peribadi 2010",
        act_number="Act 709",
        section_code="SEC-9",
        part_code="PART-II",
        parent_node_id="PDPA-2010-PART-II",
        version=2,
        language="bm",
        text=(
            "Seksyen 9 & 12B (Prinsip Keselamatan & Notis Kebocoran Data Wajib - Pindaan 2024): "
            "Kedua-dua pengguna data dan pemproses data terikat secara langsung di bawah Prinsip "
            "Keselamatan. Pengguna data WAJIB memaklumkan Pesuruhjaya dalam tempoh 72 jam selepas "
            "menyedari pelanggaran data peribadi dengan penalti sehingga RM 1,000,000."
        ),
        valid_from=date(2025, 1, 1),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta A1727 / P.U. (B) 512/2024",
        source_spans=[
            SourceSpan(
                span_id="SPAN-PDPA-SEC-9-V2-BM",
                act_number="Act 709",
                section_id="SEKSYEN-9",
                language="bm",
                pdf_page=6,
                char_offset_start=82,
                char_offset_end=384,
                text=(
                    "Kedua-dua pengguna data dan pemproses data terikat secara langsung di bawah Prinsip "
                    "Keselamatan. Pengguna data WAJIB memaklumkan Pesuruhjaya dalam tempoh 72 jam."
                ),
            )
        ],
    )
    _add_bilingual_pair(
        store,
        pdpa_sec9_v2_en,
        pdpa_sec9_v2_bm,
        authoritative="bm",
        amends_en_id="PDPA-2010-SEC-9-V1",
        amends_bm_id="PDPA-2010-SEC-9-V1-BM",
    )

    # Subsection 9(1A) hierarchical node
    pdpa_sec9_sub1a = StatutoryNode(
        node_id="PDPA-2010-SEC-9-V2-SUB-1A",
        act_name="Personal Data Protection Act 2010",
        act_number="Act 709",
        section_code="SEC-9(1A)",
        part_code="PART-II",
        subsection_code="(1A)",
        hierarchy_level=HierarchyLevel.SUBSECTION,
        parent_node_id="PDPA-2010-SEC-9-V2",
        version=2,
        language="en",
        text=(
            "Subsection 9(1A): Where processing of personal data is carried out by a data processor "
            "on behalf of a data user, the data processor shall comply directly with the Security Principle."
        ),
        valid_from=date(2025, 1, 1),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act A1727",
        source_spans=[
            SourceSpan(
                span_id="SPAN-PDPA-SEC-9-1A-EN",
                act_number="Act 709",
                section_id="SEC-9(1A)",
                language="en",
                pdf_page=6,
                char_offset_start=375,
                char_offset_end=568,
                text=(
                    "Where processing of personal data is carried out by a data processor "
                    "on behalf of a data user, the data processor shall comply directly with the Security Principle."
                ),
            )
        ],
    )
    store.upsert_node(pdpa_sec9_sub1a)

    # Section 130 (Unlawful Collection/Disclosure)
    pdpa_sec130_en = StatutoryNode(
        node_id="PDPA-2010-SEC-130-V1",
        act_name="Personal Data Protection Act 2010",
        act_number="Act 709",
        section_code="SEC-130",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="en",
        text=(
            "Section 130 (Unlawful Collection/Disclosure): Fine not exceeding RM 500,000 "
            "or imprisonment not exceeding 3 years for unlawful collection or disclosure of personal data."
        ),
        valid_from=date(2013, 11, 15),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 709",
        source_spans=[
            SourceSpan(
                span_id="SPAN-PDPA-SEC-130-EN",
                act_number="Act 709",
                section_id="SEC-130",
                language="en",
                pdf_page=88,
                char_offset_start=105,
                char_offset_end=265,
                text=(
                    "Section 130 (Unlawful Collection/Disclosure): Fine not exceeding RM 500,000 "
                    "or imprisonment not exceeding 3 years."
                ),
            )
        ],
    )
    pdpa_sec130_bm = StatutoryNode(
        node_id="PDPA-2010-SEC-130-V1-BM",
        act_name="Akta Perlindungan Data Peribadi 2010",
        act_number="Act 709",
        section_code="SEC-130",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 130 (Pengumpulan atau Penzahiran Tanpa Kebenaran): Denda tidak melebihi "
            "RM 500,000 atau penjara selama tempoh tidak melebihi 3 tahun."
        ),
        valid_from=date(2013, 11, 15),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 709",
        source_spans=[
            SourceSpan(
                span_id="SPAN-PDPA-SEC-130-BM",
                act_number="Act 709",
                section_id="SEKSYEN-130",
                language="bm",
                pdf_page=88,
                char_offset_start=100,
                char_offset_end=245,
                text=(
                    "Seksyen 130 (Pengumpulan atau Penzahiran Tanpa Kebenaran): Denda tidak melebihi "
                    "RM 500,000 atau penjara selama tempoh tidak melebihi 3 tahun."
                ),
            )
        ],
    )
    _add_bilingual_pair(store, pdpa_sec130_en, pdpa_sec130_bm, authoritative="bm")

    # Additional PDPA Principles (Sec 6, 7, 8, 10, 11, 12) + 2024 Amendment Sec 12A (DPO) & Sec 12B (Breach)
    pdpa_principles_specs = [
        (
            "PDPA-2010-SEC-6-V1",
            "SEC-6",
            date(2013, 11, 15),
            "Act 709",
            14,
            "Section 6 (General Principle): A data user shall not process personal data unless the data subject has given consent for a lawful purpose directly related to the data user's activity.",
            "Seksyen 6 (Prinsip Am): Pengguna data tidak boleh memproses data peribadi melainkan subjek data telah memberikan persetujuannya bagi maksud yang sah.",
        ),
        (
            "PDPA-2010-SEC-7-V1",
            "SEC-7",
            date(2013, 11, 15),
            "Act 709",
            15,
            "Section 7 (Notice and Choice Principle): A data user shall by written notice in both the national language (Bahasa Melayu) and the English language inform the data subject of the purposes and third-party disclosure classes.",
            "Seksyen 7 (Prinsip Notis dan Pilihan): Pengguna data hendaklah melalui notis bertulis dalam bahasa kebangsaan (Bahasa Melayu) dan bahasa Inggeris memaklumkan subjek data tentang maksud pemprosesan.",
        ),
        (
            "PDPA-2010-SEC-8-V1",
            "SEC-8",
            date(2013, 11, 15),
            "Act 709",
            16,
            "Section 8 (Disclosure Principle): No personal data shall without the consent of the data subject be disclosed for any purpose other than the purpose for which the data was to be disclosed at the time of collection.",
            "Seksyen 8 (Prinsip Penzahiran): Tiada data peribadi boleh dizahirkan tanpa persetujuan subjek data bagi apa-apa maksud selain daripada maksud yang diberitahu semasa pengumpulan.",
        ),
        (
            "PDPA-2010-SEC-10-V1",
            "SEC-10",
            date(2013, 11, 15),
            "Act 709",
            18,
            "Section 10 (Retention Principle): Personal data processed for any purpose shall not be kept longer than is necessary for the fulfilment of that purpose and shall be permanently destroyed or deleted.",
            "Seksyen 10 (Prinsip Penyimpanan): Data peribadi tidak boleh disimpan lebih lama daripada yang perlu bagi memenuhi maksud pemprosesan dan hendaklah dimusnahkan secara kekal.",
        ),
        (
            "PDPA-2010-SEC-11-V1",
            "SEC-11",
            date(2013, 11, 15),
            "Act 709",
            19,
            "Section 11 (Data Integrity Principle): A data user shall take reasonable steps to ensure that the personal data is accurate, complete, not misleading and kept up-to-date.",
            "Seksyen 11 (Prinsip Integriti Data): Pengguna data hendaklah mengambil langkah munasabah untuk memastikan data peribadi adalah tepat, lengkap, tidak mengelirukan dan terkini.",
        ),
        (
            "PDPA-2010-SEC-12-V1",
            "SEC-12",
            date(2013, 11, 15),
            "Act 709",
            20,
            "Section 12 (Access Principle): A data subject shall be given access to his personal data held by a data user and be able to correct that personal data where it is inaccurate, incomplete or misleading.",
            "Seksyen 12 (Prinsip Akses): Subjek data hendaklah diberi akses kepada data peribadinya yang dipegang oleh pengguna data serta hak untuk membetulkan data tersebut.",
        ),
        (
            "PDPA-2010-SEC-12A-V1",
            "SEC-12A",
            date(2025, 1, 1),
            "Act A1727",
            8,
            "Section 12A (Appointment of Data Protection Officer - DPO): A data user and data processor shall appoint one or more data protection officers responsible for compliance with Act 709 and notify the Commissioner.",
            "Seksyen 12A (Pelantikan Pegawai Perlindungan Data - PPD): Pengguna data dan pemproses data hendaklah melantik seorang atau lebih pegawai perlindungan data (PPD) dan memaklumkan kepada Pesuruhjaya.",
        ),
        (
            "PDPA-2010-SEC-12B-V1",
            "SEC-12B",
            date(2025, 1, 1),
            "Act A1727",
            9,
            "Section 12B (Personal Data Breach Notification): Where a data user has reason to believe a personal data breach has occurred, the data user shall notify the Commissioner within 72 hours and notify affected data subjects where significant harm is caused.",
            "Seksyen 12B (Notis Pelanggaran Data Peribadi): Apabila pengguna data mempunyai sebab untuk mempercayai berlakunya kebocoran data peribadi, notis wajib dikemukakan kepada Pesuruhjaya dalam tempoh 72 jam serta kepada subjek data terjejas.",
        ),
    ]

    for nid, scode, vfrom, gref, page, en_txt, bm_txt in pdpa_principles_specs:
        en_n = StatutoryNode(
            node_id=nid,
            act_name="Personal Data Protection Act 2010",
            act_number="Act 709",
            section_code=scode,
            part_code="PART-II",
            parent_node_id="PDPA-2010-PART-II",
            version=1,
            language="en",
            text=en_txt,
            valid_from=vfrom,
            authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
            territorial_scope=[TerritorialScope.ALL_MALAYSIA],
            gazette_ref=gref,
            source_spans=[
                SourceSpan(
                    span_id=f"SPAN-{nid}-EN",
                    act_number="Act 709",
                    section_id=scode,
                    language="en",
                    pdf_page=page,
                    char_offset_start=0,
                    char_offset_end=len(en_txt),
                    text=en_txt,
                )
            ],
        )
        bm_n = StatutoryNode(
            node_id=f"{nid}-BM",
            act_name="Akta Perlindungan Data Peribadi 2010",
            act_number="Act 709",
            section_code=scode,
            part_code="PART-II",
            parent_node_id="PDPA-2010-PART-II",
            version=1,
            language="bm",
            text=bm_txt,
            valid_from=vfrom,
            authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
            territorial_scope=[TerritorialScope.ALL_MALAYSIA],
            gazette_ref=gref,
            source_spans=[
                SourceSpan(
                    span_id=f"SPAN-{nid}-BM",
                    act_number="Act 709",
                    section_id=scode.replace("SEC-", "SEKSYEN-"),
                    language="bm",
                    pdf_page=page,
                    char_offset_start=0,
                    char_offset_end=len(bm_txt),
                    text=bm_txt,
                )
            ],
        )
        _add_bilingual_pair(store, en_n, bm_n, authoritative="bm")

    # =========================================================================
    # Territorial Scope Demo Statutes (Peninsular vs Sabah vs Sarawak)
    # =========================================================================
    ea_1955_en = StatutoryNode(
        node_id="EA-1955-SEC-60A-V1",
        act_name="Employment Act 1955",
        act_number="Act 265",
        section_code="SEC-60A",
        version=1,
        language="en",
        text=(
            "Section 60A (Hours of Work & Overtime - Peninsular Malaysia & Federal Territories): "
            "An employee shall not be required to work beyond the maximum limit of 45 working hours "
            "in one week, and overtime rates apply under the Employment Act 1955."
        ),
        valid_from=date(2023, 1, 1),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[
            TerritorialScope.PENINSULAR_MALAYSIA,
            TerritorialScope.FEDERAL_TERRITORIES,
        ],
        gazette_ref="Act A1651 / P.U. (A) 397/2022",
    )
    ea_1955_bm = StatutoryNode(
        node_id="EA-1955-SEC-60A-V1-BM",
        act_name="Akta Kerja 1955",
        act_number="Act 265",
        section_code="SEC-60A",
        version=1,
        language="bm",
        text=(
            "Seksyen 60A (Waktu Kerja - Semenanjung Malaysia & Wilayah Persekutuan): Pekerja tidak "
            "boleh dikehendaki bekerja lebih daripada 45 jam dalam satu minggu di bawah Akta Kerja 1955."
        ),
        valid_from=date(2023, 1, 1),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[
            TerritorialScope.PENINSULAR_MALAYSIA,
            TerritorialScope.FEDERAL_TERRITORIES,
        ],
        gazette_ref="Akta A1651 / P.U. (A) 397/2022",
    )
    _add_bilingual_pair(store, ea_1955_en, ea_1955_bm, authoritative="bm")

    sabah_ord_en = StatutoryNode(
        node_id="SABAH-CAP67-SEC-104-V1",
        act_name="Sabah Labour Ordinance",
        act_number="Cap. 67",
        section_code="SEC-104",
        version=1,
        language="en",
        text=(
            "Section 104 (Hours of Work & Overtime - Sabah): Governs working hours, overtime rates, "
            "and rest day entitlements exclusively for employees working in the State of Sabah."
        ),
        valid_from=date(2005, 10, 1),
        authority_tier=AuthorityTier.TIER_3_ORDINANCE,
        territorial_scope=[TerritorialScope.SABAH],
        gazette_ref="Sabah Cap. 67",
    )
    sabah_ord_bm = StatutoryNode(
        node_id="SABAH-CAP67-SEC-104-V1-BM",
        act_name="Ordinan Buruh Sabah",
        act_number="Cap. 67",
        section_code="SEC-104",
        version=1,
        language="bm",
        text=(
            "Seksyen 104 (Waktu Kerja & Kerja Lebih Masa - Sabah): Mengawal selia waktu kerja dan kadar "
            "kerja lebih masa khusus bagi pekerja di Negeri Sabah."
        ),
        valid_from=date(2005, 10, 1),
        authority_tier=AuthorityTier.TIER_3_ORDINANCE,
        territorial_scope=[TerritorialScope.SABAH],
        gazette_ref="Sabah Cap. 67",
    )
    _add_bilingual_pair(store, sabah_ord_en, sabah_ord_bm, authoritative="en")

    sarawak_ord_en = StatutoryNode(
        node_id="SARAWAK-CAP76-SEC-105-V1",
        act_name="Sarawak Labour Ordinance",
        act_number="Cap. 76",
        section_code="SEC-105",
        version=1,
        language="en",
        text=(
            "Section 105 (Hours of Work & Overtime - Sarawak): Governs working hours, overtime rates, "
            "and rest day entitlements exclusively for employees working in the State of Sarawak."
        ),
        valid_from=date(2005, 10, 1),
        authority_tier=AuthorityTier.TIER_3_ORDINANCE,
        territorial_scope=[TerritorialScope.SARAWAK],
        gazette_ref="Sarawak Cap. 76",
    )
    sarawak_ord_bm = StatutoryNode(
        node_id="SARAWAK-CAP76-SEC-105-V1-BM",
        act_name="Ordinan Buruh Sarawak",
        act_number="Cap. 76",
        section_code="SEC-105",
        version=1,
        language="bm",
        text=(
            "Seksyen 105 (Waktu Kerja & Kerja Lebih Masa - Sarawak): Mengawal selia waktu kerja dan kadar "
            "kerja lebih masa khusus bagi pekerja di Negeri Sarawak."
        ),
        valid_from=date(2005, 10, 1),
        authority_tier=AuthorityTier.TIER_3_ORDINANCE,
        territorial_scope=[TerritorialScope.SARAWAK],
        gazette_ref="Sarawak Cap. 76",
    )
    _add_bilingual_pair(store, sarawak_ord_en, sarawak_ord_bm, authoritative="en")

    # =========================================================================
    # Tier 3: Subsidiary Legislation (P.U. (A) & P.U. (B))
    # =========================================================================
    pua_342 = StatutoryNode(
        node_id="PUA-342-2024-REG-3",
        act_name="Personal Data Protection (Data Breach Notification) Regulations 2024",
        act_number="P.U. (A) 342/2024",
        section_code="REG-3",
        version=1,
        language="en",
        text=(
            "Regulation 3 [P.U. (A) 342/2024]: Prescribes the 72-hour electronic personal data "
            "breach notification template and threshold criteria where personal data breach causes significant harm."
        ),
        valid_from=date(2025, 1, 1),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (A) 342/2024",
    )
    store.upsert_node(pua_342)

    pub_512 = StatutoryNode(
        node_id="PUB-512-2024-APPT",
        act_name="Appointment of Date of Coming into Operation (PDPA Amendment Act 2024)",
        act_number="P.U. (B) 512/2024",
        section_code="GAZETTE-APPT",
        version=1,
        language="en",
        text=(
            "P.U. (B) 512/2024: The Minister appoints 1 January 2025 as the effective date on which "
            "the Personal Data Protection (Amendment) Act 2024 [Act A1727] comes into operation."
        ),
        valid_from=date(2025, 1, 1),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (B) 512/2024",
    )
    store.upsert_node(pub_512)

    # =========================================================================
    # Tier 2: Contracts Act 1950 [Act 136] & Penal Code [Act 574] (BM <-> EN)
    # =========================================================================
    ca1950_s75_en = StatutoryNode(
        node_id="ACT-136-SEC-75-V1",
        act_name="Contracts Act 1950",
        act_number="Act 136",
        section_code="SEC-75",
        version=1,
        language="en",
        text=(
            "Section 75 (Compensation for breach of contract where penalty stipulated for): "
            "When a contract has been broken, if a sum is named in the contract as the amount to be "
            "paid in case of such breach, the party complaining of the breach is entitled to receive "
            "reasonable compensation not exceeding the amount so named."
        ),
        valid_from=date(1950, 5, 23),
        authority_tier=AuthorityTier.TIER_2_ACT_OF_PARLIAMENT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 136 (Revised 1974)",
    )
    ca1950_s75_bm = StatutoryNode(
        node_id="ACT-136-SEC-75-V1-BM",
        act_name="Akta Kontrak 1950",
        act_number="Act 136",
        section_code="SEC-75",
        version=1,
        language="ms",
        text=(
            "Seksyen 75 (Pampasan bagi pecah kontrak jika penalti ditetapkan): Apabila suatu kontrak "
            "telah dipecahkan, pihak yang menuntut berhak menerima pampasan munasabah yang tidak "
            "melebihi amaun yang dinamakan dalam kontrak tersebut."
        ),
        valid_from=date(1950, 5, 23),
        authority_tier=AuthorityTier.TIER_2_ACT_OF_PARLIAMENT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 136 (Disemak 1974)",
    )
    _add_bilingual_pair(store, ca1950_s75_en, ca1950_s75_bm, authoritative="en")

    pc574_s420_en = StatutoryNode(
        node_id="ACT-574-SEC-420-V1",
        act_name="Penal Code",
        act_number="Act 574",
        section_code="SEC-420",
        version=1,
        language="en",
        text=(
            "Section 420 (Cheating and dishonestly inducing delivery of property): Whoever cheats "
            "and thereby dishonestly induces the person deceived to deliver any property shall be "
            "punished with imprisonment for a term not less than one year and not more than ten years."
        ),
        valid_from=date(1997, 8, 7),
        authority_tier=AuthorityTier.TIER_2_ACT_OF_PARLIAMENT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 574",
    )
    pc574_s420_bm = StatutoryNode(
        node_id="ACT-574-SEC-420-V1-BM",
        act_name="Kanun Keseksaan",
        act_number="Act 574",
        section_code="SEC-420",
        version=1,
        language="ms",
        text=(
            "Seksyen 420 (Menipu dan dengan curangnya mendorong supaya harta diserahkan): "
            "Barang siapa menipu dan dengan jalan demikian mendorong orang yang diperdayakan itu "
            "menyerahkan apa-apa harta hendaklah diseksa dengan penjara tidak kurang satu tahun."
        ),
        valid_from=date(1997, 8, 7),
        authority_tier=AuthorityTier.TIER_2_ACT_OF_PARLIAMENT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 574",
    )
    _add_bilingual_pair(store, pc574_s420_en, pc574_s420_bm, authoritative="bm")

    # =========================================================================
    # Tiers 4, 5, 6: Malaysian Judicial Precedent Hierarchy
    # =========================================================================
    hc_2021_text = (
        "High Court [2021] 7 MLJ 412 (HC): Held under the 2010 PDPA baseline that third-party "
        "data processors owed contractual duties only to the data user and bore no direct "
        "statutory liability under Section 9 prior to the 2024 Amendment."
    )
    hc_2021 = StatutoryNode(
        node_id="CASE-HC-2021-004",
        act_name="Re DataHost Malaya Sdn Bhd",
        act_number="[2021] 7 MLJ 412",
        section_code="PARA-24",
        hierarchy_level=HierarchyLevel.CASE,
        version=1,
        language="en",
        text=hc_2021_text,
        valid_from=date(2021, 8, 10),
        authority_tier=AuthorityTier.TIER_6_HIGH_COURT,
        court_name="High Court of Malaya (Mahkamah Tinggi Malaya)",
        case_citation="[2021] 7 MLJ 412 (HC)",
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        source_spans=[
            SourceSpan(
                span_id="SPAN-CASE-HC-2021-004",
                doc_id="mlj-2021-7-412",
                source_uri="https://lom.agc.gov.my/cases/mlj-2021-7-412",
                act_number="[2021] 7 MLJ 412",
                section_id="PARA-24",
                canonical_citation="[2021] 7 MLJ 412 (HC), para 24",
                language="en",
                pdf_page=12,
                start_char=0,
                end_char=len(hc_2021_text),
                text=hc_2021_text,
            )
        ],
    )
    store.upsert_node(hc_2021)

    coa_2024_text = (
        "Court of Appeal [2024] 5 MLJ 88 (CA): Clarified that Section 9 practical security steps "
        "require documented technical encryption safeguards by data users even prior to the 2025 "
        "statutory breach notification mandate."
    )
    coa_2024 = StatutoryNode(
        node_id="CASE-COA-2024-002",
        act_name="Syarikat Digital Nusantara Sdn Bhd v Pengarah JPDP",
        act_number="[2024] 5 MLJ 88",
        section_code="PARA-31",
        hierarchy_level=HierarchyLevel.CASE,
        version=1,
        language="en",
        text=coa_2024_text,
        valid_from=date(2024, 3, 10),
        authority_tier=AuthorityTier.TIER_5_COURT_OF_APPEAL,
        court_name="Court of Appeal (Mahkamah Rayuan)",
        case_citation="[2024] 5 MLJ 88 (CA)",
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        source_spans=[
            SourceSpan(
                span_id="SPAN-CASE-COA-2024-002",
                doc_id="mlj-2024-5-88",
                source_uri="https://lom.agc.gov.my/cases/mlj-2024-5-88",
                act_number="[2024] 5 MLJ 88",
                section_id="PARA-31",
                canonical_citation="[2024] 5 MLJ 88 (CA), para 31",
                language="en",
                pdf_page=18,
                start_char=0,
                end_char=len(coa_2024_text),
                text=coa_2024_text,
            )
        ],
    )
    store.upsert_node(coa_2024)

    fc_2025_text = (
        "Federal Court [2025] 2 MLJ 101 (FC): Affirmed that following Act A1727 (effective 1 January 2025), "
        "Section 9(1A) imposes direct statutory Security Principle liability on data processors and Section 12B "
        "mandates 72-hour breach notification, overruling prior High Court dicta limiting processor liability."
    )
    fc_2025 = StatutoryNode(
        node_id="CASE-FC-2025-001",
        act_name="Ketua Pengarah Perlindungan Data Peribadi v CloudTech Malaysia Sdn Bhd",
        act_number="[2025] 2 MLJ 101",
        section_code="PARA-42",
        hierarchy_level=HierarchyLevel.CASE,
        version=1,
        language="en",
        text=fc_2025_text,
        valid_from=date(2025, 2, 15),
        authority_tier=AuthorityTier.TIER_4_FEDERAL_COURT,
        court_name="Federal Court (Mahkamah Persekutuan)",
        case_citation="[2025] 2 MLJ 101 (FC)",
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        source_spans=[
            SourceSpan(
                span_id="SPAN-CASE-FC-2025-001",
                doc_id="mlj-2025-2-101",
                source_uri="https://lom.agc.gov.my/cases/mlj-2025-2-101",
                act_number="[2025] 2 MLJ 101",
                section_id="PARA-42",
                canonical_citation="[2025] 2 MLJ 101 (FC), para 42",
                language="en",
                pdf_page=27,
                start_char=0,
                end_char=len(fc_2025_text),
                text=fc_2025_text,
            )
        ],
    )
    store.upsert_node(fc_2025)

    fc_cubic_text = (
        "Federal Court [2019] 6 MLJ 15 (FC): Held under Section 75 of the Contracts Act 1950 [Act 136] "
        "that an innocent party is entitled to enforce a liquidated damages clause up to the stipulated sum "
        "if there is a legitimate commercial interest and the sum is not unconscionably disproportionate."
    )
    fc_cubic = StatutoryNode(
        node_id="CASE-FC-2019-CUBIC",
        act_name="Cubic Electronics Sdn Bhd v Mars Telecommunications Sdn Bhd",
        act_number="[2019] 6 MLJ 15",
        section_code="PARA-65",
        hierarchy_level=HierarchyLevel.CASE,
        version=1,
        language="en",
        text=fc_cubic_text,
        valid_from=date(2018, 11, 21),
        authority_tier=AuthorityTier.TIER_4_FEDERAL_COURT,
        court_name="Federal Court (Mahkamah Persekutuan)",
        case_citation="[2019] 6 MLJ 15 (FC)",
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        source_spans=[
            SourceSpan(
                span_id="SPAN-CASE-FC-2019-CUBIC",
                doc_id="mlj-2019-6-15",
                source_uri="https://lom.agc.gov.my/cases/mlj-2019-6-15",
                act_number="[2019] 6 MLJ 15",
                section_id="PARA-65",
                canonical_citation="[2019] 6 MLJ 15 (FC), para 65",
                language="en",
                pdf_page=34,
                start_char=0,
                end_char=len(fc_cubic_text),
                text=fc_cubic_text,
            )
        ],
    )
    store.upsert_node(fc_cubic)

    # Judicial treatment edges
    store.add_judicial_treatment(
        "CASE-HC-2021-004",
        "PDPA-2010-SEC-9-V1",
        TemporalEdgeType.INTERPRETS,
        effective_date=date(2021, 8, 10),
    )
    store.add_judicial_treatment(
        "CASE-COA-2024-002",
        "PDPA-2010-SEC-9-V1",
        TemporalEdgeType.APPLIES,
        effective_date=date(2024, 3, 10),
    )
    store.add_judicial_treatment(
        "CASE-FC-2025-001",
        "PDPA-2010-SEC-9-V2",
        TemporalEdgeType.INTERPRETS,
        effective_date=date(2025, 2, 15),
    )
    store.add_judicial_treatment(
        "CASE-FC-2025-001",
        "PDPA-2010-SEC-12B-V1",
        TemporalEdgeType.APPLIES,
        effective_date=date(2025, 2, 15),
    )
    store.add_judicial_treatment(
        "CASE-FC-2025-001",
        "CASE-HC-2021-004",
        TemporalEdgeType.OVERRULES,
        effective_date=date(2025, 2, 15),
    )
    store.add_judicial_treatment(
        "CASE-FC-2019-CUBIC",
        "ACT-136-SEC-75-V1",
        TemporalEdgeType.INTERPRETS,
        effective_date=date(2018, 11, 21),
    )

    # =========================================================================
    # Tier 7: Statutory Tribunal / Agency Guideline (JPDP)
    # =========================================================================
    jpdp_circ = StatutoryNode(
        node_id="JPDP-CIRC-01-2025",
        act_name="JPDP Commissioner Guideline on DPO & Breach Notification",
        act_number="JPDP Circular 01/2025",
        section_code="CIRC-01",
        version=1,
        language="en",
        text=(
            "JPDP Circular 01/2025: Operational guidance on registering a Data Protection Officer (DPO) "
            "via portal.pdp.gov.my and submitting 72-hour personal data breach reports."
        ),
        valid_from=date(2025, 2, 1),
        authority_tier=AuthorityTier.TIER_7_STATUTORY_TRIBUNAL,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="JPDP Circular 01/2025",
    )
    store.upsert_node(jpdp_circ)

    # =========================================================================
    # Cross-reference CITES edges
    # =========================================================================
    store.add_citation(
        "PDPA-2010-SEC-9-V1", "PDPA-2010-SEC-130-V1", effective_date=date(2013, 11, 15)
    )
    store.add_citation(
        "PDPA-2010-SEC-9-V2", "PDPA-2010-SEC-130-V1", effective_date=date(2025, 1, 1)
    )
    store.add_citation(
        "PDPA-2010-SEC-12B-V1", "PUA-342-2024-REG-3", effective_date=date(2025, 1, 1), gazette_ref="P.U. (A) 342/2024"
    )
    store.add_citation(
        "PDPA-2010-SEC-12A-V1", "JPDP-CIRC-01-2025", effective_date=date(2025, 2, 1), gazette_ref="JPDP Circular 01/2025"
    )

    return store
