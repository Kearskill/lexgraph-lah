from datetime import date
from typing import Any

from pydantic import BaseModel, Field

from lexgraph_lah.graph.reranker import (
    filter_by_territorial_scope,
    rerank_statutes_and_spans,
)
from lexgraph_lah.schemas.domain import (
    AuthorityTier,
    BilingualClausePair,
    HierarchyLevel,
    RetrievalSearchResponse,
    SourceSpan,
    StatutoryEdge,
    StatutoryNode,
    StatutoryStatus,
    TemporalEdgeType,
    TerritorialScope,
)


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
    optionally closing out a predecessor version's VALID_TO window and creating
    AMENDED_BY and AMENDS edges with gazette/authority metadata.
    """
    eff_from = (new_node.effective_from or new_node.valid_from).isoformat()
    eff_to_val = new_node.effective_to or new_node.valid_to
    eff_to = eff_to_val.isoformat() if eff_to_val else None

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
            "    n.gazette_ref = $gazette_ref,\n"
            "    n.authority_tier = $authority_tier,\n"
            "    n.territorial_scope = $territorial_scope,\n"
            "    n.status = $status,\n"
            "    n.content_hash = $content_hash\n"
            "WITH n\n"
            "MATCH (prev:StatutoryNode {node_id: $predecessor_id})\n"
            "SET prev.valid_to = date($valid_from),\n"
            "    prev.effective_to = date($effective_from),\n"
            "    prev.status = 'AMENDED'\n"
            "MERGE (prev)-[r:AMENDED_BY]->(n)\n"
            "SET r.effective_date = date($valid_from),\n"
            "    r.gazette_ref = $gazette_ref\n"
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
    query = (
        "MATCH (target:StatutoryNode {node_id: $target_node_id})\n"
        "MATCH (rep:StatutoryNode {node_id: $repealing_node_id})\n"
        "SET target.valid_to = date($effective_date),\n"
        "    target.effective_to = date($effective_date),\n"
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
    resolves multi-hop CITES / HAS_TRANSLATION edges valid on `as_of_date`.
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
        f"OPTIONAL MATCH (s)-[:CITES|HAS_TRANSLATION*1..{hops}]->(cited:StatutoryNode)\n"
        "WHERE cited.valid_from <= date($as_of_date)\n"
        "  AND (cited.valid_to IS NULL OR cited.valid_to > date($as_of_date))\n"
        "  AND NOT EXISTS {\n"
        "    MATCH (cited)-[cr:REPEALED_BY]->(:StatutoryNode)\n"
        "    WHERE cr.effective_date <= date($as_of_date)\n"
        "  }\n"
        "RETURN s, collect(DISTINCT cited) AS cited_context\n"
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
    supporting Act -> Part -> Section -> Subsection -> SourceSpan provenance,
    BM/EN translation linking, Gazette versioning, and territorial scope filtering.
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
        Inserts or updates a statutory node. If `amends_node_id` is provided,
        closes the predecessor's `valid_to` / `effective_to` window at `node.valid_from`
        and records both `AMENDED_BY` and `AMENDS` edges.
        """
        eff_date = node.effective_from or node.valid_from
        if amends_node_id and amends_node_id in self._nodes:
            prev = self._nodes[amends_node_id]
            updated_prev = prev.model_copy(
                update={
                    "valid_to": eff_date,
                    "effective_to": eff_date,
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
                    gazette_ref=node.gazette_ref,
                )
            )
            self.add_edge(
                StatutoryEdge(
                    source_id=node.node_id,
                    target_id=amends_node_id,
                    edge_type=TemporalEdgeType.AMENDS,
                    effective_date=eff_date,
                    gazette_ref=node.gazette_ref,
                )
            )

        self._nodes[node.node_id] = node

        if node.parent_node_id and node.parent_node_id in self._nodes:
            edge_map = {
                HierarchyLevel.PART: TemporalEdgeType.HAS_PART,
                HierarchyLevel.SECTION: TemporalEdgeType.HAS_SECTION,
                HierarchyLevel.SUBSECTION: TemporalEdgeType.HAS_SUBSECTION,
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
        self._nodes[target_node_id] = target.model_copy(
            update={
                "valid_to": effective_date,
                "effective_to": effective_date,
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

    def link_translation(
        self,
        en_node_id: str,
        bm_node_id: str,
        authoritative_node_id: str,
        effective_date: date,
        gazette_ref: str | None = None,
    ) -> None:
        """Links parallel English and Bahasa Melayu nodes with HAS_TRANSLATION and AUTHORITATIVE_TEXT."""
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

        self.add_edge(
            StatutoryEdge(
                source_id=en_node_id,
                target_id=bm_node_id,
                edge_type=TemporalEdgeType.HAS_TRANSLATION,
                effective_date=effective_date,
                gazette_ref=gazette_ref,
            )
        )
        self.add_edge(
            StatutoryEdge(
                source_id=bm_node_id,
                target_id=en_node_id,
                edge_type=TemporalEdgeType.HAS_TRANSLATION,
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
    ) -> list[StatutoryNode]:
        """
        Resolves StatutoryNodes active on `as_of_date`, optionally filtered by `act_name`,
        `language`, and `territorial_scope`, and traverses multi-hop `CITES` (and optionally
        `HAS_TRANSLATION`) edges valid on `as_of_date`.
        """
        seed_candidates = [
            node
            for node in self._nodes.values()
            if self._is_node_valid_on(node, as_of_date)
            and (act_name is None or node.act_name == act_name)
            and (language is None or node.language == language)
            and (
                include_containers
                or node.hierarchy_level not in {HierarchyLevel.ACT, HierarchyLevel.PART}
            )
        ]
        seed_nodes = filter_by_territorial_scope(seed_candidates, territorial_scope)

        resolved: dict[str, StatutoryNode] = {n.node_id: n for n in seed_nodes}

        if include_citations and max_hops > 0:
            allowed_edges = {TemporalEdgeType.CITES}
            if include_translations:
                allowed_edges.add(TemporalEdgeType.HAS_TRANSLATION)

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
                                and (language is None or cited_node.language == language)
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
        en_node = node if node.language == "en" else (partner if partner and partner.language == "en" else None)
        bm_node = node if node.language == "bm" else (partner if partner and partner.language == "bm" else None)

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
    # Tier 4: Subsidiary Legislation (P.U. (A) & P.U. (B))
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
        authority_tier=AuthorityTier.TIER_4_SUBSIDIARY_LEGISLATION,
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
        authority_tier=AuthorityTier.TIER_4_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (B) 512/2024",
    )
    store.upsert_node(pub_512)

    # =========================================================================
    # Tier 5: Agency Circular / Guideline (JPDP)
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
        authority_tier=AuthorityTier.TIER_5_AGENCY_CIRCULAR,
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
