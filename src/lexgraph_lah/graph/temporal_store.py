from datetime import date
from typing import Any

from pydantic import BaseModel, Field

from lexgraph_lah.schemas.domain import (
    StatutoryEdge,
    StatutoryNode,
    StatutoryStatus,
    TemporalEdgeType,
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
    optionally closing out a predecessor version's VALID_TO window and creating an
    AMENDED_BY edge.
    """
    params: dict[str, Any] = {
        "node_id": new_node.node_id,
        "act_name": new_node.act_name,
        "section_code": new_node.section_code,
        "version": new_node.version,
        "text": new_node.text,
        "valid_from": new_node.valid_from.isoformat(),
        "valid_to": new_node.valid_to.isoformat() if new_node.valid_to else None,
        "status": new_node.status.value,
        "content_hash": new_node.content_hash,
        "predecessor_id": predecessor_node_id,
    }

    if predecessor_node_id:
        query = (
            "MERGE (n:StatutoryNode {node_id: $node_id})\n"
            "SET n.act_name = $act_name,\n"
            "    n.section_code = $section_code,\n"
            "    n.version = $version,\n"
            "    n.text = $text,\n"
            "    n.valid_from = date($valid_from),\n"
            "    n.valid_to = CASE WHEN $valid_to IS NOT NULL THEN date($valid_to) ELSE null END,\n"
            "    n.status = $status,\n"
            "    n.content_hash = $content_hash\n"
            "WITH n\n"
            "MATCH (prev:StatutoryNode {node_id: $predecessor_id})\n"
            "SET prev.valid_to = date($valid_from),\n"
            "    prev.status = 'AMENDED'\n"
            "MERGE (prev)-[r:AMENDED_BY]->(n)\n"
            "SET r.effective_date = date($valid_from)\n"
            "RETURN n, prev"
        )
    else:
        query = (
            "MERGE (n:StatutoryNode {node_id: $node_id})\n"
            "SET n.act_name = $act_name,\n"
            "    n.section_code = $section_code,\n"
            "    n.version = $version,\n"
            "    n.text = $text,\n"
            "    n.valid_from = date($valid_from),\n"
            "    n.valid_to = CASE WHEN $valid_to IS NOT NULL THEN date($valid_to) ELSE null END,\n"
            "    n.status = $status,\n"
            "    n.content_hash = $content_hash\n"
            "RETURN n"
        )

    return CypherQueryBundle(query=query, params=params)


def build_repeal_cypher(
    target_node_id: str,
    repealing_node_id: str,
    effective_date: date,
) -> CypherQueryBundle:
    """
    Generates a parameterized Cypher query marking a statutory node as REPEALED_BY
    another statutory instrument as of effective_date.
    """
    query = (
        "MATCH (target:StatutoryNode {node_id: $target_node_id})\n"
        "MATCH (rep:StatutoryNode {node_id: $repealing_node_id})\n"
        "SET target.valid_to = date($effective_date),\n"
        "    target.status = 'REPEALED'\n"
        "MERGE (target)-[r:REPEALED_BY]->(rep)\n"
        "SET r.effective_date = date($effective_date)\n"
        "RETURN target, rep"
    )
    return CypherQueryBundle(
        query=query,
        params={
            "target_node_id": target_node_id,
            "repealing_node_id": repealing_node_id,
            "effective_date": effective_date.isoformat(),
        },
    )


def build_point_in_time_cypher(
    as_of_date: date,
    act_name: str | None = None,
    max_citation_hops: int = 2,
) -> CypherQueryBundle:
    """
    Generates a point-in-time Graph-RAG Cypher traversal query that retrieves only
    statutes active on `as_of_date` and resolves multi-hop CITES edges that were
    also valid on `as_of_date`.
    """
    hops = max(1, min(max_citation_hops, 4))
    act_clause = "AND s.act_name = $act_name\n" if act_name else ""
    query = (
        "MATCH (s:StatutoryNode)\n"
        "WHERE s.valid_from <= date($as_of_date)\n"
        "  AND (s.valid_to IS NULL OR s.valid_to > date($as_of_date))\n"
        f"  {act_clause}"
        "  AND NOT EXISTS {\n"
        "    MATCH (s)-[r:REPEALED_BY]->(:StatutoryNode)\n"
        "    WHERE r.effective_date <= date($as_of_date)\n"
        "  }\n"
        f"OPTIONAL MATCH (s)-[:CITES*1..{hops}]->(cited:StatutoryNode)\n"
        "WHERE cited.valid_from <= date($as_of_date)\n"
        "  AND (cited.valid_to IS NULL OR cited.valid_to > date($as_of_date))\n"
        "  AND NOT EXISTS {\n"
        "    MATCH (cited)-[cr:REPEALED_BY]->(:StatutoryNode)\n"
        "    WHERE cr.effective_date <= date($as_of_date)\n"
        "  }\n"
        "RETURN s, collect(DISTINCT cited) AS cited_context\n"
        "ORDER BY s.act_name, s.section_code"
    )
    params: dict[str, Any] = {"as_of_date": as_of_date.isoformat()}
    if act_name:
        params["act_name"] = act_name
    return CypherQueryBundle(query=query, params=params)


class TemporalGraphStore:
    """
    Amendment- and repeal-aware knowledge graph store supporting deterministic
    point-in-time statutory resolution and multi-hop citation traversal.

    FinOps Note: Point-in-time filtering runs deterministically in O(V + E) prior
    to LLM invocation, stripping superseded and post-dated amendments so zero LLM
    input tokens are wasted on inactive legislation.
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
        closes the predecessor's `valid_to` window at `node.valid_from` and links
        them with an `AMENDED_BY` edge.
        """
        if amends_node_id and amends_node_id in self._nodes:
            prev = self._nodes[amends_node_id]
            updated_prev = prev.model_copy(
                update={
                    "valid_to": node.valid_from,
                    "status": StatutoryStatus.AMENDED,
                }
            )
            self._nodes[amends_node_id] = updated_prev
            self.add_edge(
                StatutoryEdge(
                    source_id=amends_node_id,
                    target_id=node.node_id,
                    edge_type=TemporalEdgeType.AMENDED_BY,
                    effective_date=node.valid_from,
                )
            )

        self._nodes[node.node_id] = node
        return build_upsert_amendment_cypher(node, predecessor_node_id=amends_node_id)

    def repeal_node(
        self,
        target_node_id: str,
        repealing_node_id: str,
        effective_date: date,
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
                "status": StatutoryStatus.REPEALED,
            }
        )
        self.add_edge(
            StatutoryEdge(
                source_id=target_node_id,
                target_id=repealing_node_id,
                edge_type=TemporalEdgeType.REPEALED_BY,
                effective_date=effective_date,
            )
        )
        return build_repeal_cypher(target_node_id, repealing_node_id, effective_date)

    def add_edge(self, edge: StatutoryEdge) -> None:
        if edge not in self._edges:
            self._edges.append(edge)

    def add_citation(
        self, source_id: str, target_id: str, effective_date: date
    ) -> None:
        self.add_edge(
            StatutoryEdge(
                source_id=source_id,
                target_id=target_id,
                edge_type=TemporalEdgeType.CITES,
                effective_date=effective_date,
            )
        )

    def _is_repealed_on_or_before(self, node_id: str, as_of_date: date) -> bool:
        return any(
            edge.source_id == node_id
            and edge.edge_type == TemporalEdgeType.REPEALED_BY
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
    ) -> list[StatutoryNode]:
        """
        Resolves all StatutoryNodes active on `as_of_date` (optionally filtered by `act_name`)
        and traverses multi-hop `CITES` edges that are also valid on `as_of_date`.
        """
        seed_nodes = [
            node
            for node in self._nodes.values()
            if self._is_node_valid_on(node, as_of_date)
            and (act_name is None or node.act_name == act_name)
        ]

        resolved: dict[str, StatutoryNode] = {n.node_id: n for n in seed_nodes}

        if include_citations and max_hops > 0:
            frontier = {n.node_id for n in seed_nodes}
            for _ in range(max_hops):
                next_frontier: set[str] = set()
                for src_id in frontier:
                    for edge in self._edges:
                        if (
                            edge.source_id == src_id
                            and edge.edge_type == TemporalEdgeType.CITES
                            and edge.effective_date <= as_of_date
                        ):
                            cited_node = self._nodes.get(edge.target_id)
                            if (
                                cited_node
                                and cited_node.node_id not in resolved
                                and self._is_node_valid_on(cited_node, as_of_date)
                            ):
                                resolved[cited_node.node_id] = cited_node
                                next_frontier.add(cited_node.node_id)
                if not next_frontier:
                    break
                frontier = next_frontier

        return sorted(
            resolved.values(), key=lambda n: (n.act_name, n.section_code, n.version)
        )


def get_default_temporal_store() -> TemporalGraphStore:
    """
    Returns a pre-populated TemporalGraphStore containing Malaysian Personal Data
    Protection Act (PDPA) 2010 vs. 2024 Amendment provisions and Employment Act
    provisions for immediate point-in-time auditing.
    """
    store = TemporalGraphStore()

    # PDPA 2010 original data breach / security rule (active 2013-11-15 to 2025-01-01)
    pdpa_sec9_v1 = StatutoryNode(
        node_id="PDPA-2010-SEC-9-V1",
        act_name="Personal Data Protection Act 2010",
        section_code="SEC-9",
        version=1,
        text=(
            "Section 9 (Security Principle - 2010): A data user shall take practical steps "
            "to protect personal data from any loss, misuse, modification, unauthorized or "
            "accidental access or disclosure. No mandatory statutory breach notification "
            "timeline is prescribed under the 2010 baseline."
        ),
        valid_from=date(2013, 11, 15),
    )
    store.upsert_node(pdpa_sec9_v1)

    # PDPA (Amendment) Act 2024 - introduces mandatory breach notification & direct processor liability (effective 2025-01-01)
    pdpa_sec9_v2 = StatutoryNode(
        node_id="PDPA-2010-SEC-9-V2",
        act_name="Personal Data Protection Act 2010",
        section_code="SEC-9",
        version=2,
        text=(
            "Section 9 & 12B (Security Principle & Mandatory Breach Notification - 2024 Amendment): "
            "Both data users and data processors are directly bound by the Security Principle. "
            "A data user MUST notify the Commissioner within 72 hours of becoming aware of a "
            "personal data breach, and penalties are increased up to RM 1,000,000."
        ),
        valid_from=date(2025, 1, 1),
    )
    store.upsert_node(pdpa_sec9_v2, amends_node_id="PDPA-2010-SEC-9-V1")

    # Cross-referenced Penalty Section (active from 2013-11-15 until repealed/replaced)
    pdpa_sec130_v1 = StatutoryNode(
        node_id="PDPA-2010-SEC-130-V1",
        act_name="Personal Data Protection Act 2010",
        section_code="SEC-130",
        version=1,
        text=(
            "Section 130 (Unlawful Collection/Disclosure): Fine not exceeding RM 500,000 "
            "or imprisonment not exceeding 3 years."
        ),
        valid_from=date(2013, 11, 15),
    )
    store.upsert_node(pdpa_sec130_v1)
    store.add_citation(
        "PDPA-2010-SEC-9-V1", "PDPA-2010-SEC-130-V1", effective_date=date(2013, 11, 15)
    )
    store.add_citation(
        "PDPA-2010-SEC-9-V2", "PDPA-2010-SEC-130-V1", effective_date=date(2025, 1, 1)
    )

    return store
