import base64
import importlib
import json
import urllib.error
import urllib.request
import uuid
from datetime import date, timedelta
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from lexgraph_lah.config import settings
from lexgraph_lah.graph.bilingual_critic import (
    audit_bilingual_divergence,
    audit_bilingual_pair,
)
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
    BilingualDivergenceReport,
    DeonticConstraint,
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
    StatutoryVersionDiff,
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
        "regime_code": new_node.regime_code,
        "carve_out_metadata_json": (
            json.dumps(new_node.carve_out_metadata, sort_keys=True)
            if new_node.carve_out_metadata is not None
            else None
        ),
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
            "    n.content_hash = $content_hash,\n"
            "    n.regime_code = $regime_code,\n"
            "    n.carve_out_metadata_json = $carve_out_metadata_json\n"
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
            "    n.content_hash = $content_hash,\n"
            "    n.regime_code = $regime_code,\n"
            "    n.carve_out_metadata_json = $carve_out_metadata_json\n"
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
        if territorial_scope
        and territorial_scope != TerritorialScope.ALL_MALAYSIA.value
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


def build_upsert_edge_cypher(edge: StatutoryEdge) -> CypherQueryBundle:
    """Generates a parameterized Cypher query to merge a typed StatutoryEdge between nodes."""
    rel_type = edge.edge_type.value
    if not rel_type.replace("_", "").isalnum():
        raise ValueError(f"Invalid Cypher relationship type: {rel_type}")
    query = (
        "MATCH (src:StatutoryNode {node_id: $source_id})\n"
        "MATCH (dst:StatutoryNode {node_id: $target_id})\n"
        f"MERGE (src)-[r:{rel_type}]->(dst)\n"
        "SET r.effective_date = date($effective_date),\n"
        "    r.gazette_ref = $gazette_ref\n"
        "RETURN src.node_id AS source_id, dst.node_id AS target_id"
    )
    return CypherQueryBundle(
        query=query,
        params={
            "source_id": edge.source_id,
            "target_id": edge.target_id,
            "effective_date": edge.effective_date.isoformat(),
            "gazette_ref": edge.gazette_ref,
        },
    )


@runtime_checkable
class GraphBackend(Protocol):
    """Persistence backend contract for TemporalGraphStore."""

    def execute_cypher(self, bundle: CypherQueryBundle) -> list[dict[str, Any]]: ...

    def health_check(self) -> bool: ...

    def close(self) -> None: ...


class InMemoryGraphBackend:
    """Zero-dependency in-memory default backend (`GRAPH_BACKEND=memory`)."""

    def execute_cypher(self, bundle: CypherQueryBundle) -> list[dict[str, Any]]:
        return []

    def health_check(self) -> bool:
        return True

    def close(self) -> None:
        return None


class Neo4jGraphBackend:
    """
    Persistent Neo4j 5 backend (`GRAPH_BACKEND=neo4j`) executing parameterized Cypher
    via the official Bolt `neo4j` driver when installed or Neo4j 5 Transactional HTTP API.
    """

    def __init__(
        self,
        uri: str | None = None,
        http_url: str | None = None,
        user: str | None = None,
        password: str | None = None,
        database: str | None = None,
        *,
        driver: Any | None = None,
        executor: Any | None = None,
    ) -> None:
        self.uri = uri or settings.neo4j_uri
        self.http_url = (http_url or settings.neo4j_http_url).rstrip("/")
        self.user = user or settings.neo4j_user
        self.password = password or settings.neo4j_password
        self.database = database or settings.neo4j_database
        self._driver = driver
        self._executor = executor
        self._executed_bundles: list[CypherQueryBundle] = []

        if self._driver is None and self._executor is None:
            try:
                neo4j_mod = importlib.import_module("neo4j")
                graph_db = getattr(neo4j_mod, "GraphDatabase", None)
                if graph_db is not None:
                    self._driver = graph_db.driver(
                        self.uri, auth=(self.user, self.password)
                    )
            except ImportError:
                self._driver = None

    @property
    def executed_bundles(self) -> list[CypherQueryBundle]:
        return list(self._executed_bundles)

    def _execute_http_cypher(self, bundle: CypherQueryBundle) -> list[dict[str, Any]]:
        endpoint = f"{self.http_url}/db/{self.database}/tx/commit"
        payload = json.dumps(
            {"statements": [{"statement": bundle.query, "parameters": bundle.params}]}
        ).encode()
        creds = base64.b64encode(f"{self.user}:{self.password}".encode()).decode(
            "ascii"
        )
        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Basic {creds}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw_body = resp.read().decode("utf-8")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"Neo4j HTTP Cypher execution failed: {exc}") from exc

        parsed = json.loads(raw_body)
        errors = parsed.get("errors") or []
        if errors:
            raise RuntimeError(f"Neo4j Cypher error: {errors}")

        rows: list[dict[str, Any]] = []
        for res in parsed.get("results") or []:
            cols = res.get("columns") or []
            for item in res.get("data") or []:
                row_vals = item.get("row") or []
                rows.append(dict(zip(cols, row_vals, strict=False)))
        return rows

    def execute_cypher(self, bundle: CypherQueryBundle) -> list[dict[str, Any]]:
        self._executed_bundles.append(bundle)
        if self._executor is not None:
            out = self._executor(bundle.query, bundle.params)
            return list(out) if out is not None else []
        if self._driver is not None:
            with self._driver.session(database=self.database) as session:
                result = session.run(bundle.query, bundle.params)
                return [dict(rec) for rec in result]
        return self._execute_http_cypher(bundle)

    def ensure_constraints(self) -> None:
        self.execute_cypher(
            CypherQueryBundle(
                query=(
                    "CREATE CONSTRAINT statutory_node_id_unique IF NOT EXISTS "
                    "FOR (n:StatutoryNode) REQUIRE n.node_id IS UNIQUE"
                ),
                params={},
            )
        )

    def health_check(self) -> bool:
        try:
            self.execute_cypher(CypherQueryBundle(query="RETURN 1 AS ok", params={}))
            return True
        except RuntimeError:
            return False

    def close(self) -> None:
        if self._driver is not None and hasattr(self._driver, "close"):
            self._driver.close()


class TemporalGraphStore:
    """
    Bi-temporal, bilingual, hierarchy-aware Malaysian legal knowledge graph store
    supporting Act -> Part -> Chapter -> Section -> Subsection -> Proviso/Illustration ->
    SourceSpan provenance, BM/EN crosswalk, Gazette versioning, and judicial treatment.
    """

    def __init__(self, backend: GraphBackend | None = None) -> None:
        self._nodes: dict[str, StatutoryNode] = {}
        self._edges: list[StatutoryEdge] = []
        self._backend: GraphBackend = backend or InMemoryGraphBackend()

    @property
    def backend(self) -> GraphBackend:
        return self._backend

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
                    "effective_to": prev_eff_to
                    if prev_eff_to >= (prev.effective_from or prev.valid_from)
                    else eff_date,
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

        bundle = build_upsert_amendment_cypher(node, predecessor_node_id=amends_node_id)
        if not isinstance(self._backend, InMemoryGraphBackend):
            self._backend.execute_cypher(bundle)
        return bundle

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
                "effective_to": prev_eff_to
                if prev_eff_to >= (target.effective_from or target.valid_from)
                else effective_date,
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
        bundle = build_repeal_cypher(
            target_node_id, repealing_node_id, effective_date, gazette_ref=gazette_ref
        )
        if not isinstance(self._backend, InMemoryGraphBackend):
            self._backend.execute_cypher(bundle)
        return bundle

    def add_edge(self, edge: StatutoryEdge) -> None:
        if edge not in self._edges:
            self._edges.append(edge)
            if not isinstance(self._backend, InMemoryGraphBackend):
                self._backend.execute_cypher(build_upsert_edge_cypher(edge))

    def sync_to_backend(self) -> int:
        """Persists all in-memory StatutoryNodes and StatutoryEdges to the configured backend."""
        if isinstance(self._backend, InMemoryGraphBackend):
            return 0
        count = 0
        for node in self._nodes.values():
            self._backend.execute_cypher(build_upsert_amendment_cypher(node))
            count += 1
        for edge in self._edges:
            self._backend.execute_cypher(build_upsert_edge_cypher(edge))
            count += 1
        return count

    def query_point_in_time_from_backend(
        self,
        as_of_date: date,
        act_name: str | None = None,
        max_citation_hops: int = 2,
        territorial_scope: str | None = None,
    ) -> list[dict[str, Any]]:
        """Executes the parameterized point-in-time Cypher query against the backend."""
        bundle = build_point_in_time_cypher(
            as_of_date=as_of_date,
            act_name=act_name,
            max_citation_hops=max_citation_hops,
            territorial_scope=territorial_scope,
        )
        return self._backend.execute_cypher(bundle)

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
                or node.normalized_language
                == ("ms" if language in {"bm", "ms"} else language)
            )
            and node.hierarchy_level not in excluded_levels
        ]
        seed_nodes = filter_by_territorial_scope(seed_candidates, territorial_scope)

        resolved: dict[str, StatutoryNode] = {n.node_id: n for n in seed_nodes}

        if include_citations and max_hops > 0:
            allowed_edges = {TemporalEdgeType.CITES}
            if include_translations:
                allowed_edges.update(
                    {
                        TemporalEdgeType.HAS_TRANSLATION,
                        TemporalEdgeType.BM_EN_EQUIVALENT,
                    }
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
            key=lambda n: (
                int(n.authority_tier),
                n.act_name,
                n.section_code,
                n.version,
            ),
        )

    def get_bilingual_pair(
        self,
        node_id: str,
        include_divergence: bool = False,
        as_of_date: date | None = None,
    ) -> BilingualClausePair | None:
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
        if (
            partner
            and partner.authoritative_language
            and not node.authoritative_language
        ):
            auth_id = partner.node_id

        spans: list[SourceSpan] = []
        if en_node:
            spans.extend(en_node.source_spans)
        if bm_node:
            spans.extend(bm_node.source_spans)

        div_report: BilingualDivergenceReport | None = None
        if include_divergence:
            div_report = audit_bilingual_pair(
                en_node=en_node,
                bm_node=bm_node,
                authoritative_node_id=auth_id,
                as_of_date=as_of_date,
                provision_id=node.node_id,
                act_name=node.act_name,
                act_number=node.act_number,
                section_code=node.section_code,
            )

        return BilingualClausePair(
            section_code=node.section_code,
            act_name=node.act_name,
            act_number=node.act_number,
            en_node=en_node,
            bm_node=bm_node,
            authoritative_node_id=auth_id,
            gazette_ref=node.gazette_ref,
            source_spans=spans,
            divergence_report=div_report,
        )

    def diff_statute_lineage(
        self,
        provision_id: str,
        from_date: date,
        to_date: date,
    ) -> StatutoryVersionDiff:
        """Compares a statutory provision across `from_date` and `to_date` at zero token cost."""
        from lexgraph_lah.graph.diff_engine import diff_statute_lineage

        return diff_statute_lineage(
            provision_id=provision_id,
            from_date=from_date,
            to_date=to_date,
            store=self,
        )

    def audit_bilingual_divergence(
        self,
        node_id: str,
        as_of_date: date | None = None,
    ) -> BilingualDivergenceReport:
        """Runs the Act 388 s. 63 Bilingual Divergence Critic on a stored statutory pair."""
        return audit_bilingual_divergence(
            node_id=node_id,
            as_of_date=as_of_date,
            store=self,
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
                if (
                    edge.source_id == cur
                    and edge.target_id in self._nodes
                    and edge.target_id not in visited
                ):
                    visited.add(edge.target_id)
                    queue.append(edge.target_id)
                elif (
                    edge.target_id == cur
                    and edge.source_id in self._nodes
                    and edge.source_id not in visited
                ):
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
                        court_name=case_node.court_name
                        or AUTHORITY_LABELS.get(case_node.authority_tier, "Court"),
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

        treatments = self._collect_judicial_treatments(
            treatment_targets, effective_date
        )
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
            "ms"
            if raw_mode in {"ms", "bm"}
            else ("en" if raw_mode == "en" else "bilingual")
        )
        threshold = (
            req.abstention_threshold if req.abstention_threshold is not None else 0.65
        )

        with measure_latency_ms() as elapsed_holder:
            normalized_query, detected_lang, expanded_terms = (
                normalize_and_expand_query(req.query)
            )

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
                for cnode in filter_by_territorial_scope(
                    candidate_cases, req.territorial_scope
                ):
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
            expanded_statutes: dict[str, StatutoryNode] = {
                n.node_id: n for n in matched_statutes
            }
            bilingual_pairs_map: dict[str, BilingualClausePair] = {}
            traversal_target_ids: set[str] = set()

            for node in matched_statutes:
                traversal_target_ids.add(node.node_id)
                pair = self.get_bilingual_pair(
                    node.node_id, include_divergence=True, as_of_date=effective_date
                )
                if pair:
                    dedup_key = f"{pair.act_number}:{pair.section_code}"
                    if dedup_key not in bilingual_pairs_map:
                        bilingual_pairs_map[dedup_key] = pair
                    if pair.en_node and self._is_node_valid_on(
                        pair.en_node, effective_date
                    ):
                        expanded_statutes.setdefault(pair.en_node.node_id, pair.en_node)
                        statute_scores.setdefault(
                            pair.en_node.node_id,
                            statute_scores.get(node.node_id, threshold),
                        )
                        traversal_target_ids.add(pair.en_node.node_id)
                    if pair.bm_node and self._is_node_valid_on(
                        pair.bm_node, effective_date
                    ):
                        expanded_statutes.setdefault(pair.bm_node.node_id, pair.bm_node)
                        statute_scores.setdefault(
                            pair.bm_node.node_id,
                            statute_scores.get(node.node_id, threshold),
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
                                        req.query,
                                        normalized_query,
                                        expanded_terms,
                                        cited,
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
                        lang_mode == "bilingual"
                        or lnode.normalized_language == lang_mode
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
                key=lambda e: (
                    e.act_number,
                    e.section_code,
                    e.language,
                    e.version,
                    e.effective_from,
                ),
            )

            # Gather judicial treatments interpreting/applying any node in the matched set,
            # its bilingual counterpart, or (when include_repealed_lineage=True) its lineage chain
            judicial_targets = (
                lineage_all_ids
                if req.include_repealed_lineage
                else traversal_target_ids
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
                            snode.authority_tier,
                            "Tier 2: Acts of Parliament (Akta) & State Enactments",
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
                    0.0
                    if item.hierarchy_level == HierarchyLevel.CASE
                    else -item.relevance_score,
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
                s_span_ids = [
                    sp.span_id
                    for sp in snode.source_spans
                    if sp.span_id in citations_by_id
                ]
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
                c_span_ids = [
                    sp.span_id
                    for sp in jt.source_spans
                    if sp.span_id in citations_by_id
                ]
                if c_span_ids:
                    overruled_tag = (
                        f" [OVERRULED by {jt.overruled_by_node_id}]"
                        if jt.is_overruled
                        else ""
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

            superseded_entries = [
                e for e in amendment_timeline if not e.is_active_at_query_date
            ]
            if superseded_entries:
                hist = superseded_entries[0]
                for h_span in hist.source_spans:
                    citations_by_id.setdefault(h_span.span_id, h_span)
                citations = list(citations_by_id.values())
                hist_spans = [
                    sp.span_id
                    for sp in hist.source_spans
                    if sp.span_id in citations_by_id
                ]
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

            answer_parts = [
                f"[{c.claim_id}] {c.statement} (Sources: {', '.join(c.source_span_ids)})"
                for c in claims
            ]
            answer_text = "\n".join(answer_parts)

            subgraph_node_ids = (
                lineage_all_ids
                | {jt.case_node_id for jt in judicial_treatments}
                | {
                    jt.overruled_by_node_id
                    for jt in judicial_treatments
                    if jt.overruled_by_node_id
                }
            )
            subgraph_nodes = [
                self._nodes[nid]
                for nid in sorted(subgraph_node_ids)
                if nid in self._nodes
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

            bilingual_crosswalk_list = list(bilingual_pairs_map.values())
            divergence_warnings = [
                pair.divergence_report
                for pair in bilingual_crosswalk_list
                if pair.divergence_report is not None
                and pair.divergence_report.has_divergence
            ]

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
                bilingual_crosswalk=bilingual_crosswalk_list,
                bilingual_divergence_warnings=divergence_warnings,
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


def create_temporal_store(
    backend_mode: str | None = None,
    *,
    backend: GraphBackend | None = None,
    seed_defaults: bool = True,
) -> TemporalGraphStore:
    """
    Factory creating a `TemporalGraphStore` backed by either the fast in-memory store
    (`GRAPH_BACKEND=memory`, default) or persistent `Neo4jGraphBackend` (`GRAPH_BACKEND=neo4j`).
    """
    mode = (backend_mode or settings.graph_backend or "memory").strip().lower()
    if backend is not None:
        active_backend = backend
    elif mode == "neo4j":
        active_backend = Neo4jGraphBackend()
    else:
        active_backend = InMemoryGraphBackend()

    if seed_defaults:
        store = _seed_default_corpus(TemporalGraphStore(backend=InMemoryGraphBackend()))
        store._backend = active_backend
        if not isinstance(active_backend, InMemoryGraphBackend):
            store.sync_to_backend()
        return store
    return TemporalGraphStore(backend=active_backend)


def get_default_temporal_store() -> TemporalGraphStore:
    """
    Returns a pre-populated Malaysian Legal Knowledge Graph containing:
    - Tier 1: Federal Constitution (Art 8)
    - Tier 2: PDPA 2010 [Act 709] (2010 baseline vs 2024 Amendment [Act A1727] Phases 1-3),
              Cyber Security Act 2024 [Act 854], Data Sharing Act 2025 [Act 864],
              Online Safety Act 2025 [Act 866], Consumer Credit Act 2025 [Act 873],
              Employment Act 1955 [Act 265], Act 562, Act 563, Act 658, Act 136, Act 388, Act 574
    - Tier 3: Sabah Labour Ordinance [Cap. 67], Sarawak Labour Ordinance [Cap. 76],
              P.U. (A) 219-222/2024, P.U. (A) 47/2025, P.U. (A) 342/2024, P.U. (B) 512 & 522/2024, BNM RMiT
    - Tier 4-7: Federal/COA/HC precedents & PDPD Guidelines 01/2025, 02/2025, 03/2025
    with full Act -> Part -> Section -> Subsection -> SourceSpan hierarchy and
    synchronized EN <-> BM translations.
    """
    if (settings.graph_backend or "memory").strip().lower() == "neo4j":
        return create_temporal_store(backend_mode="neo4j", seed_defaults=True)
    return _seed_default_corpus(TemporalGraphStore(backend=InMemoryGraphBackend()))


def _seed_default_corpus(store: TemporalGraphStore) -> TemporalGraphStore:
    """Populates `store` with the curated Malaysian statutory and judicial corpus."""

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
        regime_code="ACT_709",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT709-SEC9-PROC-LIABILITY",
                regime_id="ACT_709",
                modality="PROHIBITION",
                metric_key="processor_direct_liability",
                operator="FORBIDDEN_CLAUSE",
                threshold_value="zero_statutory_liability_waiver",
                description="Data processors cannot contractually exclude direct statutory Security Principle liability under Act 709 s. 9(1A).",
            ),
            DeonticConstraint(
                constraint_id="DC-ACT709-SEC12B-NOTICE-72H",
                regime_id="ACT_709",
                modality="OBLIGATION",
                metric_key="incident_notice_max_hours",
                operator="<=",
                threshold_value=72.0,
                unit="hours",
                recipient="PDPA_COMMISSIONER",
                notice_stage="INITIAL_NOTICE",
                description="Mandatory breach notification to the Commissioner within 72 hours under s. 12B [Act A1727].",
            ),
        ],
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

    pdpa_deontic_by_id: dict[str, list[DeonticConstraint]] = {
        "PDPA-2010-SEC-8-V1": [
            DeonticConstraint(
                constraint_id="DC-ACT709-SEC8-XFER",
                regime_id="ACT_709",
                modality="OBLIGATION",
                metric_key="cross_border_transfer_condition",
                operator="==",
                threshold_value="consent_or_adequacy_required",
                description="Disclosure and offshore transfer require consent or adequacy safeguards under Act 709.",
            ),
        ],
        "PDPA-2010-SEC-12B-V1": [
            DeonticConstraint(
                constraint_id="DC-ACT709-SEC12B-NOTICE",
                regime_id="ACT_709",
                modality="OBLIGATION",
                metric_key="incident_notice_max_hours",
                operator="<=",
                threshold_value=72.0,
                unit="hours",
                recipient="PDPA_COMMISSIONER",
                notice_stage="INITIAL_NOTICE",
                description="Notify Commissioner within 72 hours under Act 709 s. 12B [Act A1727].",
            ),
        ],
    }

    for nid, scode, vfrom, gref, page, en_txt, bm_txt in pdpa_principles_specs:
        node_constraints = pdpa_deontic_by_id.get(nid, [])
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
            regime_code="ACT_709",
            deontic_constraints=node_constraints,
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
            regime_code="ACT_709",
            deontic_constraints=node_constraints,
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
        regime_code="ACT_265",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="EA-1955-MAX-WEEKLY-HOURS",
                regime_id="ACT_265",
                modality="OBLIGATION",
                metric_key="max_weekly_work_hours",
                operator="<=",
                threshold_value=45.0,
                unit="hours",
                territorial_scope=[
                    TerritorialScope.PENINSULAR_MALAYSIA,
                    TerritorialScope.FEDERAL_TERRITORIES,
                ],
            )
        ],
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
        regime_code="ACT_265",
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
            "Section 104 (Hours of Work & Overtime - Sabah): Governs working hours (48 working hours "
            "weekly ceiling unless locally harmonized), overtime rates, rest day entitlements, and "
            "non-resident work pass obligations exclusively for employees working in the State of Sabah."
        ),
        valid_from=date(2005, 10, 1),
        authority_tier=AuthorityTier.TIER_3_ORDINANCE,
        territorial_scope=[TerritorialScope.SABAH],
        gazette_ref="Sabah Cap. 67",
        regime_code="SABAH_CAP67",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="SABAH-CAP67-MAX-WEEKLY-HOURS",
                regime_id="SABAH_CAP67",
                modality="OBLIGATION",
                metric_key="max_weekly_work_hours",
                operator="<=",
                threshold_value=48.0,
                unit="hours",
                territorial_scope=[TerritorialScope.SABAH],
            ),
            DeonticConstraint(
                constraint_id="SABAH-CAP67-NON-RESIDENT-PERMIT",
                regime_id="SABAH_CAP67",
                modality="OBLIGATION",
                metric_key="sabah_non_resident_work_permit",
                operator="==",
                threshold_value=True,
                unit="",
                territorial_scope=[TerritorialScope.SABAH],
            ),
        ],
    )
    sabah_ord_bm = StatutoryNode(
        node_id="SABAH-CAP67-SEC-104-V1-BM",
        act_name="Ordinan Buruh Sabah",
        act_number="Cap. 67",
        section_code="SEC-104",
        version=1,
        language="bm",
        text=(
            "Seksyen 104 (Waktu Kerja & Kerja Lebih Masa - Sabah): Mengawal selia waktu kerja (had "
            "48 jam seminggu), kadar kerja lebih masa, dan permit kerja bukan pemastautin khusus bagi "
            "pekerja di Negeri Sabah."
        ),
        valid_from=date(2005, 10, 1),
        authority_tier=AuthorityTier.TIER_3_ORDINANCE,
        territorial_scope=[TerritorialScope.SABAH],
        gazette_ref="Sabah Cap. 67",
        regime_code="SABAH_CAP67",
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
            "Section 105 (Hours of Work & Overtime - Sarawak): Governs working hours (48 working hours "
            "weekly ceiling), overtime rates, rest day entitlements, and Sarawak non-resident employment "
            "licence requirements exclusively for employees working in the State of Sarawak."
        ),
        valid_from=date(2005, 10, 1),
        authority_tier=AuthorityTier.TIER_3_ORDINANCE,
        territorial_scope=[TerritorialScope.SARAWAK],
        gazette_ref="Sarawak Cap. 76",
        regime_code="SARAWAK_CAP76",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="SARAWAK-CAP76-MAX-WEEKLY-HOURS",
                regime_id="SARAWAK_CAP76",
                modality="OBLIGATION",
                metric_key="max_weekly_work_hours",
                operator="<=",
                threshold_value=48.0,
                unit="hours",
                territorial_scope=[TerritorialScope.SARAWAK],
            ),
            DeonticConstraint(
                constraint_id="SARAWAK-CAP76-NON-RESIDENT-LICENCE",
                regime_id="SARAWAK_CAP76",
                modality="OBLIGATION",
                metric_key="sarawak_non_resident_licence",
                operator="==",
                threshold_value=True,
                unit="",
                territorial_scope=[TerritorialScope.SARAWAK],
            ),
        ],
    )
    sarawak_ord_bm = StatutoryNode(
        node_id="SARAWAK-CAP76-SEC-105-V1-BM",
        act_name="Ordinan Buruh Sarawak",
        act_number="Cap. 76",
        section_code="SEC-105",
        version=1,
        language="bm",
        text=(
            "Seksyen 105 (Waktu Kerja & Kerja Lebih Masa - Sarawak): Mengawal selia waktu kerja (had "
            "48 jam seminggu), kadar kerja lebih masa, dan lesen penggajian bukan pemastautin khusus "
            "bagi pekerja di Negeri Sarawak."
        ),
        valid_from=date(2005, 10, 1),
        authority_tier=AuthorityTier.TIER_3_ORDINANCE,
        territorial_scope=[TerritorialScope.SARAWAK],
        gazette_ref="Sarawak Cap. 76",
        regime_code="SARAWAK_CAP76",
    )
    _add_bilingual_pair(store, sarawak_ord_en, sarawak_ord_bm, authoritative="en")

    # Labuan Offshore Financial Services [Act 704] (Labuan territorial isolation)
    labuan_en = StatutoryNode(
        node_id="LABUAN-FSA-SEC-10-V1",
        act_name="Labuan Financial Services and Securities Act 2010",
        act_number="Act 704",
        section_code="SEC-10",
        version=1,
        language="en",
        text=(
            "Section 10 (Offshore Financial Licensing - Labuan): A person shall not carry on "
            "Labuan financial business in or from Labuan unless licensed by the Labuan Financial "
            "Services Authority under Act 704."
        ),
        valid_from=date(2010, 2, 11),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.LABUAN],
        gazette_ref="Act 704",
        regime_code="ACT_704",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="LABUAN-FSA-LICENSE",
                regime_id="ACT_704",
                modality="OBLIGATION",
                metric_key="labuan_lfsa_license_required",
                operator="==",
                threshold_value=True,
                unit="",
                territorial_scope=[TerritorialScope.LABUAN],
            )
        ],
    )
    labuan_bm = StatutoryNode(
        node_id="LABUAN-FSA-SEC-10-V1-BM",
        act_name="Akta Perkhidmatan Kewangan dan Sekuriti Labuan 2010",
        act_number="Act 704",
        section_code="SEC-10",
        version=1,
        language="bm",
        text=(
            "Seksyen 10 (Pelesenan Kewangan Luar Pesisir - Labuan): Seseorang tidak boleh menjalankan "
            "perniagaan kewangan Labuan di atau dari Labuan melainkan dilesenkan oleh Lembaga "
            "Perkhidmatan Kewangan Labuan di bawah Akta 704."
        ),
        valid_from=date(2010, 2, 11),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.LABUAN],
        gazette_ref="Akta 704",
        regime_code="ACT_704",
    )
    _add_bilingual_pair(store, labuan_en, labuan_bm, authoritative="en")

    # Electronic Commerce Act 2006 [Act 658] (Federal / All Malaysia)
    eca_658_en = StatutoryNode(
        node_id="ACT-658-SEC-7-V1",
        act_name="Electronic Commerce Act 2006",
        act_number="Act 658",
        section_code="SEC-7",
        version=1,
        language="en",
        text=(
            "Section 7 (Formation and Validity of Electronic Contracts): In the formation of a contract, "
            "communication of proposals, acceptance, and consent may be expressed by an electronic message "
            "and shall not be denied legal effect, validity or enforceability provided electronic consent "
            "is attributable and retrievable under the Electronic Commerce Act 2006 [Act 658]."
        ),
        valid_from=date(2006, 10, 19),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 658 / P.U. (B) 280/2006",
        regime_code="ACT_658",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="ACT-658-ELEC-CONTRACT-VALID",
                regime_id="ACT_658",
                modality="PERMISSION",
                metric_key="electronic_contract_formation_valid",
                operator="==",
                threshold_value=True,
                unit="",
                territorial_scope=[TerritorialScope.ALL_MALAYSIA],
            ),
            DeonticConstraint(
                constraint_id="ACT-658-ELEC-ATTRIBUTION",
                regime_id="ACT_658",
                modality="OBLIGATION",
                metric_key="electronic_consent_attribution_required",
                operator="==",
                threshold_value=True,
                unit="",
                territorial_scope=[TerritorialScope.ALL_MALAYSIA],
            ),
        ],
    )
    eca_658_bm = StatutoryNode(
        node_id="ACT-658-SEC-7-V1-BM",
        act_name="Akta Perdagangan Elektronik 2006",
        act_number="Act 658",
        section_code="SEC-7",
        version=1,
        language="bm",
        text=(
            "Seksyen 7 (Pembentukan dan Kesahan Kontrak Elektronik): Dalam pembentukan sesuatu kontrak, "
            "komunikasi cadangan, penerimaan dan persetujuan boleh dinyatakan melalui mesej elektronik "
            "dan tidak boleh dinafikan kesan undang-undang tertakluk kepada kebolehjejakan persetujuan "
            "di bawah Akta Perdagangan Elektronik 2006 [Akta 658]."
        ),
        valid_from=date(2006, 10, 19),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 658 / P.U. (B) 280/2006",
        regime_code="ACT_658",
    )
    _add_bilingual_pair(store, eca_658_en, eca_658_bm, authoritative="bm")

    # Interpretation Acts 1948 and 1967 [Act 388] s. 63 (Authoritative Bilingual Text)
    act388_en = StatutoryNode(
        node_id="ACT-388-SEC-63-V1",
        act_name="Interpretation Acts 1948 and 1967",
        act_number="Act 388",
        section_code="SEC-63",
        version=1,
        language="en",
        text=(
            "Section 63 (Authoritative Text of Bilingual Laws - Act 388): Where a written law is enacted "
            "in both the national language and English, the text in the national language shall be the "
            "authoritative text unless otherwise prescribed by order of the Yang di-Pertuan Agong."
        ),
        valid_from=date(1967, 5, 18),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 388",
        regime_code="ACT_388",
    )
    act388_bm = StatutoryNode(
        node_id="ACT-388-SEC-63-V1-BM",
        act_name="Akta Tafsiran 1948 dan 1967",
        act_number="Act 388",
        section_code="SEC-63",
        version=1,
        language="bm",
        text=(
            "Seksyen 63 (Teks Sahih Undang-Undang Dwibahasa - Akta 388): Jika sesuatu undang-undang bertulis "
            "diperbuat dalam bahasa kebangsaan dan bahasa Inggeris, teks dalam bahasa kebangsaan hendaklah "
            "menjadi teks sahih melainkan diperuntukkan selainnya melalui perintah Yang di-Pertuan Agong."
        ),
        valid_from=date(1967, 5, 18),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 388",
        regime_code="ACT_388",
    )
    _add_bilingual_pair(store, act388_en, act388_bm, authoritative="bm")

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
        gazette_date=date(2024, 12, 24),
        regime_code="ACT_709",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-PUA342-REG3-72H",
                regime_id="ACT_709",
                modality="OBLIGATION",
                metric_key="incident_notice_max_hours",
                operator="<=",
                threshold_value=72.0,
                unit="hours",
                recipient="PDPA_COMMISSIONER",
                notice_stage="INITIAL_NOTICE",
                description="Electronic personal data breach notification within 72 hours under P.U. (A) 342/2024 Reg 3.",
            ),
        ],
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
        regime_code="ACT_136",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="ACT-136-S75-REASONABLE-COMPENSATION",
                regime_id="ACT_136",
                modality="OBLIGATION",
                metric_key="penalty_clause_reasonable_compensation_cap",
                operator="==",
                threshold_value=True,
                unit="",
                territorial_scope=[TerritorialScope.ALL_MALAYSIA],
                description=(
                    "Under Contracts Act 1950 [Act 136] s. 75, stipulated breach penalties are "
                    "capped at reasonable compensation not exceeding the named sum."
                ),
            )
        ],
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
        regime_code="ACT_136",
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
    # Tier 2 & 3: Cyber Security Act 2024 [Act 854] & P.U. (A) 220/2024 (eff. 2024-08-26)
    # =========================================================================
    csa_act = StatutoryNode(
        node_id="CSA-2024-ACT",
        act_name="Cyber Security Act 2024",
        act_number="Act 854",
        section_code="ACT-854",
        hierarchy_level=HierarchyLevel.ACT,
        text="Cyber Security Act 2024 [Act 854]: An Act to enhance national cyber security and regulate National Critical Information Infrastructure (NCII).",
        valid_from=date(2024, 8, 26),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 854 / P.U. (B) 338/2024",
        regime_code="ACT_854",
    )
    store.upsert_node(csa_act)

    csa_s22_en = StatutoryNode(
        node_id="CSA-2024-SEC-22-V1",
        act_name="Cyber Security Act 2024",
        act_number="Act 854",
        section_code="SEC-22",
        parent_node_id="CSA-2024-ACT",
        version=1,
        language="en",
        text=(
            "Section 22 (Cyber Security Risk Assessment and Audit - Act 854): An NCII entity shall "
            "conduct mandatory cyber security risk assessments and statutory audits as directed by the "
            "Chief Executive (NACSA) and cannot contractually exclude regulatory audit access."
        ),
        valid_from=date(2024, 8, 26),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 854",
        regime_code="ACT_854",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT854-SEC22-AUDIT",
                regime_id="ACT_854",
                modality="OBLIGATION",
                metric_key="regulator_audit_access",
                operator="==",
                threshold_value=True,
                description="Mandatory NCII cyber risk assessment and NACSA/regulator audit access under Act 854 s. 22.",
            ),
            DeonticConstraint(
                constraint_id="DC-ACT854-SEC22-WAIVER",
                regime_id="ACT_854",
                modality="PROHIBITION",
                metric_key="processor_direct_liability",
                operator="FORBIDDEN_CLAUSE",
                threshold_value="zero_statutory_liability_waiver",
                description="Vendors/subcontractors supporting NCII cannot exclude statutory cyber security risk & audit accountability.",
            ),
        ],
        source_spans=[
            SourceSpan(
                span_id="SPAN-CSA-2024-SEC-22-EN",
                act_number="Act 854",
                section_id="SEC-22",
                language="en",
                pdf_page=24,
                char_offset_start=0,
                char_offset_end=247,
                text=(
                    "Section 22 (Cyber Security Risk Assessment and Audit - Act 854): An NCII entity shall "
                    "conduct mandatory cyber security risk assessments and statutory audits as directed by the "
                    "Chief Executive (NACSA) and cannot contractually exclude regulatory audit access."
                ),
            )
        ],
    )
    csa_s22_bm = StatutoryNode(
        node_id="CSA-2024-SEC-22-V1-BM",
        act_name="Akta Keselamatan Siber 2024",
        act_number="Act 854",
        section_code="SEC-22",
        parent_node_id="CSA-2024-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 22 (Penilaian Risiko dan Audit Keselamatan Siber - Akta 854): Entiti Infrastruktur "
            "Maklumat Kritikal Negara (NCII) wajib menjalankan penilaian risiko dan audit keselamatan siber "
            "serta membenarkan akses audit pengawal selia NACSA."
        ),
        valid_from=date(2024, 8, 26),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 854",
        regime_code="ACT_854",
        deontic_constraints=csa_s22_en.deontic_constraints,
    )
    _add_bilingual_pair(store, csa_s22_en, csa_s22_bm, authoritative="bm")

    csa_s23_en = StatutoryNode(
        node_id="CSA-2024-SEC-23-V1",
        act_name="Cyber Security Act 2024",
        act_number="Act 854",
        section_code="SEC-23",
        parent_node_id="CSA-2024-ACT",
        version=1,
        language="en",
        text=(
            "Section 23 (Notification of Cyber Security Incident - Act 854): An NCII entity shall notify "
            "NACSA and the sector lead immediately upon becoming aware of a cyber security incident, with "
            "initial particulars within 6 hours and a full report within 14 days."
        ),
        valid_from=date(2024, 8, 26),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 854",
        regime_code="ACT_854",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT854-SEC23-6H",
                regime_id="ACT_854",
                modality="OBLIGATION",
                metric_key="incident_notice_max_hours",
                operator="<=",
                threshold_value=6.0,
                unit="hours",
                recipient="NACSA",
                notice_stage="INITIAL_NOTICE",
                description="Immediate notice and initial particulars within 6 hours under Act 854 s. 23 & P.U. (A) 220/2024.",
            ),
            DeonticConstraint(
                constraint_id="DC-ACT854-SEC23-14D",
                regime_id="ACT_854",
                modality="OBLIGATION",
                metric_key="full_report_max_days",
                operator="<=",
                threshold_value=14.0,
                unit="days",
                recipient="NACSA",
                notice_stage="FULL_REPORT",
                description="Full cyber security incident report within 14 days under Act 854 s. 23 & P.U. (A) 220/2024.",
            ),
        ],
    )
    csa_s23_bm = StatutoryNode(
        node_id="CSA-2024-SEC-23-V1-BM",
        act_name="Akta Keselamatan Siber 2024",
        act_number="Act 854",
        section_code="SEC-23",
        parent_node_id="CSA-2024-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 23 (Pemberitahuan Insiden Keselamatan Siber - Akta 854): Entiti NCII wajib "
            "memaklumkan NACSA dengan segera, mengemukakan butiran awal dalam tempoh 6 jam dan "
            "laporan penuh dalam tempoh 14 hari."
        ),
        valid_from=date(2024, 8, 26),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 854",
        regime_code="ACT_854",
        deontic_constraints=csa_s23_en.deontic_constraints,
    )
    _add_bilingual_pair(store, csa_s23_en, csa_s23_bm, authoritative="bm")

    pua_220_en = StatutoryNode(
        node_id="PUA-220-2024-REG-4",
        act_name="Cyber Security (Notification of Cyber Security Incident) Regulations 2024",
        act_number="P.U. (A) 220/2024",
        section_code="REG-4",
        version=1,
        language="en",
        text=(
            "Regulation 4 [P.U. (A) 220/2024]: Mandates immediate notification of an NCII cyber security "
            "incident, submission of prescribed initial particulars within 6 hours, and submission of a "
            "comprehensive post-incident report within 14 days to NACSA."
        ),
        valid_from=date(2024, 8, 26),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (A) 220/2024",
        gazette_date=date(2024, 8, 22),
        regime_code="ACT_854",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-PUA220-REG4-6H",
                regime_id="ACT_854",
                modality="OBLIGATION",
                metric_key="incident_notice_max_hours",
                operator="<=",
                threshold_value=6.0,
                unit="hours",
                recipient="NACSA",
                notice_stage="INITIAL_NOTICE",
                description="P.U. (A) 220/2024 Reg 4 requires 6-hour initial NCII incident particulars.",
            ),
            DeonticConstraint(
                constraint_id="DC-PUA220-REG4-14D",
                regime_id="ACT_854",
                modality="OBLIGATION",
                metric_key="full_report_max_days",
                operator="<=",
                threshold_value=14.0,
                unit="days",
                recipient="NACSA",
                notice_stage="FULL_REPORT",
                description="P.U. (A) 220/2024 Reg 4 requires 14-day full cyber incident report.",
            ),
        ],
    )
    pua_220_bm = StatutoryNode(
        node_id="PUA-220-2024-REG-4-BM",
        act_name="Peraturan-Peraturan Keselamatan Siber (Pemberitahuan Insiden Keselamatan Siber) 2024",
        act_number="P.U. (A) 220/2024",
        section_code="REG-4",
        version=1,
        language="bm",
        text=(
            "Peraturan 4 [P.U. (A) 220/2024]: Mewajibkan pemberitahuan segera insiden keselamatan siber "
            "NCII, penyerahan butiran awal dalam tempoh 6 jam dan laporan penuh dalam tempoh 14 hari kepada NACSA."
        ),
        valid_from=date(2024, 8, 26),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (A) 220/2024",
        regime_code="ACT_854",
        deontic_constraints=pua_220_en.deontic_constraints,
    )
    _add_bilingual_pair(store, pua_220_en, pua_220_bm, authoritative="bm")

    # =========================================================================
    # Tier 3: BNM RMiT (Risk Management in Technology) Policy Document
    # =========================================================================
    bnm_rmit_incident_en = StatutoryNode(
        node_id="BNM-RMIT-SEC-10-32-V1",
        act_name="BNM Risk Management in Technology (RMiT)",
        act_number="BNM/RH/PD 028-98",
        section_code="PARA-10.32",
        version=1,
        language="en",
        text=(
            "BNM RMiT Paragraph 10.32 & 12.1 (Critical Incident & Cloud Oversight): A financial institution "
            "shall notify Bank Negara Malaysia of any critical technology or cyber incident within 1 hour "
            "of detection, and third-party cloud agreements must preserve BNM audit access and tested exit plans."
        ),
        valid_from=date(2020, 6, 19),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="BNM/RH/PD 028-98 (RMiT)",
        regime_code="BNM_RMIT",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-BNMRMIT-1H",
                regime_id="BNM_RMIT",
                modality="OBLIGATION",
                metric_key="incident_notice_max_hours",
                operator="<=",
                threshold_value=1.0,
                unit="hours",
                recipient="BNM_SUPERVISOR",
                notice_stage="INITIAL_NOTICE",
                description="BNM RMiT mandates critical technology incident escalation within 1 hour of detection.",
            ),
            DeonticConstraint(
                constraint_id="DC-BNMRMIT-AUDIT",
                regime_id="BNM_RMIT",
                modality="OBLIGATION",
                metric_key="regulator_audit_access",
                operator="==",
                threshold_value=True,
                description="BNM RMiT mandates unrestricted regulator & internal audit access over third-party/cloud providers.",
            ),
            DeonticConstraint(
                constraint_id="DC-BNMRMIT-CLOUD-EXIT",
                regime_id="BNM_RMIT",
                modality="OBLIGATION",
                metric_key="cross_border_transfer_condition",
                operator="==",
                threshold_value="bnm_oversight_and_exit_plan_required",
                description="BNM RMiT mandates documented cloud exit plans and data residency/regulatory oversight.",
            ),
            DeonticConstraint(
                constraint_id="DC-BNMRMIT-LIABILITY",
                regime_id="BNM_RMIT",
                modality="PROHIBITION",
                metric_key="processor_direct_liability",
                operator="FORBIDDEN_CLAUSE",
                threshold_value="zero_statutory_liability_waiver",
                description="Outsourcing/cloud agreements cannot waive vendor regulatory accountability under BNM RMiT.",
            ),
        ],
    )
    bnm_rmit_incident_bm = StatutoryNode(
        node_id="BNM-RMIT-SEC-10-32-V1-BM",
        act_name="Dokumen Polisi Pengurusan Risiko Teknologi BNM (RMiT)",
        act_number="BNM/RH/PD 028-98",
        section_code="PARA-10.32",
        version=1,
        language="bm",
        text=(
            "BNM RMiT Perenggan 10.32 & 12.1 (Insiden Kritikal & Pengawasan Awan): Institusi kewangan "
            "hendaklah memaklumkan Bank Negara Malaysia mengenai sebarang insiden teknologi kritikal dalam "
            "tempoh 1 jam serta mengekalkan hak audit BNM dan pelan keluar perkhidmatan awan."
        ),
        valid_from=date(2020, 6, 19),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="BNM/RH/PD 028-98 (RMiT)",
        regime_code="BNM_RMIT",
        deontic_constraints=bnm_rmit_incident_en.deontic_constraints,
    )
    _add_bilingual_pair(
        store, bnm_rmit_incident_en, bnm_rmit_incident_bm, authoritative="en"
    )

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
        "PDPA-2010-SEC-12B-V1",
        "PUA-342-2024-REG-3",
        effective_date=date(2025, 1, 1),
        gazette_ref="P.U. (A) 342/2024",
    )
    store.add_citation(
        "PDPA-2010-SEC-12A-V1",
        "JPDP-CIRC-01-2025",
        effective_date=date(2025, 2, 1),
        gazette_ref="JPDP Circular 01/2025",
    )
    store.add_citation(
        "CSA-2024-SEC-23-V1",
        "PUA-220-2024-REG-4",
        effective_date=date(2024, 8, 26),
        gazette_ref="P.U. (A) 220/2024",
    )
    store.add_citation(
        "BNM-RMIT-SEC-10-32-V1",
        "CSA-2024-SEC-23-V1",
        effective_date=date(2024, 8, 26),
        gazette_ref="Act 854",
    )

    # =========================================================================
    # Phase 1A: Cyber Security Act 2024 [Act 854] Full Subsidiary Suite (2024-2025)
    # =========================================================================
    pua_219_en = StatutoryNode(
        node_id="PUA-219-2024-REG-3",
        act_name="Cyber Security (Risk Assessment and Audit) Regulations 2024",
        act_number="P.U. (A) 219/2024",
        section_code="REG-3",
        parent_node_id="CSA-2024-ACT",
        version=1,
        language="en",
        text=(
            "Regulations 3 & 4 [P.U. (A) 219/2024]: An NCII entity shall carry out a cyber security "
            "risk assessment at least once a year (12 months) and cause an independent cyber security "
            "audit to be conducted by an approved auditor at least once every two years (2 years)."
        ),
        valid_from=date(2024, 8, 26),
        gazette_date=date(2024, 8, 22),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (A) 219/2024",
        regime_code="ACT_854",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-PUA219-RISK-ASSESSMENT-12M",
                regime_id="ACT_854",
                modality="OBLIGATION",
                metric_key="ncii_risk_assessment_max_interval_months",
                operator="<=",
                threshold_value=12.0,
                unit="months",
                description="Mandatory NCII cyber security risk assessment at least once a year under P.U. (A) 219/2024.",
            ),
            DeonticConstraint(
                constraint_id="DC-PUA219-AUDIT-2Y",
                regime_id="ACT_854",
                modality="OBLIGATION",
                metric_key="ncii_independent_audit_max_interval_years",
                operator="<=",
                threshold_value=2.0,
                unit="years",
                description="Mandatory independent NCII cyber security audit at least once every 2 years under P.U. (A) 219/2024.",
            ),
        ],
    )
    pua_219_bm = StatutoryNode(
        node_id="PUA-219-2024-REG-3-BM",
        act_name="Peraturan-Peraturan Keselamatan Siber (Penilaian Risiko dan Audit) 2024",
        act_number="P.U. (A) 219/2024",
        section_code="REG-3",
        parent_node_id="CSA-2024-ACT",
        version=1,
        language="bm",
        text=(
            "Peraturan 3 & 4 [P.U. (A) 219/2024]: Entiti NCII hendaklah menjalankan penilaian risiko "
            "keselamatan siber sekurang-kurangnya sekali setahun (12 bulan) dan audit bebas sekali setiap 2 tahun."
        ),
        valid_from=date(2024, 8, 26),
        gazette_date=date(2024, 8, 22),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (A) 219/2024",
        regime_code="ACT_854",
        deontic_constraints=pua_219_en.deontic_constraints,
    )
    _add_bilingual_pair(store, pua_219_en, pua_219_bm, authoritative="bm")

    csa_s27_en = StatutoryNode(
        node_id="CSA-2024-SEC-27-V1",
        act_name="Cyber Security Act 2024",
        act_number="Act 854",
        section_code="SEC-27",
        parent_node_id="CSA-2024-ACT",
        version=1,
        language="en",
        text=(
            "Section 27 (Licensing of Cyber Security Service Providers - Act 854): No person shall "
            "provide managed security operations centre monitoring or penetration testing services "
            "unless licensed by the Chief Executive (NACSA)."
        ),
        valid_from=date(2024, 8, 26),
        gazette_date=date(2024, 6, 26),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 854 / P.U. (B) 338/2024",
        regime_code="ACT_854",
    )
    csa_s27_bm = StatutoryNode(
        node_id="CSA-2024-SEC-27-V1-BM",
        act_name="Akta Keselamatan Siber 2024",
        act_number="Act 854",
        section_code="SEC-27",
        parent_node_id="CSA-2024-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 27 (Pelesenan Pemberi Perkhidmatan Keselamatan Siber - Akta 854): Tiada seorang "
            "pun boleh menyediakan perkhidmatan pemantauan pusat operasi keselamatan terurus atau ujian "
            "penembusan melainkan dilesenkan oleh NACSA."
        ),
        valid_from=date(2024, 8, 26),
        gazette_date=date(2024, 6, 26),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 854 / P.U. (B) 338/2024",
        regime_code="ACT_854",
    )
    _add_bilingual_pair(store, csa_s27_en, csa_s27_bm, authoritative="bm")

    pua_221_en = StatutoryNode(
        node_id="PUA-221-2024-REG-3",
        act_name="Cyber Security (Licensing of Cyber Security Service Provider) Regulations 2024",
        act_number="P.U. (A) 221/2024",
        section_code="REG-3",
        parent_node_id="CSA-2024-ACT",
        version=1,
        language="en",
        text=(
            "Regulations 2 & 3 [P.U. (A) 221/2024]: Providers of managed security operations centre "
            "(SOC) monitoring services and penetration testing services MUST hold a valid NACSA "
            "cyber security service provider licence."
        ),
        valid_from=date(2024, 8, 26),
        gazette_date=date(2024, 8, 22),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (A) 221/2024",
        regime_code="ACT_854",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-PUA221-MSSP-LICENSE",
                regime_id="ACT_854",
                modality="OBLIGATION",
                metric_key="mssp_soc_pentest_nacsa_license_required",
                operator="==",
                threshold_value=True,
                description="Mandatory NACSA licence for managed SOC monitoring and penetration testing vendors under P.U. (A) 221/2024.",
            ),
            DeonticConstraint(
                constraint_id="DC-PUA221-UNLICENSED-PROHIBITION",
                regime_id="ACT_854",
                modality="PROHIBITION",
                metric_key="unlicensed_mssp_service_prohibition",
                operator="FORBIDDEN_CLAUSE",
                threshold_value="unlicensed_mssp_or_pentest_vendor",
                description="Contracts engaging unlicensed MSSP SOC monitoring or penetration testing vendors contravene P.U. (A) 221/2024.",
            ),
        ],
    )
    pua_221_bm = StatutoryNode(
        node_id="PUA-221-2024-REG-3-BM",
        act_name="Peraturan-Peraturan Keselamatan Siber (Pelesenan Pemberi Perkhidmatan Keselamatan Siber) 2024",
        act_number="P.U. (A) 221/2024",
        section_code="REG-3",
        parent_node_id="CSA-2024-ACT",
        version=1,
        language="bm",
        text=(
            "Peraturan 2 & 3 [P.U. (A) 221/2024]: Pemberi perkhidmatan pemantauan pusat operasi "
            "keselamatan terurus (SOC) dan perkhidmatan ujian penembusan WAJIB memegang lesen sah "
            "daripada Ketua Eksekutif NACSA."
        ),
        valid_from=date(2024, 8, 26),
        gazette_date=date(2024, 8, 22),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (A) 221/2024",
        regime_code="ACT_854",
        deontic_constraints=pua_221_en.deontic_constraints,
    )
    _add_bilingual_pair(store, pua_221_en, pua_221_bm, authoritative="bm")

    pua_222_en = StatutoryNode(
        node_id="PUA-222-2024-REG-2",
        act_name="Cyber Security (Compounding of Offences) Regulations 2024",
        act_number="P.U. (A) 222/2024",
        section_code="REG-2",
        parent_node_id="CSA-2024-ACT",
        version=1,
        language="en",
        text=(
            "Regulations 2 & 3 [P.U. (A) 222/2024]: Prescribes compoundable offences under Act 854 "
            "and permits compounding up to 50% of the maximum statutory fine with written consent of "
            "the Public Prosecutor."
        ),
        valid_from=date(2024, 8, 26),
        gazette_date=date(2024, 8, 22),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (A) 222/2024",
        regime_code="ACT_854",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-PUA222-COMPOUND-50PCT",
                regime_id="ACT_854",
                modality="PERMISSION",
                metric_key="csa_offence_compounding_max_fine_pct",
                operator="<=",
                threshold_value=50.0,
                unit="percent",
                description="Compoundable Act 854 offences may be compounded up to 50% of max fine under P.U. (A) 222/2024.",
            )
        ],
    )
    pua_222_bm = StatutoryNode(
        node_id="PUA-222-2024-REG-2-BM",
        act_name="Peraturan-Peraturan Keselamatan Siber (Pengkompaunan Kesalahan) 2024",
        act_number="P.U. (A) 222/2024",
        section_code="REG-2",
        parent_node_id="CSA-2024-ACT",
        version=1,
        language="bm",
        text=(
            "Peraturan 2 & 3 [P.U. (A) 222/2024]: Menetapkan kesalahan boleh kompaun di bawah Akta 854 "
            "dengan kadar kompaun tidak melebihi 50% daripada denda maksimum dengan izin Pendakwa Raya."
        ),
        valid_from=date(2024, 8, 26),
        gazette_date=date(2024, 8, 22),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (A) 222/2024",
        regime_code="ACT_854",
        deontic_constraints=pua_222_en.deontic_constraints,
    )
    _add_bilingual_pair(store, pua_222_en, pua_222_bm, authoritative="bm")

    pua_47_2025_carveout = {
        "instrument": "P.U. (A) 47/2025",
        "title": "Cyber Security (Exemption) Order 2025",
        "gazette_date": "2025-01-28",
        "effective_from": "2025-02-01",
        "parent_act": "Act 854",
        "carve_out_type": "CONDITIONAL_SUBSIDIARY_EXEMPTION",
        "covered_sections": ["SEC-27"],
        "exempted_scope": (
            "Specified internal in-house SOC operations, non-commercial research/testing, "
            "and prescribed transitional MSSP licensing carve-outs subject to NACSA conditions."
        ),
    }
    pua_47_en = StatutoryNode(
        node_id="PUA-47-2025-EXEMPT",
        act_name="Cyber Security (Exemption) Order 2025",
        act_number="P.U. (A) 47/2025",
        section_code="ORDER-2",
        parent_node_id="CSA-2024-ACT",
        version=1,
        language="en",
        text=(
            "Cyber Security (Exemption) Order 2025 [P.U. (A) 47/2025] (effective 1 February 2025): "
            "Grants targeted licensing exemptions and transitional carve-outs from Section 27 of Act 854 "
            "for specified internal enterprise security operations and prescribed categories."
        ),
        valid_from=date(2025, 2, 1),
        gazette_date=date(2025, 1, 28),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (A) 47/2025",
        regime_code="ACT_854",
        carve_out_metadata=pua_47_2025_carveout,
    )
    pua_47_bm = StatutoryNode(
        node_id="PUA-47-2025-EXEMPT-BM",
        act_name="Perintah Keselamatan Siber (Pengecualian) 2025",
        act_number="P.U. (A) 47/2025",
        section_code="ORDER-2",
        parent_node_id="CSA-2024-ACT",
        version=1,
        language="bm",
        text=(
            "Perintah Keselamatan Siber (Pengecualian) 2025 [P.U. (A) 47/2025] (berkuat kuasa 1 Februari 2025): "
            "Memperuntukkan pengecualian bersyarat daripada kehendak pelesenan Seksyen 27 Akta 854 bagi "
            "kategori operasi keselamatan dalaman dan peralihan yang ditetapkan."
        ),
        valid_from=date(2025, 2, 1),
        gazette_date=date(2025, 1, 28),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (A) 47/2025",
        regime_code="ACT_854",
        carve_out_metadata=pua_47_2025_carveout,
    )
    _add_bilingual_pair(store, pua_47_en, pua_47_bm, authoritative="bm")

    store.add_citation(
        "CSA-2024-SEC-22-V1",
        "PUA-219-2024-REG-3",
        effective_date=date(2024, 8, 26),
        gazette_ref="P.U. (A) 219/2024",
    )
    store.add_citation(
        "CSA-2024-SEC-27-V1",
        "PUA-221-2024-REG-3",
        effective_date=date(2024, 8, 26),
        gazette_ref="P.U. (A) 221/2024",
    )
    store.add_citation(
        "CSA-2024-SEC-27-V1",
        "PUA-47-2025-EXEMPT",
        effective_date=date(2025, 2, 1),
        gazette_ref="P.U. (A) 47/2025",
    )

    # =========================================================================
    # Phase 1B: PDPA (Amendment) Act 2024 [Act A1727] 3-Phase Commencement
    # (P.U. (B) 522/2024: 2025-01-01, 2025-04-01, 2025-06-01) & 2025 Guidelines
    # =========================================================================
    pub_522_p1 = StatutoryNode(
        node_id="PUB-522-2024-P1",
        act_name="Appointment of Date of Coming into Operation (Act A1727 Phase 1)",
        act_number="P.U. (B) 522/2024",
        section_code="PHASE-1",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="en",
        text=(
            "P.U. (B) 522/2024 Phase 1 (effective 1 January 2025): Brings into operation sections "
            "7, 11, 13, and 14 of Act A1727 covering electronic service of notices and administrative continuity."
        ),
        valid_from=date(2025, 1, 1),
        gazette_date=date(2024, 12, 24),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (B) 522/2024",
        regime_code="ACT_709",
    )
    store.upsert_node(pub_522_p1)

    pub_522_p2 = StatutoryNode(
        node_id="PUB-522-2024-P2",
        act_name="Appointment of Date of Coming into Operation (Act A1727 Phase 2)",
        act_number="P.U. (B) 522/2024",
        section_code="PHASE-2",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="en",
        text=(
            "P.U. (B) 522/2024 Phase 2 (effective 1 April 2025): Brings into operation sections "
            "2, 3, 4, 5, 8, 10, and 12 of Act A1727: direct Data Processor Security Principle liability "
            "(up to RM 1,000,000 fine / 3 years imprisonment), biometric sensitive personal data, "
            "Data Controller terminology, and replacement of s. 129 cross-border whitelist."
        ),
        valid_from=date(2025, 4, 1),
        gazette_date=date(2024, 12, 24),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (B) 522/2024",
        regime_code="ACT_709",
    )
    store.upsert_node(pub_522_p2)

    pdpa_sec9_p2_en = StatutoryNode(
        node_id="PDPA-2010-SEC-9-P2-PROC",
        act_name="Personal Data Protection Act 2010",
        act_number="Act 709",
        section_code="SEC-9(1A)-P2",
        part_code="PART-II",
        parent_node_id="PDPA-2010-PART-II",
        version=1,
        language="en",
        text=(
            "Section 9(1A) & (2) [Act A1727 Phase 2, effective 1 April 2025]: A data processor is "
            "directly subject to the Security Principle and commits an offence punishable by a fine "
            "not exceeding RM 1,000,000 or imprisonment up to 3 years or both."
        ),
        valid_from=date(2025, 4, 1),
        gazette_date=date(2024, 12, 24),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act A1727 / P.U. (B) 522/2024 (Phase 2)",
        regime_code="ACT_709",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT709-P2-FINE-1M",
                regime_id="ACT_709",
                modality="OBLIGATION",
                metric_key="processor_direct_liability_max_fine_myr",
                operator=">=",
                threshold_value=1_000_000.0,
                unit="MYR",
                description="Act A1727 Phase 2 (2025-04-01) statutory fine ceiling of RM 1,000,000 on data controllers and data processors.",
            ),
            DeonticConstraint(
                constraint_id="DC-ACT709-P2-JAIL-3Y",
                regime_id="ACT_709",
                modality="OBLIGATION",
                metric_key="processor_direct_liability_max_imprisonment_years",
                operator=">=",
                threshold_value=3.0,
                unit="years",
                description="Act A1727 Phase 2 (2025-04-01) statutory imprisonment ceiling up to 3 years.",
            ),
        ],
    )
    pdpa_sec9_p2_bm = StatutoryNode(
        node_id="PDPA-2010-SEC-9-P2-PROC-BM",
        act_name="Akta Perlindungan Data Peribadi 2010",
        act_number="Act 709",
        section_code="SEC-9(1A)-P2",
        part_code="PART-II",
        parent_node_id="PDPA-2010-PART-II",
        version=1,
        language="bm",
        text=(
            "Seksyen 9(1A) & (2) [Akta A1727 Fasa 2, berkuat kuasa 1 April 2025]: Pemproses data "
            "terikat secara langsung di bawah Prinsip Keselamatan dengan denda sehingga RM 1,000,000 "
            "atau penjara sehingga 3 tahun atau kedua-duanya."
        ),
        valid_from=date(2025, 4, 1),
        gazette_date=date(2024, 12, 24),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta A1727 / P.U. (B) 522/2024 (Fasa 2)",
        regime_code="ACT_709",
        deontic_constraints=pdpa_sec9_p2_en.deontic_constraints,
    )
    _add_bilingual_pair(store, pdpa_sec9_p2_en, pdpa_sec9_p2_bm, authoritative="bm")

    pdpa_bio_en = StatutoryNode(
        node_id="PDPA-2010-SEC-4-BIOMETRIC-V1",
        act_name="Personal Data Protection Act 2010",
        act_number="Act 709",
        section_code="SEC-4-BIOMETRIC",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="en",
        text=(
            "Section 4 (Sensitive Personal Data - Biometric Data, Act A1727 Phase 2, eff. 2025-04-01): "
            "Biometric data relating to physical, physiological, or behavioural characteristics allowing "
            "unique identification is classified as sensitive personal data requiring explicit consent."
        ),
        valid_from=date(2025, 4, 1),
        gazette_date=date(2024, 12, 24),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act A1727 / P.U. (B) 522/2024 (Phase 2)",
        regime_code="ACT_709",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT709-BIOMETRIC-CONSENT",
                regime_id="ACT_709",
                modality="OBLIGATION",
                metric_key="biometric_sensitive_data_explicit_consent_required",
                operator="==",
                threshold_value=True,
                description="Biometric data requires Section 40 sensitive personal data explicit consent from 2025-04-01.",
            )
        ],
    )
    pdpa_bio_bm = StatutoryNode(
        node_id="PDPA-2010-SEC-4-BIOMETRIC-V1-BM",
        act_name="Akta Perlindungan Data Peribadi 2010",
        act_number="Act 709",
        section_code="SEC-4-BIOMETRIC",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 4 (Data Peribadi Sensitif - Data Biometrik, Akta A1727 Fasa 2, berkuat kuasa 1 April 2025): "
            "Data biometrik diklasifikasikan sebagai data peribadi sensitif yang memerlukan persetujuan nyata."
        ),
        valid_from=date(2025, 4, 1),
        gazette_date=date(2024, 12, 24),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta A1727 / P.U. (B) 522/2024 (Fasa 2)",
        regime_code="ACT_709",
        deontic_constraints=pdpa_bio_en.deontic_constraints,
    )
    _add_bilingual_pair(store, pdpa_bio_en, pdpa_bio_bm, authoritative="bm")

    pdpa_129_v1_en = StatutoryNode(
        node_id="PDPA-2010-SEC-129-V1",
        act_name="Personal Data Protection Act 2010",
        act_number="Act 709",
        section_code="SEC-129",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="en",
        text=(
            "Section 129 (Transfer of Personal Data Outside Malaysia - 2010 Whitelist Regime): "
            "A data user shall not transfer personal data outside Malaysia unless to a Ministerial "
            "whitelisted jurisdiction or subject to statutory exceptions such as consent."
        ),
        valid_from=date(2013, 11, 15),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 709 (P.U. (B) 464/2013)",
        regime_code="ACT_709",
    )
    pdpa_129_v1_bm = StatutoryNode(
        node_id="PDPA-2010-SEC-129-V1-BM",
        act_name="Akta Perlindungan Data Peribadi 2010",
        act_number="Act 709",
        section_code="SEC-129",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 129 (Pemindahan Data Peribadi ke Luar Malaysia - Rejim Senarai Putih 2010): "
            "Pengguna data tidak boleh memindahkan data peribadi ke luar Malaysia kecuali ke tempat "
            "yang dinyatakan oleh Menteri atau dengan persetujuan."
        ),
        valid_from=date(2013, 11, 15),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 709 (P.U. (B) 464/2013)",
        regime_code="ACT_709",
    )
    _add_bilingual_pair(store, pdpa_129_v1_en, pdpa_129_v1_bm, authoritative="bm")

    pdpa_129_v2_en = StatutoryNode(
        node_id="PDPA-2010-SEC-129-V2",
        act_name="Personal Data Protection Act 2010",
        act_number="Act 709",
        section_code="SEC-129",
        parent_node_id="PDPA-2010-ACT",
        version=2,
        language="en",
        text=(
            "Section 129 (Cross-Border Personal Data Transfer - Act A1727 Phase 2, eff. 2025-04-01): "
            "Replaces the Ministerial whitelist; a data controller may transfer personal data outside "
            "Malaysia if the destination jurisdiction provides substantially similar laws or an adequate "
            "level of protection, or with binding safeguards under CBPDT Guidelines No. 03/2025."
        ),
        valid_from=date(2025, 4, 1),
        gazette_date=date(2024, 12, 24),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act A1727 / P.U. (B) 522/2024 (Phase 2)",
        regime_code="ACT_709",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT709-SEC129-ADEQUACY",
                regime_id="ACT_709",
                modality="OBLIGATION",
                metric_key="cross_border_transfer_condition",
                operator="==",
                threshold_value="consent_or_adequacy_required",
                description="Amended Section 129 (eff. 2025-04-01) requires substantially similar law, adequacy, or consent.",
            )
        ],
    )
    pdpa_129_v2_bm = StatutoryNode(
        node_id="PDPA-2010-SEC-129-V2-BM",
        act_name="Akta Perlindungan Data Peribadi 2010",
        act_number="Act 709",
        section_code="SEC-129",
        parent_node_id="PDPA-2010-ACT",
        version=2,
        language="bm",
        text=(
            "Seksyen 129 (Pemindahan Data Rentas Sempadan - Akta A1727 Fasa 2, berkuat kuasa 1 April 2025): "
            "Menggantikan senarai putih; pengawal data boleh memindahkan data ke luar Malaysia sekiranya "
            "terdapat tahap perlindungan setara atau persetujuan di bawah Garis Panduan CBPDT Bil. 03/2025."
        ),
        valid_from=date(2025, 4, 1),
        gazette_date=date(2024, 12, 24),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta A1727 / P.U. (B) 522/2024 (Fasa 2)",
        regime_code="ACT_709",
        deontic_constraints=pdpa_129_v2_en.deontic_constraints,
    )
    _add_bilingual_pair(
        store,
        pdpa_129_v2_en,
        pdpa_129_v2_bm,
        authoritative="bm",
        amends_en_id="PDPA-2010-SEC-129-V1",
        amends_bm_id="PDPA-2010-SEC-129-V1-BM",
    )

    pdpd_cbpdt_en = StatutoryNode(
        node_id="PDPD-CBPDT-2025-03",
        act_name="PDPD Cross-Border Personal Data Transfer Guidelines No. 03/2025",
        act_number="PDPD Guideline No. 03/2025",
        section_code="GUIDELINE-03",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="en",
        text=(
            "CBPDT Guidelines No. 03/2025 (effective 29 April 2025): Prescribes Transfer Impact "
            "Assessment (TIA), binding contractual clauses, and comparable-protection verification "
            "for cross-border transfers under amended Section 129."
        ),
        valid_from=date(2025, 4, 29),
        gazette_date=date(2025, 4, 29),
        authority_tier=AuthorityTier.TIER_7_STATUTORY_TRIBUNAL,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="PDPD Guideline No. 03/2025",
        regime_code="ACT_709",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-CBPDT-TIA-REQ",
                regime_id="ACT_709",
                modality="OBLIGATION",
                metric_key="cbpdt_transfer_impact_assessment_required",
                operator="==",
                threshold_value=True,
                description="Transfer Impact Assessment and comparable protection safeguards under CBPDT Guidelines No. 03/2025.",
            )
        ],
    )
    pdpd_cbpdt_bm = StatutoryNode(
        node_id="PDPD-CBPDT-2025-03-BM",
        act_name="Garis Panduan Pemindahan Data Peribadi Rentas Sempadan JPDP Bil. 03/2025",
        act_number="PDPD Guideline No. 03/2025",
        section_code="GUIDELINE-03",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="bm",
        text=(
            "Garis Panduan CBPDT Bil. 03/2025 (berkuat kuasa 29 April 2025): Menetapkan Penilaian Impak "
            "Pemindahan (TIA) dan klausa kontrak mengikat bagi pemindahan rentas sempadan di bawah Seksyen 129."
        ),
        valid_from=date(2025, 4, 29),
        gazette_date=date(2025, 4, 29),
        authority_tier=AuthorityTier.TIER_7_STATUTORY_TRIBUNAL,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="PDPD Guideline No. 03/2025",
        regime_code="ACT_709",
        deontic_constraints=pdpd_cbpdt_en.deontic_constraints,
    )
    _add_bilingual_pair(store, pdpd_cbpdt_en, pdpd_cbpdt_bm, authoritative="bm")

    pub_522_p3 = StatutoryNode(
        node_id="PUB-522-2024-P3",
        act_name="Appointment of Date of Coming into Operation (Act A1727 Phase 3)",
        act_number="P.U. (B) 522/2024",
        section_code="PHASE-3",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="en",
        text=(
            "P.U. (B) 522/2024 Phase 3 (effective 1 June 2025): Brings into operation sections 6 and 9 "
            "of Act A1727: mandatory Data Protection Officer (DPO) appointment, Data Portability right "
            "(s. 43A), 72-hour Commissioner breach notification + within-7-days affected data-subject notice, "
            "and 2-year data breach register retention."
        ),
        valid_from=date(2025, 6, 1),
        gazette_date=date(2024, 12, 24),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="P.U. (B) 522/2024",
        regime_code="ACT_709",
    )
    store.upsert_node(pub_522_p3)

    pdpa_43a_en = StatutoryNode(
        node_id="PDPA-2010-SEC-43A-V1",
        act_name="Personal Data Protection Act 2010",
        act_number="Act 709",
        section_code="SEC-43A",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="en",
        text=(
            "Section 43A (Right to Data Portability - Act A1727 Phase 3, effective 1 June 2025): "
            "A data subject may request the data controller to transmit personal data directly to "
            "another data controller in a structured, commonly used, machine-readable format."
        ),
        valid_from=date(2025, 6, 1),
        gazette_date=date(2024, 12, 24),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act A1727 / P.U. (B) 522/2024 (Phase 3)",
        regime_code="ACT_709",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT709-SEC43A-PORTABILITY",
                regime_id="ACT_709",
                modality="OBLIGATION",
                metric_key="data_portability_right_enabled",
                operator="==",
                threshold_value=True,
                description="Mandatory data portability right under Act 709 s. 43A effective 2025-06-01.",
            )
        ],
    )
    pdpa_43a_bm = StatutoryNode(
        node_id="PDPA-2010-SEC-43A-V1-BM",
        act_name="Akta Perlindungan Data Peribadi 2010",
        act_number="Act 709",
        section_code="SEC-43A",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 43A (Hak kepada Kemudahalihan Data - Akta A1727 Fasa 3, berkuat kuasa 1 Jun 2025): "
            "Subjek data berhak meminta pengawal data memindahkan data peribadinya terus kepada pengawal "
            "data lain dalam format berstruktur dan boleh dibaca mesin."
        ),
        valid_from=date(2025, 6, 1),
        gazette_date=date(2024, 12, 24),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta A1727 / P.U. (B) 522/2024 (Fasa 3)",
        regime_code="ACT_709",
        deontic_constraints=pdpa_43a_en.deontic_constraints,
    )
    _add_bilingual_pair(store, pdpa_43a_en, pdpa_43a_bm, authoritative="bm")

    pdpd_dpo_en = StatutoryNode(
        node_id="PDPD-DPO-2025-01",
        act_name="PDPD Guideline on Appointment of Data Protection Officer No. 01/2025",
        act_number="PDPD Guideline No. 01/2025",
        section_code="GUIDELINE-01",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="en",
        text=(
            "PDPD Guideline No. 01/2025 (effective 1 June 2025): Mandates DPO appointment and competency "
            "where processing exceeds 20,000 data subjects, 10,000 sensitive data subjects, or regular "
            "systematic monitoring, with Commissioner registration within 21 days."
        ),
        valid_from=date(2025, 6, 1),
        gazette_date=date(2025, 2, 25),
        authority_tier=AuthorityTier.TIER_7_STATUTORY_TRIBUNAL,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="PDPD Guideline No. 01/2025",
        regime_code="ACT_709",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-PDPD-DPO-COMPETENCY",
                regime_id="ACT_709",
                modality="OBLIGATION",
                metric_key="dpo_appointment_and_competency_required",
                operator="==",
                threshold_value=True,
                description="Mandatory DPO appointment, competency, and 21-day Commissioner notification effective 2025-06-01.",
            )
        ],
    )
    pdpd_dpo_bm = StatutoryNode(
        node_id="PDPD-DPO-2025-01-BM",
        act_name="Garis Panduan Pelantikan Pegawai Perlindungan Data JPDP Bil. 01/2025",
        act_number="PDPD Guideline No. 01/2025",
        section_code="GUIDELINE-01",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="bm",
        text=(
            "Garis Panduan JPDP Bil. 01/2025 (berkuat kuasa 1 Jun 2025): Mewajibkan pelantikan dan "
            "kompetensi PPD bagi pemprosesan melebihi 20,000 subjek data atau 10,000 data sensitif."
        ),
        valid_from=date(2025, 6, 1),
        gazette_date=date(2025, 2, 25),
        authority_tier=AuthorityTier.TIER_7_STATUTORY_TRIBUNAL,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="PDPD Guideline No. 01/2025",
        regime_code="ACT_709",
        deontic_constraints=pdpd_dpo_en.deontic_constraints,
    )
    _add_bilingual_pair(store, pdpd_dpo_en, pdpd_dpo_bm, authoritative="bm")

    pdpd_dbn_en = StatutoryNode(
        node_id="PDPD-DBN-2025-02",
        act_name="PDPD Guideline on Data Breach Notification No. 02/2025",
        act_number="PDPD Guideline No. 02/2025",
        section_code="GUIDELINE-02",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="en",
        text=(
            "PDPD Data Breach Notification Guideline No. 02/2025 (effective 1 June 2025): Requires "
            "72-hour notification to the Commissioner, notification to affected data subjects within "
            "7 days where significant harm is caused, and maintenance of a data breach register for at least 2 years."
        ),
        valid_from=date(2025, 6, 1),
        gazette_date=date(2025, 2, 25),
        authority_tier=AuthorityTier.TIER_7_STATUTORY_TRIBUNAL,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="PDPD Guideline No. 02/2025",
        regime_code="ACT_709",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-PDPD-DBN-COMM-72H",
                regime_id="ACT_709",
                modality="OBLIGATION",
                metric_key="incident_notice_max_hours",
                operator="<=",
                threshold_value=72.0,
                unit="hours",
                recipient="PDPA_COMMISSIONER",
                notice_stage="INITIAL_NOTICE",
                description="72-hour Commissioner data breach notification under s. 12B & Guideline No. 02/2025.",
            ),
            DeonticConstraint(
                constraint_id="DC-PDPD-DBN-SUBJECT-7D",
                regime_id="ACT_709",
                modality="OBLIGATION",
                metric_key="data_subject_breach_notice_max_days",
                operator="<=",
                threshold_value=7.0,
                unit="days",
                recipient="AFFECTED_DATA_SUBJECT",
                notice_stage="DATA_SUBJECT_NOTICE",
                description="Affected data subjects must be notified without unnecessary delay and within 7 days of initial Commissioner notice.",
            ),
            DeonticConstraint(
                constraint_id="DC-PDPD-DBN-REGISTER-2Y",
                regime_id="ACT_709",
                modality="OBLIGATION",
                metric_key="breach_register_min_retention_years",
                operator=">=",
                threshold_value=2.0,
                unit="years",
                description="Mandatory data breach register retention for at least 2 years under Guideline No. 02/2025.",
            ),
        ],
    )
    pdpd_dbn_bm = StatutoryNode(
        node_id="PDPD-DBN-2025-02-BM",
        act_name="Garis Panduan Pemberitahuan Pelanggaran Data Peribadi JPDP Bil. 02/2025",
        act_number="PDPD Guideline No. 02/2025",
        section_code="GUIDELINE-02",
        parent_node_id="PDPA-2010-ACT",
        version=1,
        language="bm",
        text=(
            "Garis Panduan Pemberitahuan Pelanggaran Data Peribadi JPDP Bil. 02/2025 (berkuat kuasa 1 Jun 2025): "
            "Mewajibkan notis kepada Pesuruhjaya dalam 72 jam, notis kepada subjek data terjejas dalam "
            "tempoh 7 hari, dan penyimpanan daftar pelanggaran data sekurang-kurangnya 2 tahun."
        ),
        valid_from=date(2025, 6, 1),
        gazette_date=date(2025, 2, 25),
        authority_tier=AuthorityTier.TIER_7_STATUTORY_TRIBUNAL,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="PDPD Guideline No. 02/2025",
        regime_code="ACT_709",
        deontic_constraints=pdpd_dbn_en.deontic_constraints,
    )
    _add_bilingual_pair(store, pdpd_dbn_en, pdpd_dbn_bm, authoritative="bm")

    store.add_citation(
        "PDPA-2010-SEC-129-V2",
        "PDPD-CBPDT-2025-03",
        effective_date=date(2025, 4, 29),
        gazette_ref="PDPD Guideline No. 03/2025",
    )
    store.add_citation(
        "PDPA-2010-SEC-12A-V1",
        "PDPD-DPO-2025-01",
        effective_date=date(2025, 6, 1),
        gazette_ref="PDPD Guideline No. 01/2025",
    )
    store.add_citation(
        "PDPA-2010-SEC-12B-V1",
        "PDPD-DBN-2025-02",
        effective_date=date(2025, 6, 1),
        gazette_ref="PDPD Guideline No. 02/2025",
    )

    # =========================================================================
    # Phase 1C: 2025-2026 & Companion Malaysian Statutes
    # (Act 864, Act 866, Act 873, Act 562, Act 563)
    # =========================================================================
    act864_act = StatutoryNode(
        node_id="ACT-864-ACT",
        act_name="Data Sharing Act 2025",
        act_number="Act 864",
        section_code="ACT-864",
        hierarchy_level=HierarchyLevel.ACT,
        text="Data Sharing Act 2025 [Act 864]: An Act to provide for the sharing of data among public sector agencies and protection of shared data.",
        valid_from=date(2025, 4, 28),
        gazette_date=date(2025, 2, 20),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 864",
        regime_code="ACT_864",
    )
    store.upsert_node(act864_act)

    act864_s12_en = StatutoryNode(
        node_id="ACT-864-SEC-12-V1",
        act_name="Data Sharing Act 2025",
        act_number="Act 864",
        section_code="SEC-12",
        parent_node_id="ACT-864-ACT",
        version=1,
        language="en",
        text=(
            "Section 12 (Inter-Agency Public-Sector Data Sharing Governance - Act 864, eff. 2025-04-28): "
            "A public sector data recipient shall process shared data strictly for approved statutory "
            "purposes and enforce security, retention, and access controls prescribed by the National Data Sharing Committee."
        ),
        valid_from=date(2025, 4, 28),
        gazette_date=date(2025, 2, 20),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 864",
        regime_code="ACT_864",
    )
    act864_s12_bm = StatutoryNode(
        node_id="ACT-864-SEC-12-V1-BM",
        act_name="Akta Perkongsian Data 2025",
        act_number="Act 864",
        section_code="SEC-12",
        parent_node_id="ACT-864-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 12 (Tadbir Urus Perkongsian Data Sektor Awam - Akta 864, berkuat kuasa 28 April 2025): "
            "Agensi penerima data sektor awam hendaklah menggunakan data yang dikongsi hanya bagi maksud "
            "diluluskan dan mematuhi kawalan keselamatan."
        ),
        valid_from=date(2025, 4, 28),
        gazette_date=date(2025, 2, 20),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 864",
        regime_code="ACT_864",
    )
    _add_bilingual_pair(store, act864_s12_en, act864_s12_bm, authoritative="bm")

    act864_s17_en = StatutoryNode(
        node_id="ACT-864-SEC-17-V1",
        act_name="Data Sharing Act 2025",
        act_number="Act 864",
        section_code="SEC-17(1)",
        parent_node_id="ACT-864-ACT",
        version=1,
        language="en",
        text=(
            "Section 17(1) (Duty of Third Party to Protect Shared Data - Act 864, eff. 2025-04-28): "
            "Where a data recipient engages a third-party vendor or contractor for data migration, "
            "integration, or analytics involving shared public-sector data, the statutory security, "
            "confidentiality, and protection duties extend directly to that third-party vendor."
        ),
        valid_from=date(2025, 4, 28),
        gazette_date=date(2025, 2, 20),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 864",
        regime_code="ACT_864",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT864-S17-THIRD-PARTY",
                regime_id="ACT_864",
                modality="OBLIGATION",
                metric_key="public_sector_third_party_data_protection",
                operator="==",
                threshold_value=True,
                description="Act 864 s. 17(1) extends statutory shared-data protection duties to third-party public-sector vendors/contractors.",
            ),
            DeonticConstraint(
                constraint_id="DC-ACT864-S17-WAIVER",
                regime_id="ACT_864",
                modality="PROHIBITION",
                metric_key="public_sector_vendor_statutory_waiver",
                operator="FORBIDDEN_CLAUSE",
                threshold_value="third_party_shared_data_duty_waiver",
                description="Third-party vendors performing public-sector data migration, integration, or analytics cannot disclaim Act 864 s. 17(1) duties.",
            ),
        ],
    )
    act864_s17_bm = StatutoryNode(
        node_id="ACT-864-SEC-17-V1-BM",
        act_name="Akta Perkongsian Data 2025",
        act_number="Act 864",
        section_code="SEC-17(1)",
        parent_node_id="ACT-864-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 17(1) (Kewajipan Pihak Ketiga Melindungi Data Dikongsi - Akta 864, berkuat kuasa 28 April 2025): "
            "Apabila penerima data melantik vendor atau kontraktor pihak ketiga bagi migrasi, integrasi, atau "
            "analitik data sektor awam, kewajipan perlindungan berkanun terpakai secara langsung kepada pihak ketiga tersebut."
        ),
        valid_from=date(2025, 4, 28),
        gazette_date=date(2025, 2, 20),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 864",
        regime_code="ACT_864",
        deontic_constraints=act864_s17_en.deontic_constraints,
    )
    _add_bilingual_pair(store, act864_s17_en, act864_s17_bm, authoritative="bm")

    # Online Safety Act 2025 [Act 866] (eff. 2026-01-01) + Codes (eff. 2026-06-01)
    act866_act = StatutoryNode(
        node_id="ACT-866-ACT",
        act_name="Online Safety Act 2025",
        act_number="Act 866",
        section_code="ACT-866",
        hierarchy_level=HierarchyLevel.ACT,
        text="Online Safety Act 2025 [Act 866]: An Act to regulate harmful online content and enforce platform safety plans.",
        valid_from=date(2026, 1, 1),
        gazette_date=date(2025, 12, 19),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 866 / P.U. (B) 449/2025",
        regime_code="ACT_866",
    )
    store.upsert_node(act866_act)

    act866_s15_en = StatutoryNode(
        node_id="ACT-866-SEC-15-V1",
        act_name="Online Safety Act 2025",
        act_number="Act 866",
        section_code="SEC-15",
        parent_node_id="ACT-866-ACT",
        version=1,
        language="en",
        text=(
            "Sections 15-22 & 42 (Platform Harmful-Content Takedown, Safety Plan & RM 10M Penalty - "
            "Act 866, effective 1 January 2026): Licensed application and content service providers shall "
            "prepare an annual Online Safety Plan, mitigate and take down priority harmful content, report "
            "harmful content incidents promptly to MCMC, and face financial penalties up to RM 10,000,000 for non-compliance."
        ),
        valid_from=date(2026, 1, 1),
        gazette_date=date(2025, 12, 19),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 866 / P.U. (B) 449/2025",
        regime_code="ACT_866",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT866-HARMFUL-CONTENT",
                regime_id="ACT_866",
                modality="OBLIGATION",
                metric_key="online_safety_harmful_content_mitigation",
                operator="==",
                threshold_value=True,
                description="Mandatory platform harmful-content takedown and reporting duties under Act 866.",
            ),
            DeonticConstraint(
                constraint_id="DC-ACT866-SAFETY-PLAN",
                regime_id="ACT_866",
                modality="OBLIGATION",
                metric_key="online_safety_plan_required",
                operator="==",
                threshold_value=True,
                description="Mandatory platform Online Safety Plan governance under Act 866.",
            ),
            DeonticConstraint(
                constraint_id="DC-ACT866-MAX-PENALTY-10M",
                regime_id="ACT_866",
                modality="OBLIGATION",
                metric_key="online_safety_max_penalty_myr",
                operator=">=",
                threshold_value=10_000_000.0,
                unit="MYR",
                description="Maximum statutory penalty of RM 10,000,000 for platform non-compliance under Act 866.",
            ),
            DeonticConstraint(
                constraint_id="DC-ACT866-MCMC-REPORT-24H",
                regime_id="ACT_866",
                modality="OBLIGATION",
                metric_key="online_safety_harmful_content_notice_hours",
                operator="<=",
                threshold_value=24.0,
                unit="hours",
                recipient="MCMC",
                notice_stage="HARMFUL_CONTENT_REPORT",
                description="Platform harmful-content reporting/takedown escalation to MCMC within 24 hours under Act 866.",
            ),
        ],
    )
    act866_s15_bm = StatutoryNode(
        node_id="ACT-866-SEC-15-V1-BM",
        act_name="Akta Keselamatan Dalam Talian 2025",
        act_number="Act 866",
        section_code="SEC-15",
        parent_node_id="ACT-866-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 15-22 & 42 (Penurunan Kandungan Memudaratkan, Pelan Keselamatan & Penalti RM 10 Juta - "
            "Akta 866, berkuat kuasa 1 Januari 2026): Pemberi perkhidmatan berlesen wajib menyediakan Pelan "
            "Keselamatan Dalam Talian, menurunkan kandungan memudaratkan, dan tertakluk kepada penalti sehingga RM 10,000,000."
        ),
        valid_from=date(2026, 1, 1),
        gazette_date=date(2025, 12, 19),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 866 / P.U. (B) 449/2025",
        regime_code="ACT_866",
        deontic_constraints=act866_s15_en.deontic_constraints,
    )
    _add_bilingual_pair(store, act866_s15_en, act866_s15_bm, authoritative="bm")

    act866_code_en = StatutoryNode(
        node_id="ACT-866-CODE-2026-V1",
        act_name="Online Safety (Risk Mitigation Code and Child Protection Code) 2026",
        act_number="Act 866 Codes 2026",
        section_code="CODE-RMCP",
        parent_node_id="ACT-866-ACT",
        version=1,
        language="en",
        text=(
            "Risk Mitigation Code & Child Protection Code [Act 866, effective 1 June 2026]: Platforms "
            "shall enforce under-16 age verification using MyKad or passport checks and apply high-privacy "
            "child protection defaults."
        ),
        valid_from=date(2026, 6, 1),
        gazette_date=date(2026, 5, 15),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 866 Codes 2026",
        regime_code="ACT_866",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT866-U16-AGE-VERIFY",
                regime_id="ACT_866",
                modality="OBLIGATION",
                metric_key="online_safety_under_16_age_verification",
                operator="==",
                threshold_value=True,
                description="Mandatory under-16 MyKad/passport age-verification requirements effective 2026-06-01.",
            )
        ],
    )
    act866_code_bm = StatutoryNode(
        node_id="ACT-866-CODE-2026-V1-BM",
        act_name="Kod Mitigasi Risiko dan Kod Perlindungan Kanak-Kanak (Akta 866) 2026",
        act_number="Act 866 Codes 2026",
        section_code="CODE-RMCP",
        parent_node_id="ACT-866-ACT",
        version=1,
        language="bm",
        text=(
            "Kod Mitigasi Risiko & Kod Perlindungan Kanak-Kanak [Akta 866, berkuat kuasa 1 Jun 2026]: "
            "Platform wajib melaksanakan pengesahan umur bawah 16 tahun melalui MyKad atau pasport."
        ),
        valid_from=date(2026, 6, 1),
        gazette_date=date(2026, 5, 15),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 866 Codes 2026",
        regime_code="ACT_866",
        deontic_constraints=act866_code_en.deontic_constraints,
    )
    _add_bilingual_pair(store, act866_code_en, act866_code_bm, authoritative="bm")
    store.add_citation(
        "ACT-866-SEC-15-V1",
        "ACT-866-CODE-2026-V1",
        effective_date=date(2026, 6, 1),
        gazette_ref="Act 866 Codes 2026",
    )

    # Consumer Credit Act 2025 [Act 873] (eff. 2026-03-01, SKP licensing 2026-06-01)
    act873_act = StatutoryNode(
        node_id="ACT-873-ACT",
        act_name="Consumer Credit Act 2025",
        act_number="Act 873",
        section_code="ACT-873",
        hierarchy_level=HierarchyLevel.ACT,
        text="Consumer Credit Act 2025 [Act 873]: An Act to establish the Consumer Credit Commission (SKP) and regulate non-bank credit, BNPL, and debt collection.",
        valid_from=date(2026, 3, 1),
        gazette_date=date(2025, 12, 31),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 873",
        regime_code="ACT_873",
    )
    store.upsert_node(act873_act)

    act873_s35_en = StatutoryNode(
        node_id="ACT-873-SEC-35-V1",
        act_name="Consumer Credit Act 2025",
        act_number="Act 873",
        section_code="SEC-35",
        parent_node_id="ACT-873-ACT",
        version=1,
        language="en",
        text=(
            "Section 35 (Prohibition of Rule-of-78 and Flat-Rate Interest Calculation - Act 873, eff. 2026-03-01): "
            "A credit provider or Buy Now Pay Later (BNPL) operator shall NOT include or apply Rule-of-78 "
            "or flat-rate interest calculation clauses in any consumer credit agreement."
        ),
        valid_from=date(2026, 3, 1),
        gazette_date=date(2025, 12, 31),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 873",
        regime_code="ACT_873",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT873-NO-RULE78",
                regime_id="ACT_873",
                modality="PROHIBITION",
                metric_key="rule_of_78_interest_prohibition",
                operator="FORBIDDEN_CLAUSE",
                threshold_value="rule_of_78_or_flat_rate_interest",
                description="Prohibition of Rule-of-78 and flat-rate interest calculation clauses under Consumer Credit Act 2025 [Act 873].",
            )
        ],
    )
    act873_s35_bm = StatutoryNode(
        node_id="ACT-873-SEC-35-V1-BM",
        act_name="Akta Kredit Pengguna 2025",
        act_number="Act 873",
        section_code="SEC-35",
        parent_node_id="ACT-873-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 35 (Larangan Pengiraan Faedah Peraturan 78 dan Kadar Rata - Akta 873, berkuat kuasa 1 Mac 2026): "
            "Pemberi kredit atau pengendali Beli Sekarang Bayar Kemudian (BNPL) dilarang menggunakan klausa "
            "pengiraan faedah Peraturan 78 atau kadar rata dalam perjanjian kredit pengguna."
        ),
        valid_from=date(2026, 3, 1),
        gazette_date=date(2025, 12, 31),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 873",
        regime_code="ACT_873",
        deontic_constraints=act873_s35_en.deontic_constraints,
    )
    _add_bilingual_pair(store, act873_s35_en, act873_s35_bm, authoritative="bm")

    act873_skp_en = StatutoryNode(
        node_id="ACT-873-SKP-LIC-V1",
        act_name="Consumer Credit Act 2025",
        act_number="Act 873",
        section_code="SEC-42-SKP",
        parent_node_id="ACT-873-ACT",
        version=1,
        language="en",
        text=(
            "SKP Licensing & Registration Mandate [Act 873, effective 1 June 2026]: Non-bank credit "
            "providers, Buy Now Pay Later (BNPL) operators, leasing/factoring firms, and debt-collection "
            "agencies must be licensed or registered with Suruhanjaya Kredit Pengguna (SKP)."
        ),
        valid_from=date(2026, 6, 1),
        gazette_date=date(2025, 12, 31),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 873 (SKP Licensing)",
        regime_code="ACT_873",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT873-SKP-LICENSE",
                regime_id="ACT_873",
                modality="OBLIGATION",
                metric_key="skp_non_bank_credit_license_required",
                operator="==",
                threshold_value=True,
                description="Mandatory SKP licensing/registration for non-bank credit, BNPL, and debt-collection firms effective 2026-06-01.",
            )
        ],
    )
    act873_skp_bm = StatutoryNode(
        node_id="ACT-873-SKP-LIC-V1-BM",
        act_name="Akta Kredit Pengguna 2025",
        act_number="Act 873",
        section_code="SEC-42-SKP",
        parent_node_id="ACT-873-ACT",
        version=1,
        language="bm",
        text=(
            "Pelesenan & Pendaftaran SKP [Akta 873, berkuat kuasa 1 Jun 2026]: Pemberi kredit bukan bank, "
            "pengendali BNPL, dan agensi pemungut hutang wajib dilesenkan atau didaftarkan dengan "
            "Suruhanjaya Kredit Pengguna (SKP)."
        ),
        valid_from=date(2026, 6, 1),
        gazette_date=date(2025, 12, 31),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 873 (Pelesenan SKP)",
        regime_code="ACT_873",
        deontic_constraints=act873_skp_en.deontic_constraints,
    )
    _add_bilingual_pair(store, act873_skp_en, act873_skp_bm, authoritative="bm")
    store.add_citation(
        "ACT-873-SEC-35-V1",
        "ACT-873-SKP-LIC-V1",
        effective_date=date(2026, 6, 1),
        gazette_ref="Act 873",
    )

    # Companion Statutes: Digital Signature Act 1997 [Act 562] & Computer Crimes Act 1997 [Act 563]
    act562_en = StatutoryNode(
        node_id="ACT-562-SEC-62-V1",
        act_name="Digital Signature Act 1997",
        act_number="Act 562",
        section_code="SEC-62",
        version=1,
        language="en",
        text=(
            "Section 62 (Satisfaction of Signature Requirements - Digital Signature Act 1997 [Act 562]): "
            "Where a rule of law requires a signature, that requirement is satisfied by a digital signature "
            "verified by reference to the public key listed in a valid certificate issued by a licensed Certification Authority."
        ),
        valid_from=date(1998, 10, 1),
        gazette_date=date(1998, 9, 24),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 562 / P.U. (B) 397/1998",
        regime_code="ACT_562",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT562-DIGITAL-SIG",
                regime_id="ACT_562",
                modality="PERMISSION",
                metric_key="licensed_ca_digital_signature_valid",
                operator="==",
                threshold_value=True,
                description="Licensed CA digital signatures satisfy statutory signature requirements under Act 562 s. 62.",
            )
        ],
    )
    act562_bm = StatutoryNode(
        node_id="ACT-562-SEC-62-V1-BM",
        act_name="Akta Tandatangan Digital 1997",
        act_number="Act 562",
        section_code="SEC-62",
        version=1,
        language="bm",
        text=(
            "Seksyen 62 (Pematuhan Kehendak Tandatangan - Akta Tandatangan Digital 1997 [Akta 562]): "
            "Kehendak tandatangan undang-undang dipenuhi melalui tandatangan digital yang disahkan oleh "
            "Pihak Berkuasa Pemerakuan berlesen."
        ),
        valid_from=date(1998, 10, 1),
        gazette_date=date(1998, 9, 24),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 562 / P.U. (B) 397/1998",
        regime_code="ACT_562",
        deontic_constraints=act562_en.deontic_constraints,
    )
    _add_bilingual_pair(store, act562_en, act562_bm, authoritative="bm")
    store.add_citation(
        "ACT-658-SEC-7-V1",
        "ACT-562-SEC-62-V1",
        effective_date=date(2006, 10, 19),
        gazette_ref="Act 562",
    )

    act563_en = StatutoryNode(
        node_id="ACT-563-SEC-3-V1",
        act_name="Computer Crimes Act 1997",
        act_number="Act 563",
        section_code="SEC-3",
        version=1,
        language="en",
        text=(
            "Sections 3 & 5 (Unauthorized Access and Modification - Computer Crimes Act 1997 [Act 563]): "
            "Knowingly causing a computer to perform any function with intent to secure unauthorized access "
            "to any program or data, or unauthorized modification of computer contents, constitutes a criminal offence."
        ),
        valid_from=date(2000, 6, 1),
        gazette_date=date(2000, 5, 25),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 563 / P.U. (B) 175/2000",
        regime_code="ACT_563",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT563-UNAUTH-ACCESS",
                regime_id="ACT_563",
                modality="PROHIBITION",
                metric_key="unauthorized_computer_access_prohibited",
                operator="FORBIDDEN_CLAUSE",
                threshold_value="unauthorized_computer_access_or_modification",
                description="Unauthorized computer access or content modification is prohibited under Computer Crimes Act 1997 [Act 563] ss. 3 & 5.",
            )
        ],
    )
    act563_bm = StatutoryNode(
        node_id="ACT-563-SEC-3-V1-BM",
        act_name="Akta Jenayah Komputer 1997",
        act_number="Act 563",
        section_code="SEC-3",
        version=1,
        language="bm",
        text=(
            "Seksyen 3 & 5 (Capaian dan Pengubahsuaian Tanpa Kuasa - Akta Jenayah Komputer 1997 [Akta 563]): "
            "Capaian tanpa kuasa terhadap bahan komputer atau pengubahsuaian kandungan komputer tanpa kuasa "
            "adalah suatu kesalahan jenayah."
        ),
        valid_from=date(2000, 6, 1),
        gazette_date=date(2000, 5, 25),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 563 / P.U. (B) 175/2000",
        regime_code="ACT_563",
        deontic_constraints=act563_en.deontic_constraints,
    )
    _add_bilingual_pair(store, act563_en, act563_bm, authoritative="bm")
    store.add_citation(
        "CSA-2024-SEC-23-V1",
        "ACT-563-SEC-3-V1",
        effective_date=date(2024, 8, 26),
        gazette_ref="Act 563",
    )

    # =========================================================================
    # Phase 5 (Deliverable 2 & 3): Act 388 s. 54, Stamp Act 1949 [Act 378] SDSAS,
    # Income Tax Act 1967 [Act 53] s. 82C & s. 120(1)(d) MyInvois, MOSTI AIGE,
    # and BNM Outsourcing + RMiT Cross-Links
    # =========================================================================
    act388_s54_en = StatutoryNode(
        node_id="ACT-388-SEC-54-V1",
        act_name="Interpretation Acts 1948 and 1967",
        act_number="Act 388",
        section_code="SEC-54",
        version=1,
        language="en",
        text=(
            "Section 54 (Computation of Time - Act 388): In computing time for the purposes of any "
            "written law, where an act or notice must be done within a number of days from a given "
            "event, the day on which the event occurs is excluded, and if the last day falls on a "
            "weekly holiday or public holiday, the period shall include the next following day not being an excluded day."
        ),
        valid_from=date(1967, 5, 18),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 388",
        regime_code="ACT_388",
    )
    act388_s54_bm = StatutoryNode(
        node_id="ACT-388-SEC-54-V1-BM",
        act_name="Akta Tafsiran 1948 dan 1967",
        act_number="Act 388",
        section_code="SEC-54",
        version=1,
        language="bm",
        text=(
            "Seksyen 54 (Pengiraan Masa - Akta 388): Dalam mengira masa bagi maksud mana-mana "
            "undang-undang bertulis, hari berlakunya peristiwa itu hendaklah dikecualikan, dan jika "
            "hari terakhir jatuh pada hari kelepasan mingguan atau kelepasan am, tempoh itu hendaklah "
            "merangkumi hari berikutnya yang bukan hari dikecualikan."
        ),
        valid_from=date(1967, 5, 18),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 388",
        regime_code="ACT_388",
    )
    _add_bilingual_pair(store, act388_s54_en, act388_s54_bm, authoritative="bm")

    # 1. Stamp Act 1949 [Act 378] & Tax Measures Act 2025 (SDSAS, eff. 2026-01-01)
    act378_act = StatutoryNode(
        node_id="ACT-378-ACT",
        act_name="Stamp Act 1949",
        act_number="Act 378",
        section_code="ACT-378",
        hierarchy_level=HierarchyLevel.ACT,
        text="Stamp Act 1949 [Act 378]: Consolidated Malaysian law governing stamp duty, admissibility of instruments, and the Stamp Duty Self-Assessment System (SDSAS).",
        valid_from=date(1949, 12, 5),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 378",
        regime_code="ACT_378",
    )
    store.upsert_node(act378_act)

    act378_s52_en = StatutoryNode(
        node_id="ACT-378-SEC-52-V1",
        act_name="Stamp Act 1949",
        act_number="Act 378",
        section_code="SEC-52",
        parent_node_id="ACT-378-ACT",
        version=1,
        language="en",
        text=(
            "Section 52 (Instruments Not Duly Stamped Inadmissible in Evidence - Act 378): "
            "No instrument chargeable with duty shall be admitted in evidence for any purpose by any "
            "person having by law or consent authority to receive evidence, or acted upon, registered, "
            "or authenticated, unless such instrument is duly stamped."
        ),
        valid_from=date(1949, 12, 5),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 378",
        regime_code="ACT_378",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT378-S52-STAMPING",
                regime_id="ACT_378",
                modality="OBLIGATION",
                metric_key="stamp_duty_duly_stamped_admissibility",
                operator="==",
                threshold_value=True,
                description="Unstamped chargeable instruments are inadmissible in evidence under Stamp Act 1949 [Act 378] s. 52.",
            )
        ],
    )
    act378_s52_bm = StatutoryNode(
        node_id="ACT-378-SEC-52-V1-BM",
        act_name="Akta Setem 1949",
        act_number="Act 378",
        section_code="SEC-52",
        parent_node_id="ACT-378-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 52 (Surat Cara Tidak Disetemkan dengan Sempurna Tidak Boleh Diterima Sebagai Keterangan - Akta 378): "
            "Tiada surat cara yang dikenakan duti boleh diterima sebagai keterangan atau didaftarkan "
            "melainkan surat cara tersebut telah disetemkan dengan sempurna."
        ),
        valid_from=date(1949, 12, 5),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 378",
        regime_code="ACT_378",
        deontic_constraints=act378_s52_en.deontic_constraints,
    )
    _add_bilingual_pair(store, act378_s52_en, act378_s52_bm, authoritative="en")

    act378_sdsas_en = StatutoryNode(
        node_id="ACT-378-SDSAS-2026-V1",
        act_name="Stamp Act 1949 (SDSAS - Tax Measures Act 2025)",
        act_number="Act 378",
        section_code="SEC-SDSAS-30D",
        parent_node_id="ACT-378-ACT",
        version=1,
        language="en",
        text=(
            "Stamp Duty Self-Assessment System [Act 378 & Tax Measures Act 2025, effective 1 January 2026]: "
            "A duty payer shall submit a self-assessment stamp duty return and pay assessed stamp duty "
            "within 30 days from execution of the instrument."
        ),
        valid_from=date(2026, 1, 1),
        gazette_date=date(2025, 12, 31),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Tax Measures Act 2025 / Act 378 (SDSAS)",
        regime_code="ACT_378",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT378-SDSAS-RETURN",
                regime_id="ACT_378",
                modality="OBLIGATION",
                metric_key="stamp_duty_self_assessment_required",
                operator="==",
                threshold_value=True,
                description="Mandatory SDSAS self-assessment stamp duty return effective 2026-01-01.",
            ),
            DeonticConstraint(
                constraint_id="DC-ACT378-SDSAS-30D",
                regime_id="ACT_378",
                modality="OBLIGATION",
                metric_key="stamp_duty_payment_max_days",
                operator="<=",
                threshold_value=30.0,
                unit="days",
                recipient="LHDN_STAMP_DUTY",
                notice_stage="SELF_ASSESSMENT_PAYMENT",
                description="SDSAS self-assessment return and stamp duty payment due within 30 days from execution.",
            ),
        ],
    )
    act378_sdsas_bm = StatutoryNode(
        node_id="ACT-378-SDSAS-2026-V1-BM",
        act_name="Akta Setem 1949 (SDSAS - Akta Langkah-Langkah Pengiraan dan Pengutipan Cukai 2025)",
        act_number="Act 378",
        section_code="SEC-SDSAS-30D",
        parent_node_id="ACT-378-ACT",
        version=1,
        language="bm",
        text=(
            "Sistem Taksiran Sendiri Duti Setem [Akta 378 & Akta Langkah Cukai 2025, berkuat kuasa 1 Januari 2026]: "
            "Pembayar duti hendaklah mengemukakan penyata taksiran sendiri dan membayar duti setem "
            "dalam tempoh 30 hari dari tarikh penyempurnaan surat cara."
        ),
        valid_from=date(2026, 1, 1),
        gazette_date=date(2025, 12, 31),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 378 (SDSAS)",
        regime_code="ACT_378",
        deontic_constraints=act378_sdsas_en.deontic_constraints,
    )
    _add_bilingual_pair(store, act378_sdsas_en, act378_sdsas_bm, authoritative="bm")

    act378_emp_v1_en = StatutoryNode(
        node_id="ACT-378-EMP-EXEMPT-V1",
        act_name="Stamp Act 1949",
        act_number="Act 378",
        section_code="FIRST-SCHED-ITEM-4",
        parent_node_id="ACT-378-ACT",
        version=1,
        language="en",
        text=(
            "First Schedule Item 4 (Pre-2026 Employment Contract Stamp Duty Exemption - Act 378): "
            "Employment contracts where monthly wages do not exceed RM 300 shall be exempt from stamp duty."
        ),
        valid_from=date(1949, 12, 5),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 378",
        regime_code="ACT_378",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT378-EMP-300",
                regime_id="ACT_378",
                modality="OBLIGATION",
                metric_key="employment_stamp_duty_exempt_monthly_myr",
                operator="<=",
                threshold_value=300.0,
                unit="MYR",
                description="Pre-2026 employment contract stamp duty exemption ceiling of RM 300/month.",
            )
        ],
    )
    act378_emp_v1_bm = StatutoryNode(
        node_id="ACT-378-EMP-EXEMPT-V1-BM",
        act_name="Akta Setem 1949",
        act_number="Act 378",
        section_code="FIRST-SCHED-ITEM-4",
        parent_node_id="ACT-378-ACT",
        version=1,
        language="bm",
        text=(
            "Jadual Pertama Butiran 4 (Pengecualian Duti Setem Kontrak Pekerjaan Pra-2026 - Akta 378): "
            "Kontrak perkhidmatan pekerjaan dengan gaji bulanan tidak melebihi RM 300 hendaklah dikecualikan daripada duti setem."
        ),
        valid_from=date(1949, 12, 5),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 378",
        regime_code="ACT_378",
        deontic_constraints=act378_emp_v1_en.deontic_constraints,
    )
    _add_bilingual_pair(store, act378_emp_v1_en, act378_emp_v1_bm, authoritative="en")

    act378_emp_v2_en = StatutoryNode(
        node_id="ACT-378-EMP-EXEMPT-V2",
        act_name="Stamp Act 1949",
        act_number="Act 378",
        section_code="FIRST-SCHED-ITEM-4",
        parent_node_id="ACT-378-ACT",
        version=2,
        language="en",
        text=(
            "First Schedule Item 4 (2026 Employment Contract Stamp Duty Exemption - Act 378, effective 1 January 2026): "
            "Employment contracts where monthly salary does not exceed RM 3,000 shall be exempt from stamp duty, "
            "replacing the legacy RM 300 monthly threshold."
        ),
        valid_from=date(2026, 1, 1),
        gazette_date=date(2025, 12, 31),
        amendment_act_ref="Finance / Tax Measures Act 2025",
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Tax Measures Act 2025 / Act 378",
        regime_code="ACT_378",
        carve_out_metadata={
            "previous_threshold_myr": 300.0,
            "new_threshold_myr": 3000.0,
            "effective_from": "2026-01-01",
        },
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT378-EMP-3000",
                regime_id="ACT_378",
                modality="OBLIGATION",
                metric_key="employment_stamp_duty_exempt_monthly_myr",
                operator="<=",
                threshold_value=3000.0,
                unit="MYR",
                description="Employment contract stamp duty exemption threshold raised from RM 300 to RM 3,000/month effective 2026-01-01.",
            )
        ],
    )
    act378_emp_v2_bm = StatutoryNode(
        node_id="ACT-378-EMP-EXEMPT-V2-BM",
        act_name="Akta Setem 1949",
        act_number="Act 378",
        section_code="FIRST-SCHED-ITEM-4",
        parent_node_id="ACT-378-ACT",
        version=2,
        language="bm",
        text=(
            "Jadual Pertama Butiran 4 (Pengecualian Duti Setem Kontrak Pekerjaan 2026 - Akta 378, berkuat kuasa 1 Januari 2026): "
            "Kontrak pekerjaan dengan gaji bulanan tidak melebihi RM 3,000 hendaklah dikecualikan daripada duti setem, "
            "menggantikan had lama RM 300 sebulan."
        ),
        valid_from=date(2026, 1, 1),
        gazette_date=date(2025, 12, 31),
        amendment_act_ref="Finance / Tax Measures Act 2025",
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta Langkah Cukai 2025 / Akta 378",
        regime_code="ACT_378",
        carve_out_metadata=act378_emp_v2_en.carve_out_metadata,
        deontic_constraints=act378_emp_v2_en.deontic_constraints,
    )
    _add_bilingual_pair(
        store,
        act378_emp_v2_en,
        act378_emp_v2_bm,
        authoritative="bm",
        amends_en_id="ACT-378-EMP-EXEMPT-V1",
        amends_bm_id="ACT-378-EMP-EXEMPT-V1-BM",
    )

    act378_foreign_8_en = StatutoryNode(
        node_id="ACT-378-FOREIGN-RES-8PCT-V1",
        act_name="Stamp Act 1949",
        act_number="Act 378",
        section_code="FIRST-SCHED-ITEM-32AB",
        parent_node_id="ACT-378-ACT",
        version=1,
        language="en",
        text=(
            "First Schedule Item 32AB (Foreign Residential Property Transfer Stamp Duty - Act 378, effective 1 January 2026): "
            "Instruments of transfer for residential property acquired by non-citizens or foreign companies "
            "shall bear a flat 8% ad valorem stamp duty rate."
        ),
        valid_from=date(2026, 1, 1),
        gazette_date=date(2025, 12, 31),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Tax Measures Act 2025 / Act 378",
        regime_code="ACT_378",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT378-FOREIGN-RES-8PCT",
                regime_id="ACT_378",
                modality="OBLIGATION",
                metric_key="foreign_residential_transfer_stamp_duty_pct",
                operator="==",
                threshold_value=8.0,
                unit="percent",
                description="8% ad valorem stamp duty tier on foreign residential property transfers effective 2026-01-01.",
            )
        ],
    )
    act378_foreign_8_bm = StatutoryNode(
        node_id="ACT-378-FOREIGN-RES-8PCT-V1-BM",
        act_name="Akta Setem 1949",
        act_number="Act 378",
        section_code="FIRST-SCHED-ITEM-32AB",
        parent_node_id="ACT-378-ACT",
        version=1,
        language="bm",
        text=(
            "Jadual Pertama Butiran 32AB (Duti Setem Pindah Milik Hartanah Kediaman Warga Asing - Akta 378, berkuat kuasa 1 Januari 2026): "
            "Surat cara pindah milik harta tanah kediaman oleh bukan warganegara atau syarikat asing "
            "hendaklah dikenakan kadar duti setem ad valorem sebanyak 8%."
        ),
        valid_from=date(2026, 1, 1),
        gazette_date=date(2025, 12, 31),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta Langkah Cukai 2025 / Akta 378",
        regime_code="ACT_378",
        deontic_constraints=act378_foreign_8_en.deontic_constraints,
    )
    _add_bilingual_pair(
        store, act378_foreign_8_en, act378_foreign_8_bm, authoritative="bm"
    )

    # 2. Income Tax Act 1967 [Act 53] s. 82C & s. 120(1)(d) — LHDN MyInvois
    act53_act = StatutoryNode(
        node_id="ACT-53-ACT",
        act_name="Income Tax Act 1967",
        act_number="Act 53",
        section_code="ACT-53",
        hierarchy_level=HierarchyLevel.ACT,
        text="Income Tax Act 1967 [Act 53]: Principal Malaysian income tax legislation governing LHDN MyInvois e-Invoicing under s. 82C and offences under s. 120(1)(d).",
        valid_from=date(1967, 9, 28),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 53",
        regime_code="ACT_53",
    )
    store.upsert_node(act53_act)

    act53_s82c_en = StatutoryNode(
        node_id="ACT-53-SEC-82C-P1-V1",
        act_name="Income Tax Act 1967",
        act_number="Act 53",
        section_code="SEC-82C",
        parent_node_id="ACT-53-ACT",
        version=1,
        language="en",
        text=(
            "Section 82C (LHDN MyInvois Electronic Invoice Validation, 72-Hour Cancellation & Self-Billed Imports - Act 53, eff. 2024-08-01): "
            "A person shall issue an electronic invoice validated with a Unique Identifier Number (UIN) via MyInvois, "
            "complete any buyer rejection or supplier cancellation within 72 hours of validation, and issue a "
            "self-billed e-invoice for cross-border foreign supplier imports."
        ),
        valid_from=date(2024, 8, 1),
        gazette_date=date(2023, 12, 29),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 53 s. 82C / LHDN MyInvois Guideline",
        regime_code="ACT_53",
        carve_out_metadata={
            "phased_commencement": {
                "phase_1": "2024-08-01",
                "phase_2": "2025-01-01",
                "phase_3": "2025-07-01",
                "phase_4": "2026-01-01",
            }
        },
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT53-UIN-VALID",
                regime_id="ACT_53",
                modality="OBLIGATION",
                metric_key="myinvois_uin_validation_required",
                operator="==",
                threshold_value=True,
                description="Real-time LHDN MyInvois UIN validation and TIN/SST/UBL cooperation required under Act 53 s. 82C.",
            ),
            DeonticConstraint(
                constraint_id="DC-ACT53-72H-CANCEL",
                regime_id="ACT_53",
                modality="OBLIGATION",
                metric_key="myinvois_cancellation_rejection_max_hours",
                operator="<=",
                threshold_value=72.0,
                unit="hours",
                recipient="LHDN_MYINVOIS",
                notice_stage="CANCELLATION_OR_REJECTION",
                description="72-hour LHDN MyInvois buyer rejection / supplier cancellation window after UIN validation.",
            ),
            DeonticConstraint(
                constraint_id="DC-ACT53-SELF-BILLED-FOREIGN",
                regime_id="ACT_53",
                modality="OBLIGATION",
                metric_key="myinvois_self_billed_foreign_import_required",
                operator="==",
                threshold_value=True,
                description="Malaysian buyer must issue self-billed e-invoice for cross-border foreign supplier goods/services.",
            ),
        ],
    )
    act53_s82c_bm = StatutoryNode(
        node_id="ACT-53-SEC-82C-P1-V1-BM",
        act_name="Akta Cukai Pendapatan 1967",
        act_number="Act 53",
        section_code="SEC-82C",
        parent_node_id="ACT-53-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 82C (Pengesahan e-Invois MyInvois LHDN, Pembatalan 72 Jam & Invois Bil Kendiri Import - Akta 53, berkuat kuasa 1 Ogos 2024): "
            "Seseorang hendaklah mengeluarkan e-Invois yang disahkan melalui MyInvois dengan Nombor Pengenalan Unik, "
            "melaksanakan penolakan pembeli atau pembatalan pembekal dalam tempoh 72 jam selepas pengesahan, serta "
            "mengeluarkan e-Invois bil kendiri bagi import pembekal luar negara."
        ),
        valid_from=date(2024, 8, 1),
        gazette_date=date(2023, 12, 29),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 53 s. 82C / Garis Panduan MyInvois LHDN",
        regime_code="ACT_53",
        carve_out_metadata=act53_s82c_en.carve_out_metadata,
        deontic_constraints=act53_s82c_en.deontic_constraints,
    )
    _add_bilingual_pair(store, act53_s82c_en, act53_s82c_bm, authoritative="en")

    act53_10k_en = StatutoryNode(
        node_id="ACT-53-MYINVOIS-10K-V1",
        act_name="Income Tax Act 1967",
        act_number="Act 53",
        section_code="SEC-82C-CONSOL-10K",
        parent_node_id="ACT-53-ACT",
        version=1,
        language="en",
        text=(
            "Section 82C & LHDN MyInvois Mandatory Individual e-Invoice Rule (effective 1 January 2026): "
            "Suppliers shall NOT issue a consolidated e-invoice for any single transaction exceeding RM 10,000; "
            "an individual validated e-invoice must be issued for every transaction above RM 10,000."
        ),
        valid_from=date(2026, 1, 1),
        gazette_date=date(2025, 6, 5),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="LHDN MyInvois Specific Guideline (2026-01-01)",
        regime_code="ACT_53",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT53-CONSOL-10K-CAP",
                regime_id="ACT_53",
                modality="OBLIGATION",
                metric_key="myinvois_consolidated_max_single_tx_myr",
                operator="<=",
                threshold_value=10_000.0,
                unit="MYR",
                description="Consolidated e-invoices prohibited for single transactions above RM 10,000 effective 2026-01-01.",
            ),
            DeonticConstraint(
                constraint_id="DC-ACT53-NO-CONSOL-10K",
                regime_id="ACT_53",
                modality="PROHIBITION",
                metric_key="myinvois_consolidated_over_10k_prohibited",
                operator="FORBIDDEN_CLAUSE",
                threshold_value="consolidated_einvoice_single_tx_over_rm10000",
                description="Contractual billing schedules cannot mandate consolidated e-invoicing for single transactions > RM 10,000.",
            ),
        ],
    )
    act53_10k_bm = StatutoryNode(
        node_id="ACT-53-MYINVOIS-10K-V1-BM",
        act_name="Akta Cukai Pendapatan 1967",
        act_number="Act 53",
        section_code="SEC-82C-CONSOL-10K",
        parent_node_id="ACT-53-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 82C & Peraturan e-Invois Individu Wajib MyInvois LHDN (berkuat kuasa 1 Januari 2026): "
            "Pembekal tidak boleh mengeluarkan e-Invois disatukan bagi mana-mana transaksi tunggal melebihi RM 10,000; "
            "e-Invois individu yang disahkan wajib dikeluarkan bagi setiap transaksi melebihi RM 10,000."
        ),
        valid_from=date(2026, 1, 1),
        gazette_date=date(2025, 6, 5),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Garis Panduan Khusus MyInvois LHDN (2026-01-01)",
        regime_code="ACT_53",
        deontic_constraints=act53_10k_en.deontic_constraints,
    )
    _add_bilingual_pair(store, act53_10k_en, act53_10k_bm, authoritative="bm")

    act53_exempt_v1_en = StatutoryNode(
        node_id="ACT-53-MYINVOIS-EXEMPT-V1",
        act_name="Income Tax Act 1967",
        act_number="Act 53",
        section_code="SEC-82C-EXEMPT",
        parent_node_id="ACT-53-ACT",
        version=1,
        language="en",
        text=(
            "Section 82C LHDN MyInvois Micro-Enterprise Exemption (Pre-2026-08-30 Baseline): "
            "Taxpayers with annual turnover or revenue below RM 500,000 are exempt from mandatory MyInvois e-Invoicing."
        ),
        valid_from=date(2025, 1, 1),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="LHDN MyInvois Guideline (2025-01-01)",
        regime_code="ACT_53",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT53-EXEMPT-500K",
                regime_id="ACT_53",
                modality="OBLIGATION",
                metric_key="myinvois_annual_revenue_exemption_myr",
                operator="<=",
                threshold_value=500_000.0,
                unit="MYR",
                description="Initial MyInvois annual revenue exemption threshold of RM 500,000 prior to 2026-08-30.",
            )
        ],
    )
    act53_exempt_v1_bm = StatutoryNode(
        node_id="ACT-53-MYINVOIS-EXEMPT-V1-BM",
        act_name="Akta Cukai Pendapatan 1967",
        act_number="Act 53",
        section_code="SEC-82C-EXEMPT",
        parent_node_id="ACT-53-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 82C Pengecualian Perusahaan Mikro MyInvois LHDN (Asas Pra-2026-08-30): "
            "Pembayar cukai dengan perolehan atau pendapatan tahunan di bawah RM 500,000 dikecualikan daripada e-Invois MyInvois wajib."
        ),
        valid_from=date(2025, 1, 1),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Garis Panduan MyInvois LHDN (2025-01-01)",
        regime_code="ACT_53",
        deontic_constraints=act53_exempt_v1_en.deontic_constraints,
    )
    _add_bilingual_pair(
        store, act53_exempt_v1_en, act53_exempt_v1_bm, authoritative="en"
    )

    act53_exempt_v2_en = StatutoryNode(
        node_id="ACT-53-MYINVOIS-EXEMPT-V2",
        act_name="Income Tax Act 1967",
        act_number="Act 53",
        section_code="SEC-82C-EXEMPT",
        parent_node_id="ACT-53-ACT",
        version=2,
        language="en",
        text=(
            "Section 82C LHDN MyInvois Exemption Threshold Revision (effective 30 August 2026): "
            "Annual revenue exemption threshold is raised from RM 500,000 to RM 3,000,000; however, "
            "subsidiaries, related companies, or entities with a corporate shareholder/holding company "
            "whose turnover exceeds RM 3,000,000 shall NOT qualify for this exemption."
        ),
        valid_from=date(2026, 8, 30),
        gazette_date=date(2026, 8, 28),
        amendment_act_ref="LHDN MyInvois Revised Guideline (2026-08-30)",
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="LHDN MyInvois Revised Guideline (2026-08-30)",
        regime_code="ACT_53",
        carve_out_metadata={
            "previous_exemption_myr": 500_000.0,
            "new_exemption_myr": 3_000_000.0,
            "related_company_holding_carve_out": True,
            "effective_from": "2026-08-30",
        },
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT53-EXEMPT-3M",
                regime_id="ACT_53",
                modality="OBLIGATION",
                metric_key="myinvois_annual_revenue_exemption_myr",
                operator="<=",
                threshold_value=3_000_000.0,
                unit="MYR",
                description="Updated MyInvois annual revenue exemption threshold of RM 3,000,000 effective 2026-08-30.",
            ),
            DeonticConstraint(
                constraint_id="DC-ACT53-RELATED-CO-NONEXEMPT",
                regime_id="ACT_53",
                modality="OBLIGATION",
                metric_key="myinvois_related_company_non_exempt",
                operator="==",
                threshold_value=True,
                description="Related-company and holding-company carve-out: entities linked to group revenue > RM 3,000,000 remain non-exempt.",
            ),
        ],
    )
    act53_exempt_v2_bm = StatutoryNode(
        node_id="ACT-53-MYINVOIS-EXEMPT-V2-BM",
        act_name="Akta Cukai Pendapatan 1967",
        act_number="Act 53",
        section_code="SEC-82C-EXEMPT",
        parent_node_id="ACT-53-ACT",
        version=2,
        language="bm",
        text=(
            "Seksyen 82C Semakan Ambang Pengecualian MyInvois LHDN (berkuat kuasa 30 Ogos 2026): "
            "Ambang pengecualian hasil tahunan dinaikkan daripada RM 500,000 kepada RM 3,000,000; namun "
            "anak syarikat, syarikat berkaitan, atau entiti dengan syarikat pemegang yang melebihi "
            "RM 3,000,000 tidak boleh menikmati pengecualian ini."
        ),
        valid_from=date(2026, 8, 30),
        gazette_date=date(2026, 8, 28),
        amendment_act_ref="LHDN MyInvois Revised Guideline (2026-08-30)",
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Garis Panduan MyInvois Disemak (2026-08-30)",
        regime_code="ACT_53",
        carve_out_metadata=act53_exempt_v2_en.carve_out_metadata,
        deontic_constraints=act53_exempt_v2_en.deontic_constraints,
    )
    _add_bilingual_pair(
        store,
        act53_exempt_v2_en,
        act53_exempt_v2_bm,
        authoritative="bm",
        amends_en_id="ACT-53-MYINVOIS-EXEMPT-V1",
        amends_bm_id="ACT-53-MYINVOIS-EXEMPT-V1-BM",
    )

    act53_s120_en = StatutoryNode(
        node_id="ACT-53-SEC-120-1D-V1",
        act_name="Income Tax Act 1967",
        act_number="Act 53",
        section_code="SEC-120(1)(d)",
        parent_node_id="ACT-53-ACT",
        version=1,
        language="en",
        text=(
            "Section 120(1)(d) (Penalty for Failure to Issue Electronic Invoice - Act 53): "
            "Any person who without reasonable excuse fails to issue an electronic invoice under "
            "Section 82C shall be guilty of an offence and liable to a fine of not less than RM 200 "
            "and not more than RM 20,000 or imprisonment for a term not exceeding 6 months or both."
        ),
        valid_from=date(2024, 8, 1),
        gazette_date=date(2023, 12, 29),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Act 53 s. 120(1)(d)",
        regime_code="ACT_53",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-ACT53-S120-PENALTY",
                regime_id="ACT_53",
                modality="OBLIGATION",
                metric_key="myinvois_non_compliance_max_fine_myr",
                operator=">=",
                threshold_value=20_000.0,
                unit="MYR",
                description="Statutory penalty RM 200 to RM 20,000 fine and/or up to 6 months imprisonment under Act 53 s. 120(1)(d).",
            )
        ],
    )
    act53_s120_bm = StatutoryNode(
        node_id="ACT-53-SEC-120-1D-V1-BM",
        act_name="Akta Cukai Pendapatan 1967",
        act_number="Act 53",
        section_code="SEC-120(1)(d)",
        parent_node_id="ACT-53-ACT",
        version=1,
        language="bm",
        text=(
            "Seksyen 120(1)(d) (Penalti Kegagalan Mengeluarkan e-Invois - Akta 53): "
            "Mana-mana orang yang tanpa alasan munasabah gagal mengeluarkan e-Invois di bawah "
            "Seksyen 82C hendaklah didenda tidak kurang daripada RM 200 dan tidak melebihi RM 20,000 "
            "atau dipenjarakan tidak melebihi 6 bulan atau kedua-duanya."
        ),
        valid_from=date(2024, 8, 1),
        gazette_date=date(2023, 12, 29),
        authority_tier=AuthorityTier.TIER_2_PRINCIPAL_ACT,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="Akta 53 s. 120(1)(d)",
        regime_code="ACT_53",
        deontic_constraints=act53_s120_en.deontic_constraints,
    )
    _add_bilingual_pair(store, act53_s120_en, act53_s120_bm, authoritative="en")

    store.add_citation(
        "ACT-53-SEC-82C-P1-V1",
        "ACT-53-MYINVOIS-10K-V1",
        effective_date=date(2026, 1, 1),
        gazette_ref="LHDN MyInvois Specific Guideline (2026-01-01)",
    )
    store.add_citation(
        "ACT-53-SEC-82C-P1-V1",
        "ACT-53-SEC-120-1D-V1",
        effective_date=date(2024, 8, 1),
        gazette_ref="Act 53 s. 120(1)(d)",
    )

    # 3. MOSTI National Guidelines on AI Governance & Ethics (AIGE, eff. 2024-09-20)
    aige_en = StatutoryNode(
        node_id="MOSTI-AIGE-2024-PRINCIPLES-V1",
        act_name="MOSTI National Guidelines on AI Governance & Ethics (AIGE)",
        act_number="MOSTI AIGE 2024",
        section_code="AIGE-7-PRINCIPLES",
        version=1,
        language="en",
        text=(
            "MOSTI National Guidelines on AI Governance & Ethics (AIGE, issued 20 September 2024 — Voluntary Governance Framework): "
            "Public-sector and enterprise AI deployments should align with the 7 Responsible AI Principles "
            "(Fairness; Reliability, Safety and Control; Privacy and Security; Inclusiveness; Transparency; Accountability; "
            "Pursuit of Human Benefit and Happiness), maintain human-in-the-loop or human-on-the-loop oversight, "
            "preserve AI decision audit trails, and cross-comply with PDPA Act 709 s. 9 and s. 129."
        ),
        valid_from=date(2024, 9, 20),
        gazette_date=date(2024, 9, 20),
        authority_tier=AuthorityTier.TIER_5_AGENCY_CIRCULAR,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="MOSTI AIGE (2024-09-20)",
        regime_code="MOSTI_AIGE",
        carve_out_metadata={
            "is_mandatory_statute": False,
            "governance_regime": "VOLUNTARY_GUIDELINE",
            "seven_principles": [
                "Fairness",
                "Reliability, Safety and Control",
                "Privacy and Security",
                "Inclusiveness",
                "Transparency",
                "Accountability",
                "Pursuit of Human Benefit and Happiness",
            ],
        },
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-AIGE-7-PRINCIPLES",
                regime_id="MOSTI_AIGE",
                modality="VOLUNTARY_GUIDELINE",
                metric_key="aige_seven_principles_alignment",
                operator="==",
                threshold_value=True,
                description="Voluntary alignment with MOSTI AIGE 7 Responsible AI Principles.",
            ),
            DeonticConstraint(
                constraint_id="DC-AIGE-HITL",
                regime_id="MOSTI_AIGE",
                modality="VOLUNTARY_GUIDELINE",
                metric_key="aige_human_in_the_loop_controls",
                operator="==",
                threshold_value=True,
                description="Voluntary human-in-the-loop / human-on-the-loop oversight controls for high-impact AI decisions.",
            ),
            DeonticConstraint(
                constraint_id="DC-AIGE-AUDIT-TRAIL",
                regime_id="MOSTI_AIGE",
                modality="VOLUNTARY_GUIDELINE",
                metric_key="aige_ai_audit_trail_retention",
                operator="==",
                threshold_value=True,
                description="Voluntary AI decision logging and audit trail retention under MOSTI AIGE.",
            ),
        ],
    )
    aige_bm = StatutoryNode(
        node_id="MOSTI-AIGE-2024-PRINCIPLES-V1-BM",
        act_name="Garis Panduan Tadbir Urus dan Etika AI Kebangsaan MOSTI (AIGE)",
        act_number="MOSTI AIGE 2024",
        section_code="AIGE-7-PRINCIPLES",
        version=1,
        language="bm",
        text=(
            "Garis Panduan Tadbir Urus dan Etika AI Kebangsaan MOSTI (AIGE, 20 September 2024 — Rangka Kerja Tadbir Urus Sukarela): "
            "Penggunaan AI sektor awam dan perusahaan digalakkan mematuhi 7 Prinsip AI Bertanggungjawab, "
            "mengekalkan kawalan manusia dalam gelung, menyimpan jejak audit keputusan AI, serta mematuhi "
            "Akta 709 Seksyen 9 dan Seksyen 129."
        ),
        valid_from=date(2024, 9, 20),
        gazette_date=date(2024, 9, 20),
        authority_tier=AuthorityTier.TIER_5_AGENCY_CIRCULAR,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="MOSTI AIGE (2024-09-20)",
        regime_code="MOSTI_AIGE",
        carve_out_metadata=aige_en.carve_out_metadata,
        deontic_constraints=aige_en.deontic_constraints,
    )
    _add_bilingual_pair(store, aige_en, aige_bm, authoritative="en")
    store.add_citation(
        "MOSTI-AIGE-2024-PRINCIPLES-V1",
        "PDPA-2010-SEC-9-V2",
        effective_date=date(2025, 1, 1),
        gazette_ref="MOSTI AIGE -> Act 709 s. 9",
    )
    store.add_citation(
        "MOSTI-AIGE-2024-PRINCIPLES-V1",
        "PDPA-2010-SEC-129-V2",
        effective_date=date(2025, 4, 1),
        gazette_ref="MOSTI AIGE -> Act 709 s. 129",
    )

    # 4. BNM Outsourcing Policy Document + RMiT Enhancements (Crypto Key Ownership, Sub-Contractors, Audit)
    bnm_outsource_en = StatutoryNode(
        node_id="BNM-OUTSOURCING-2019-V1",
        act_name="BNM Outsourcing Policy Document & RMiT Controls",
        act_number="BNM/RH/PD 028-99",
        section_code="PARA-11.2",
        version=1,
        language="en",
        text=(
            "BNM Outsourcing Policy Document & RMiT Cloud Controls: Financial institutions shall retain "
            "exclusive cryptographic key ownership (BYOK/customer-managed keys), prohibit sub-contracting "
            "of material outsourced functions without prior written approval, and preserve unrestricted "
            "Bank Negara Malaysia and internal right-of-audit over outsourced service providers."
        ),
        valid_from=date(2019, 10, 23),
        gazette_date=date(2019, 10, 23),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="BNM/RH/PD 028-99 (Outsourcing)",
        regime_code="BNM_RMIT",
        deontic_constraints=[
            DeonticConstraint(
                constraint_id="DC-BNM-CRYPTO-KEY-OWNERSHIP",
                regime_id="BNM_RMIT",
                modality="OBLIGATION",
                metric_key="bnm_crypto_key_ownership_fi_retained",
                operator="==",
                threshold_value=True,
                description="Financial institution must retain exclusive cryptographic key ownership under BNM Outsourcing + RMiT.",
            ),
            DeonticConstraint(
                constraint_id="DC-BNM-SUBCONTRACTOR-APPROVAL",
                regime_id="BNM_RMIT",
                modality="OBLIGATION",
                metric_key="bnm_subcontractor_prior_approval_required",
                operator="==",
                threshold_value=True,
                description="Material sub-contracting requires prior written financial-institution approval under BNM Outsourcing.",
            ),
            DeonticConstraint(
                constraint_id="DC-BNM-OUTSOURCE-AUDIT",
                regime_id="BNM_RMIT",
                modality="OBLIGATION",
                metric_key="bnm_outsourcing_regulator_audit_rights",
                operator="==",
                threshold_value=True,
                description="Outsourced provider agreements must grant unrestricted BNM & internal regulator right-of-audit.",
            ),
        ],
    )
    bnm_outsource_bm = StatutoryNode(
        node_id="BNM-OUTSOURCING-2019-V1-BM",
        act_name="Dokumen Polisi Penyumberan Luar BNM & Kawalan RMiT",
        act_number="BNM/RH/PD 028-99",
        section_code="PARA-11.2",
        version=1,
        language="bm",
        text=(
            "Dokumen Polisi Penyumberan Luar BNM & Kawalan Awan RMiT: Institusi kewangan hendaklah mengekalkan "
            "pemilikan eksklusif kunci kriptografi, melarang sub-kontrak fungsi material tanpa kelulusan "
            "bertulis terdahulu, dan mengekalkan hak audit Bank Negara Malaysia tanpa sekatan."
        ),
        valid_from=date(2019, 10, 23),
        gazette_date=date(2019, 10, 23),
        authority_tier=AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION,
        territorial_scope=[TerritorialScope.ALL_MALAYSIA],
        gazette_ref="BNM/RH/PD 028-99 (Outsourcing)",
        regime_code="BNM_RMIT",
        deontic_constraints=bnm_outsource_en.deontic_constraints,
    )
    _add_bilingual_pair(store, bnm_outsource_en, bnm_outsource_bm, authoritative="en")
    store.add_citation(
        "BNM-RMIT-SEC-10-32-V1",
        "BNM-OUTSOURCING-2019-V1",
        effective_date=date(2020, 6, 19),
        gazette_ref="BNM/RH/PD 028-99",
    )
    store.add_citation(
        "BNM-OUTSOURCING-2019-V1",
        "MOSTI-AIGE-2024-PRINCIPLES-V1",
        effective_date=date(2024, 9, 20),
        gazette_ref="MOSTI AIGE (2024-09-20)",
    )

    return store
