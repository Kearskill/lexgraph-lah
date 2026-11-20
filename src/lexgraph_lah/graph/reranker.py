import math
import re
from collections import Counter

from lexgraph_lah.graph.bilingual_router import normalize_and_expand_query
from lexgraph_lah.schemas.domain import (
    AuthorityTier,
    ScoredSourceSpan,
    StatutoryNode,
    TerritorialScope,
)

AUTHORITY_WEIGHTS: dict[AuthorityTier, float] = {
    AuthorityTier.TIER_1_FEDERAL_CONSTITUTION: 1.00,
    AuthorityTier.TIER_2_ACT_OF_PARLIAMENT: 0.90,
    AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION: 0.80,
    AuthorityTier.TIER_4_FEDERAL_COURT: 0.70,
    AuthorityTier.TIER_5_COURT_OF_APPEAL: 0.60,
    AuthorityTier.TIER_6_HIGH_COURT: 0.50,
    AuthorityTier.TIER_7_SUBORDINATE_COURT: 0.40,
}

AUTHORITY_LABELS: dict[AuthorityTier, str] = {
    AuthorityTier.TIER_1_FEDERAL_CONSTITUTION: "Tier 1: Federal Constitution (Perlembagaan Persekutuan)",
    AuthorityTier.TIER_2_ACT_OF_PARLIAMENT: "Tier 2: Acts of Parliament (Akta) & State Enactments",
    AuthorityTier.TIER_3_SUBSIDIARY_LEGISLATION: "Tier 3: Subsidiary Legislation (P.U. (A), P.U. (B))",
    AuthorityTier.TIER_4_FEDERAL_COURT: "Tier 4: Federal Court (Mahkamah Persekutuan)",
    AuthorityTier.TIER_5_COURT_OF_APPEAL: "Tier 5: Court of Appeal (Mahkamah Rayuan)",
    AuthorityTier.TIER_6_HIGH_COURT: "Tier 6: High Court (Mahkamah Tinggi Malaya & Sabah/Sarawak)",
    AuthorityTier.TIER_7_SUBORDINATE_COURT: "Tier 7: Subordinate Courts & Statutory Tribunals",
}

_QUERY_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "can",
    "do",
    "does",
    "for",
    "from",
    "how",
    "if",
    "in",
    "is",
    "it",
    "law",
    "laws",
    "legal",
    "may",
    "must",
    "of",
    "on",
    "or",
    "provision",
    "provisions",
    "requirement",
    "requirements",
    "rule",
    "rules",
    "shall",
    "should",
    "statute",
    "statutory",
    "tell",
    "that",
    "the",
    "this",
    "to",
    "under",
    "what",
    "when",
    "where",
    "which",
    "who",
    "why",
    "will",
    "with",
    # BM & Manglish conversational wrapper stopwords
    "apa",
    "apakah",
    "atau",
    "bagaimana",
    "bagi",
    "boleh",
    "dalam",
    "dan",
    "dari",
    "daripada",
    "dengan",
    "di",
    "ini",
    "itu",
    "jika",
    "kalau",
    "ke",
    "kena",
    "kepada",
    "keperluan",
    "oleh",
    "pada",
    "peraturan",
    "syarat",
    "tentang",
    "terhadap",
    "terangkan",
    "tidak",
    "untuk",
    "yang",
    "lah",
    "malaysia",
}


def filter_by_territorial_scope(
    nodes: list[StatutoryNode],
    scope: TerritorialScope | str | None,
) -> list[StatutoryNode]:
    """
    Filters statutory nodes by Malaysian territorial scope to prevent
    cross-jurisdiction retrieval leakage (e.g., Peninsular Act 265 vs Sabah/Sarawak Ordinances).
    """
    if scope is None:
        return list(nodes)

    target_val = (
        scope.value if isinstance(scope, TerritorialScope) else str(scope).strip()
    )
    if not target_val or target_val == TerritorialScope.ALL_MALAYSIA.value:
        return list(nodes)

    filtered: list[StatutoryNode] = []
    for node in nodes:
        node_scopes = {s.value for s in node.territorial_scope}
        if (
            target_val in node_scopes
            or TerritorialScope.ALL_MALAYSIA.value in node_scopes
        ):
            filtered.append(node)
    return filtered


def _char_trigram_cosine(a: str, b: str) -> float:
    if len(a) < 3 or len(b) < 3:
        return 0.0
    ca = Counter(a[i : i + 3] for i in range(len(a) - 2))
    cb = Counter(b[i : i + 3] for i in range(len(b) - 2))
    shared = set(ca.keys()) & set(cb.keys())
    if not shared:
        return 0.0
    dot = sum(ca[k] * cb[k] for k in shared)
    norm_a = math.sqrt(sum(v * v for v in ca.values()))
    norm_b = math.sqrt(sum(v * v for v in cb.values()))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def _content_tokens(text: str) -> list[str]:
    raw = re.findall(r"[a-z0-9.-]+", text.lower())
    return [
        tok.strip(".-")
        for tok in raw
        if len(tok.strip(".-")) >= 2 and tok.strip(".-") not in _QUERY_STOPWORDS
    ]


def compute_hybrid_relevance_score(
    query: str,
    normalized_query: str,
    expanded_terms: list[str],
    node: StatutoryNode,
) -> float:
    """
    Deterministic hybrid lexical + bilingual + structural relevance score in [0.0, 1.0].
    Domain-matched statutory provisions score >= 0.78 while off-topic or unverified
    queries fall cleanly below the 0.78 Abstention Gate.
    """
    node_blob = " ".join(
        [
            node.node_id,
            node.act_name,
            node.act_number,
            node.section_code,
            node.gazette_ref or "",
            node.amendment_act_ref or "",
            node.court_name or "",
            node.case_citation or "",
            node.text,
        ]
    ).lower()
    node_tokens = set(_content_tokens(node_blob))
    query_tokens = _content_tokens(query)
    if not query_tokens:
        query_tokens = [
            tok for tok in re.findall(r"[a-z0-9]+", query.lower()) if len(tok) >= 2
        ]
    if not query_tokens:
        return 0.0

    # Check direct content matches AND bilingual expanded phrase/token matches
    direct_matches = sum(
        1 for tok in query_tokens if tok in node_tokens or tok in node_blob
    )
    expanded_tokens = [
        tok
        for tok in _content_tokens(" ".join(expanded_terms))
        if tok not in set(query_tokens)
    ]
    expanded_matches = sum(
        1 for tok in set(expanded_tokens) if tok in node_tokens or tok in node_blob
    )

    if direct_matches == 0 and expanded_matches == 0:
        ngram = _char_trigram_cosine(query.lower(), node_blob)
        return round(min(0.32, ngram * 0.65), 4)

    # Same-language direct coverage gets full weight; cross-lingual expanded terms
    # ensure BM queries match EN nodes and vice versa without penalizing direct matches.
    direct_coverage = direct_matches / max(1.0, float(len(query_tokens)))
    cross_coverage = min(
        1.0,
        (direct_matches + expanded_matches * 0.85) / max(1.0, float(len(query_tokens))),
    )
    concept_coverage = max(direct_coverage, cross_coverage * 0.96)

    # Phrase match boost for multi-word legal concepts
    phrase_bonus = 0.0
    for phrase in expanded_terms:
        if " " in phrase and phrase in node_blob:
            phrase_bonus = max(phrase_bonus, 0.10)

    # Structural match boost for exact Section / Article / Act / P.U. Gazette citations
    structural_bonus = 0.0
    sec_norm = (
        node.section_code.lower()
        .replace("sec-", "")
        .replace("seksyen-", "")
        .replace("art-", "")
    )
    if sec_norm and (
        f"section {sec_norm}" in normalized_query
        or f"seksyen {sec_norm}" in normalized_query
        or f"sec-{sec_norm}" in normalized_query
        or f"article {sec_norm}" in normalized_query
        or f"perkara {sec_norm}" in normalized_query
    ):
        structural_bonus += 0.14
    if (
        node.act_number.lower() in normalized_query
        or node.act_name.lower() in normalized_query
    ):
        structural_bonus += 0.08
    if node.gazette_ref and node.gazette_ref.lower() in normalized_query:
        structural_bonus += 0.10

    ngram_cos = _char_trigram_cosine(normalized_query, node_blob)
    raw_score = (
        0.80 * concept_coverage + 0.14 * ngram_cos + phrase_bonus + structural_bonus
    )
    return round(max(0.0, min(1.0, raw_score)), 4)


def rerank_statutes_and_spans(
    query: str,
    nodes: list[StatutoryNode],
    abstention_threshold: float = 0.78,
    territorial_scope: TerritorialScope | str | None = None,
) -> tuple[bool, float, str, str, list[ScoredSourceSpan]]:
    """
    Executes bilingual query normalization, territorial scope isolation,
    7-tier Malaysian legal authority reranking, and deterministic Abstention Gate check.

    Returns:
        (is_abstained, max_relevance_score, normalized_query, detected_language, ranked_spans)
    """
    normalized_query, detected_language, expanded_terms = normalize_and_expand_query(
        query
    )
    scoped_nodes = filter_by_territorial_scope(nodes, territorial_scope)

    scored_spans: list[ScoredSourceSpan] = []
    max_vector_score = 0.0

    for node in scoped_nodes:
        vec_score = compute_hybrid_relevance_score(
            query=query,
            normalized_query=normalized_query,
            expanded_terms=expanded_terms,
            node=node,
        )
        max_vector_score = max(max_vector_score, vec_score)

        if vec_score < abstention_threshold:
            continue

        auth_weight = AUTHORITY_WEIGHTS.get(node.authority_tier, 0.70)
        penalty = 0.25 if node.is_overruled else 0.0
        composite = round(
            max(0.0, min(1.0, 0.75 * vec_score + 0.25 * auth_weight - penalty)), 4
        )

        for span in node.source_spans:
            scored_spans.append(
                ScoredSourceSpan(
                    span=span,
                    node_id=node.node_id,
                    act_name=node.act_name,
                    authority_tier=node.authority_tier,
                    authority_label=AUTHORITY_LABELS.get(
                        node.authority_tier,
                        "Tier 2: Acts of Parliament (Akta) & State Enactments",
                    ),
                    territorial_scope=node.territorial_scope,
                    gazette_ref=node.gazette_ref,
                    vector_score=vec_score,
                    authority_weight=auth_weight,
                    final_score=composite,
                    bilingual_node_id=node.translation_node_id,
                )
            )

    # Sort strictly by composite final_score descending, then authority tier ascending (Tier 1 first)
    scored_spans.sort(
        key=lambda item: (
            -item.final_score,
            int(item.authority_tier),
            item.node_id,
            item.span.span_id,
        )
    )

    is_abstained = len(scored_spans) == 0
    return (
        is_abstained,
        round(max_vector_score, 4),
        normalized_query,
        detected_language,
        scored_spans,
    )
