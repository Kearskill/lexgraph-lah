from __future__ import annotations

import io
import json
import zipfile
from datetime import date

import pytest
from pydantic import ValidationError

from lexgraph_lah.graph.temporal_store import (
    InMemoryGraphBackend,
    Neo4jGraphBackend,
    TemporalGraphStore,
    create_temporal_store,
)
from lexgraph_lah.ingestion.contract_ast import (
    NullOCRAdapter,
    OCRPageResult,
    build_contract_ast,
)
from lexgraph_lah.ingestion.gazette_ingestor import (
    ingest_gazette_instrument,
    parse_gazette_json,
    parse_gazette_xml,
)
from lexgraph_lah.ingestion.gazette_ingestor import (
    main as gazette_cli_main,
)
from lexgraph_lah.middleware.pii_scrubber import ReversiblePIIVault, scrub_malaysian_pii
from lexgraph_lah.schemas.domain import ContractEdgeType, StatutoryNode


def _make_docx_with_schedule_table() -> bytes:
    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
        "<w:p><w:r><w:t>SEC-5.1 Security &amp; Schedule Incorporation: Subject to Clause 8.1, "
        "Vendor shall comply with Jadual 1 and this clause shall survive termination.</w:t></w:r></w:p>"
        "<w:p><w:r><w:t>SEC-8.1 Confidentiality &amp; Survival: Tertakluk kepada Klausa 5.1, "
        "obligations kekal berkuat kuasa selepas penamatan.</w:t></w:r></w:p>"
        "<w:p><w:r><w:t>Jadual 1: Lampiran SLA &amp; Bayaran</w:t></w:r></w:p>"
        "<w:tbl>"
        "<w:tr><w:tc><w:p><w:r><w:t>Metric</w:t></w:r></w:p></w:tc>"
        "<w:tc><w:p><w:r><w:t>SLA Window</w:t></w:r></w:p></w:tc></w:tr>"
        "<w:tr><w:tc><w:p><w:r><w:t>NACSA Initial Notice</w:t></w:r></w:p></w:tc>"
        "<w:tc><w:p><w:r><w:t>6 hours</w:t></w:r></w:p></w:tc></w:tr>"
        "<w:tr><w:tc><w:p><w:r><w:t>Vendor Bank Account</w:t></w:r></w:p></w:tc>"
        "<w:tc><w:p><w:r><w:t>Maybank Account: 514011223344</w:t></w:r></w:p></w:tc></w:tr>"
        "</w:tbl>"
        "</w:body></w:document>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("word/document.xml", doc_xml.encode("utf-8"))
    return buf.getvalue()


def _make_scanned_image_only_pdf() -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /XObject /Subtype /Image /Width 100 /Height 100 >>\n"
        b"stream\n\xff\xd8\xff\xe0FAKEJPEGIMAGE\nendstream\nendobj\n%%EOF\n"
    )


def test_neo4j_graph_backend_execution_and_dual_backend_factory():
    """
    Verifies dual-backend TemporalGraphStore: zero-dependency memory default AND
    Neo4jGraphBackend parameterized Cypher execution on upsert/repeal/edge/PIT query.
    """
    mem_store = create_temporal_store("memory", seed_defaults=False)
    assert isinstance(mem_store.backend, InMemoryGraphBackend)

    executed: list[tuple[str, dict]] = []

    def _fake_executor(query: str, params: dict) -> list[dict]:
        executed.append((query, params))
        return [{"node_id": params.get("node_id")}]

    neo_backend = Neo4jGraphBackend(
        uri="bolt://localhost:7687",
        user="neo4j",
        password="secret",
        executor=_fake_executor,
    )
    neo_store = TemporalGraphStore(backend=neo_backend)
    n1 = StatutoryNode(
        node_id="NEO-ACT-SEC-1-V1",
        act_name="Neo Test Act",
        act_number="Act 999",
        section_code="SEC-1",
        text="Section 1: Original test rule.",
        valid_from=date(2024, 1, 1),
    )
    n2 = StatutoryNode(
        node_id="NEO-ACT-SEC-1-V2",
        act_name="Neo Test Act",
        act_number="Act 999",
        section_code="SEC-1",
        version=2,
        text="Section 1: Amended test rule.",
        valid_from=date(2025, 6, 1),
    )
    neo_store.upsert_node(n1)
    neo_store.upsert_node(n2, amends_node_id="NEO-ACT-SEC-1-V1")
    neo_store.add_citation("NEO-ACT-SEC-1-V2", "NEO-ACT-SEC-1-V1", date(2025, 6, 1))
    rows = neo_store.query_point_in_time_from_backend(as_of_date=date(2026, 1, 1))

    assert neo_backend.health_check() is True
    assert len(rows) == 1
    assert any("MERGE (n:StatutoryNode {node_id: $node_id})" in q for q, _ in executed)
    assert any("MERGE (prev)-[r:AMENDED_BY]->(n)" in q for q, _ in executed)
    assert any("MERGE (src)-[r:CITES]->(dst)" in q for q, _ in executed)
    assert any("WHERE s.valid_from <= date($as_of_date)" in q for q, _ in executed)

    # Factory with injected backend populates and syncs default Malaysian corpus
    seeded_neo = create_temporal_store(
        "neo4j",
        backend=Neo4jGraphBackend(executor=_fake_executor),
        seed_defaults=True,
    )
    assert "PDPA-2010-SEC-9-V2" in seeded_neo.nodes
    assert len(executed) > len(seeded_neo.nodes)


def test_gazette_ingestor_json_xml_validation_and_idempotency(tmp_path):
    """
    Verifies structured JSON & XML gazette schema validation, error rejection,
    idempotent re-ingestion, and CLI entrypoint.
    """
    json_payload = {
        "gazette_ref": "P.U. (A) 900/2026",
        "act_name": "Cyber Security (Mock Test) Regulations 2026",
        "act_number": "P.U. (A) 900/2026",
        "gazette_date": "2026-04-01",
        "effective_from": "2026-04-15",
        "regime_code": "ACT_854",
        "provisions": [
            {
                "node_id": "PUA-900-2026-REG-1",
                "section_code": "REG-1",
                "text": "Regulation 1: NCII entities shall maintain 24-hour SOC escalation.",
                "language": "en",
                "deontic_constraints": [
                    {
                        "constraint_id": "DC-900-24H",
                        "regime_id": "ACT_854",
                        "modality": "OBLIGATION",
                        "metric_key": "incident_notice_max_hours",
                        "operator": "<=",
                        "threshold_value": 24.0,
                        "unit": "hours",
                    }
                ],
            }
        ],
    }
    parsed_json = parse_gazette_json(json.dumps(json_payload))
    store = TemporalGraphStore()
    res1 = ingest_gazette_instrument(parsed_json, store=store)
    assert res1.inserted_node_ids == ["PUA-900-2026-REG-1"]
    assert res1.skipped_unchanged_node_ids == []

    # Idempotent second pass skips unchanged node and adds 0 duplicate edges
    res2 = ingest_gazette_instrument(parsed_json, store=store)
    assert res2.inserted_node_ids == []
    assert res2.skipped_unchanged_node_ids == ["PUA-900-2026-REG-1"]
    assert res2.edges_recorded == 0

    xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
    <gazette_instrument>
      <gazette_ref>P.U. (B) 901/2026</gazette_ref>
      <act_name>Notification of Commencement 2026</act_name>
      <act_number>P.U. (B) 901/2026</act_number>
      <gazette_date>2026-05-01</gazette_date>
      <effective_from>2026-05-10</effective_from>
      <regime_code>ACT_709</regime_code>
      <provisions>
        <provision>
          <node_id>PUB-901-2026-APPT</node_id>
          <section_code>APPT-1</section_code>
          <text>Commencement appointed on 10 May 2026.</text>
          <language>en</language>
        </provision>
      </provisions>
    </gazette_instrument>
    """
    parsed_xml = parse_gazette_xml(xml_payload)
    res_xml = ingest_gazette_instrument(parsed_xml, store=store)
    assert res_xml.inserted_node_ids == ["PUB-901-2026-APPT"]

    # Invalid gazette_ref raises ValidationError
    bad_payload = dict(json_payload, gazette_ref="INVALID-REF-XYZ")
    with pytest.raises(ValidationError):
        parse_gazette_json(json.dumps(bad_payload))

    # CLI execution smoke check
    json_file = tmp_path / "pua900.json"
    json_file.write_text(json.dumps(json_payload), encoding="utf-8")
    assert gazette_cli_main(["--input", str(json_file), "--backend", "memory"]) == 0


def test_ooxml_table_ast_new_edges_and_scanned_pdf_ocr_fallback():
    """
    Verifies:
      1. `<w:tbl>` schedules (`Jadual` / `Lampiran`) parsed as structured `SCHEDULE` nodes with `table_rows`.
      2. `SUBJECT_TO`, `INCORPORATES_SCHEDULE`, and `SURVIVES_TERMINATION` edges.
      3. Low-text scanned PDF triggers safe deterministic abstention metadata when `OCR_PROVIDER=none`,
         and recovers clauses when a pluggable OCR adapter supplies page text.
    """
    docx_bytes = _make_docx_with_schedule_table()
    ast_docx, vault = build_contract_ast(
        "AST-TBL-01", file_bytes=docx_bytes, filename="schedule_contract.docx"
    )
    sched_nodes = [c for c in ast_docx.clauses if c.section_type == "SCHEDULE"]
    assert len(sched_nodes) == 1
    sched = sched_nodes[0]
    assert sched.clause_id == "SCHED-JADUAL-1"
    assert len(sched.table_rows) == 3
    assert sched.table_rows[1] == ["NACSA Initial Notice", "6 hours"]
    # Bank account inside table cell was scrubbed to [BANK_MY_01]
    assert "514011223344" not in sched.text
    assert "[BANK_MY_01]" in sched.text
    assert "514011223344" in vault.rehydrate(sched.text)

    edge_types = {e.edge_type for e in ast_docx.edges}
    assert {
        ContractEdgeType.SUBJECT_TO,
        ContractEdgeType.INCORPORATES_SCHEDULE,
        ContractEdgeType.SURVIVES_TERMINATION,
    } <= edge_types

    # Scanned image-only PDF with OCR_PROVIDER=none -> deterministic abstention metadata
    scanned_pdf = _make_scanned_image_only_pdf()
    ast_none, _ = build_contract_ast(
        "SCAN-PDF-NONE",
        file_bytes=scanned_pdf,
        filename="scanned.pdf",
        ocr_adapter=NullOCRAdapter(),
    )
    assert ast_none.requires_ocr_abstention is True
    assert ast_none.ocr_metadata is not None
    assert ast_none.ocr_metadata["provider"] == "none"
    assert ast_none.ocr_metadata["abstention_recommended"] is True

    # Pluggable OCR adapter recovers scanned text into clauses
    class _FakeOCRAdapter:
        provider_name = "tesseract"

        def extract_pages(
            self, pdf_bytes: bytes, page_numbers: list[int]
        ) -> list[OCRPageResult]:
            return [
                OCRPageResult(
                    page_number=pno,
                    text="SEC-1.1 Scanned Clause: Vendor shall notify NACSA within 6 hours.",
                    provider="tesseract",
                    confidence=0.92,
                    requires_ocr=True,
                )
                for pno in page_numbers
            ]

    ast_ocr, _ = build_contract_ast(
        "SCAN-PDF-OCR",
        file_bytes=scanned_pdf,
        filename="scanned.pdf",
        ocr_adapter=_FakeOCRAdapter(),
    )
    assert ast_ocr.requires_ocr_abstention is False
    assert ast_ocr.ocr_metadata is not None
    assert ast_ocr.ocr_metadata["ocr_applied"] is True
    assert "Vendor shall notify NACSA within 6 hours." in ast_ocr.scrubbed_text


def test_expanded_malaysian_pii_scrubber_and_50_page_latency_under_50ms():
    """
    Verifies LHDN TIN (`[TIN_MY_01]`), KWSP (`[KWSP_01]`), PERKESO (`[PERKESO_01]`),
    and Malaysian Bank/DuitNow (`[BANK_MY_01]`) masking + lossless rehydration, and
    asserts `< 50 ms` scrubbing latency on a 50-page contract fixture.
    """
    sample = (
        "Taxpayer NRIC 900101-14-5678, LHDN TIN IG12345678900 and Company TIN C25845632000, "
        "KWSP No: 12345678, EPF Member 87654321, PERKESO No: A3100123456K, "
        "Maybank Account: 514011223344, DuitNow Account: 8001234567, Tel +6012-3456789, "
        "Email finance@syarikat.my, SSM 202001012345 (1358123-K)."
    )
    vault = ReversiblePIIVault(token_style="vault")
    masked, summary = vault.scrub(sample)
    for raw_pii in (
        "900101-14-5678",
        "IG12345678900",
        "C25845632000",
        "12345678",
        "87654321",
        "A3100123456K",
        "514011223344",
        "8001234567",
        "+6012-3456789",
        "finance@syarikat.my",
        "202001012345",
    ):
        assert raw_pii not in masked
    assert "[MYKAD_01]" in masked
    assert "[TIN_MY_01]" in masked
    assert "[TIN_MY_02]" in masked
    assert "[KWSP_01]" in masked
    assert "[KWSP_02]" in masked
    assert "[PERKESO_01]" in masked
    assert "[BANK_MY_01]" in masked
    assert "[BANK_MY_02]" in masked
    assert vault.rehydrate(masked) == sample
    assert summary.scrub_latency_ms < 50.0

    # 50-page synthetic Malaysian contract fixture (~150 KB across 50 pages)
    page_block = (
        "Clause 9 Data Security & Payroll Schedule: Personal data of employees including "
        "NRIC 910202-10-4321, LHDN TIN IG56003500070, Company TIN CS20201234560, "
        "KWSP No: 11223344, PERKESO ID: F9100012345V, CIMB Account: 800123456789, "
        "Tel +6013-9876543, and Email hr@contoh.com.my shall be encrypted at rest under "
        "Section 9 of the Personal Data Protection Act 2010 [Act 709] and Act 854. "
    ) * 7
    fifty_page_contract = "\n".join(
        f"--- PAGE {p} ---\n{page_block}" for p in range(1, 51)
    )
    assert len(fifty_page_contract) > 120_000

    # Warm-up call to isolate JIT/regex cache effects, then measure full 50-page scrub
    _ = scrub_malaysian_pii("warmup 900101-14-5678")
    large_summary = scrub_malaysian_pii(fifty_page_contract)
    assert large_summary.scrub_latency_ms < 50.0
    assert large_summary.redaction_count >= 8
    assert "IG56003500070" not in large_summary.masked_text
    assert "11223344" not in large_summary.masked_text
    assert "F9100012345V" not in large_summary.masked_text
    assert "800123456789" not in large_summary.masked_text
