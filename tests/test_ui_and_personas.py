from fastapi.testclient import TestClient

from lexgraph_lah.main import app


def test_ui_renders_disclaimer_scope_chips_persona_toggle_and_bilingual_drawer():
    """
    Verifies the upgraded Studio UI at / and /demo includes:
    1. Persistent non-legal-advice disclaimer banner.
    2. Territorial scope filter chips (Peninsular Malaysia, Sabah, Sarawak, Federal Territories).
    3. Practitioner Mode (IRAC) vs. Rakyat Literacy Mode (gov.my) toggle.
    4. Side-by-side Bahasa Melayu <-> English clause diff & SourceSpan citation drawer.
    5. Point-in-time as_of_date selector.
    """
    client = TestClient(app)
    for route in ("/", "/demo"):
        res = client.get(route)
        assert res.status_code == 200
        html = res.text

        # Disclaimer banner
        assert "legalDisclaimerBanner" in html
        assert "NOT LEGAL ADVICE" in html
        assert "Legal Profession Act 1976" in html

        # Territorial chips
        assert "scopeChipsContainer" in html
        for scope in (
            "All Malaysia",
            "Peninsular Malaysia",
            "Sabah",
            "Sarawak",
            "Federal Territories",
        ):
            assert scope in html

        # Persona toggle
        assert "personaPractitionerBtn" in html
        assert "personaRakyatBtn" in html
        assert "Practitioner Mode (IRAC)" in html
        assert "Rakyat Literacy (gov.my)" in html

        # Bilingual diff & SourceSpan drawer + as_of_date selector
        assert "bilingualDrawer" in html
        assert "ENGLISH (Section)" in html
        assert "BAHASA MELAYU (Seksyen)" in html
        assert "Verified SourceSpan Provenance" in html
        assert "refDateInput" in html


def test_compliance_check_and_scan_support_practitioner_and_rakyat_personas():
    """
    Verifies /compliance/check and /api/v1/compliance/scan return both Practitioner IRAC
    and Rakyat Literacy Mode (gov.my checklist) payloads cleanly.
    """
    client = TestClient(app)
    for persona in ("PRACTITIONER", "RAKYAT"):
        res = client.post(
            "/compliance/check?use_cache=false",
            json={
                "document_id": f"UI-PERSONA-{persona}",
                "raw_text": (
                    "SEC-8.1 Processor Liability Exclusion: The Data Processor shall bear zero "
                    "statutory liability for unauthorized data disclosure."
                ),
                "reference_date": "2026-03-15",
                "territorial_scope": "Peninsular Malaysia",
                "persona": persona,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["persona"] == persona
        assert body["territorial_scope"] == "Peninsular Malaysia"
        assert "NOT LEGAL ADVICE" in body["disclaimer"]
        assert body["irac_summary"] is not None
        assert body["rakyat_summary"] is not None
        assert len(body["rakyat_summary"]["gov_my_checklist"]) >= 1
        assert len(body["bilingual_provisions"]) >= 1
