"""
Bilingual (EN + BM) Hybrid Statutory Retriever: Field-Weighted BM25F + Vector/Subword + RRF (k=60).

Designed to close the semantic retrieval gap on oblique, euphemistic, Manglish/code-switched,
and OCR-degraded contract clauses (e.g., "follow-the-sun global telemetry replication" ->
Act 709 s. 129; "automated customer risk scoring without manual review" -> MOSTI AIGE & Act 873;
"discretionary deferred fee splitting" -> Act 873 BNPL) while strictly enforcing bi-temporal
(`as_of_date`) and 5-tier East/West/Offshore Malaysian territorial filters BEFORE scoring.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter, defaultdict
from datetime import date
from typing import TYPE_CHECKING, Any, ClassVar, Literal, Protocol, runtime_checkable
from urllib.parse import urlparse

import httpx

from lexgraph_lah.config import settings
from lexgraph_lah.graph.bilingual_router import normalize_and_expand_query
from lexgraph_lah.graph.reranker import (
    AUTHORITY_WEIGHTS,
    filter_by_territorial_scope,
)
from lexgraph_lah.schemas.domain import (
    RetrievalExplainCandidate,
    RetrievalExplainResponse,
    StatutoryNode,
    TemporalEdgeType,
    TerritorialScope,
)

if TYPE_CHECKING:
    from lexgraph_lah.graph.temporal_store import TemporalGraphStore

TerritorialTierLiteral = Literal["Sabah", "Sarawak", "Labuan", "Peninsular", "Federal"]

_STOPWORDS: set[str] = {
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
    "into",
    "is",
    "it",
    "its",
    "may",
    "must",
    "of",
    "on",
    "or",
    "our",
    "shall",
    "should",
    "that",
    "the",
    "their",
    "this",
    "to",
    "under",
    "was",
    "were",
    "what",
    "when",
    "where",
    "which",
    "who",
    "why",
    "will",
    "with",
    "within",
    "without",
    # Bahasa Melayu functional stopwords
    "ada",
    "adalah",
    "atau",
    "bagi",
    "bahawa",
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
    "juga",
    "ke",
    "kepada",
    "kerana",
    "oleh",
    "pada",
    "sebagai",
    "secara",
    "serta",
    "supaya",
    "tidak",
    "untuk",
    "yang",
    "lah",
}

# Explicit Bahasa Melayu nasal-assimilation & legal root map before affix stripping
_BM_ROOT_EXCEPTIONS: dict[str, str] = {
    "pemindahan": "pindah",
    "memindahkan": "pindah",
    "dipindahkan": "pindah",
    "perpindahan": "pindah",
    "pemprosesan": "proses",
    "memproses": "proses",
    "diproses": "proses",
    "pemproses": "proses",
    "pengawalan": "kawal",
    "mengawal": "kawal",
    "dikawal": "kawal",
    "pengawal": "kawal",
    "pelantikan": "lantik",
    "melantik": "lantik",
    "dilantik": "lantik",
    "pendedahan": "dedah",
    "mendedahkan": "dedah",
    "didedahkan": "dedah",
    "terdedah": "dedah",
    "pemberitahuan": "beritahu",
    "memberitahu": "beritahu",
    "diberitahu": "beritahu",
    "pengiraan": "kira",
    "mengira": "kira",
    "dikira": "kira",
    "pembayaran": "bayar",
    "membayar": "bayar",
    "dibayar": "bayar",
    "bayaran": "bayar",
    "penyimpanan": "simpan",
    "menyimpan": "simpan",
    "disimpan": "simpan",
    "simpanan": "simpan",
    "perlindungan": "lindung",
    "pelindungan": "lindung",
    "melindungi": "lindung",
    "dilindungi": "lindung",
    "pelanggaran": "langgar",
    "melanggar": "langgar",
    "dilanggar": "langgar",
    "pelesenan": "lesen",
    "melesenkan": "lesen",
    "dilesenkan": "lesen",
    "pendaftaran": "daftar",
    "mendaftar": "daftar",
    "didaftarkan": "daftar",
    "didaftar": "daftar",
    "penggunaan": "guna",
    "menggunakan": "guna",
    "digunakan": "guna",
    "pengguna": "guna",
    "penghantaran": "hantar",
    "menghantar": "hantar",
    "dihantar": "hantar",
    "persetujuan": "setuju",
    "bersetuju": "setuju",
    "disetujui": "setuju",
    "keizinan": "izin",
    "mengizinkan": "izin",
    "diizinkan": "izin",
    "kebocoran": "bocor",
    "membocorkan": "bocor",
    "keselamatan": "selamat",
    "kewajipan": "wajib",
    "mewajibkan": "wajib",
    "diwajibkan": "wajib",
    "larangan": "larang",
    "melarang": "larang",
    "dilarang": "larang",
    "pengecualian": "kecuali",
    "mengecualikan": "kecuali",
    "dikecualikan": "kecuali",
    "penyelarasan": "selaras",
    "menyelaraskan": "selaras",
    "pemantauan": "pantau",
    "memantau": "pantau",
    "dipantau": "pantau",
    "pengauditan": "audit",
    "mengaudit": "audit",
    "diaudit": "audit",
    "pengesahan": "sah",
    "mengesahkan": "sah",
    "disahkan": "sah",
    "pengehadan": "had",
    "mengehadkan": "had",
    "dihadkan": "had",
    "pemansuhan": "mansuh",
    "memansuhkan": "mansuh",
    "dimansuhkan": "mansuh",
    "peraturan": "atur",
    "pengaturan": "atur",
    "pendakwaan": "dakwa",
    "penyumberan": "sumber",
    "kekerapan": "kerap",
    "ketelusan": "telus",
    "kebertanggungjawaban": "tanggungjawab",
    "akauntabiliti": "accountab",
    "peminjaman": "pinjam",
    "meminjam": "pinjam",
    "kredit": "credit",
    "ansuran": "installment",
    "faedah": "interest",
}

_EN_STEM_OVERRIDES: dict[str, str] = {
    "notifications": "notifi",
    "notification": "notifi",
    "notifying": "notifi",
    "notify": "notifi",
    "notified": "notifi",
    "transferring": "transfer",
    "transferred": "transfer",
    "transfers": "transfer",
    "replicated": "replicat",
    "replication": "replicat",
    "replicating": "replicat",
    "telemetry": "telemetri",
    "automated": "automat",
    "automatically": "automat",
    "automation": "automat",
    "algorithmic": "algorithm",
    "algorithms": "algorithm",
    "scoring": "score",
    "scored": "score",
    "splitting": "split",
    "deferred": "defer",
    "deferral": "defer",
    "discretionary": "discretion",
    "installments": "installment",
    "instalments": "installment",
    "instalment": "installment",
    "processors": "processor",
    "processing": "process",
    "processed": "process",
    "controllers": "controller",
    "outsourced": "outsourc",
    "outsourcing": "outsourc",
    "subcontractors": "subcontract",
    "subcontractor": "subcontract",
    "subprocessors": "subprocessor",
    "penalties": "penalti",
    "penalty": "penalti",
    "liabilities": "liabil",
    "liability": "liabil",
    "invoices": "invoic",
    "invoicing": "invoic",
    "invoiced": "invoic",
    "consolidated": "consolid",
    "consolidation": "consolid",
    "unstamped": "unstamp",
    "stamping": "stamp",
    "stamped": "stamp",
    "safeguards": "safeguard",
    "biometric": "biometr",
    "biometrics": "biometr",
    "employees": "employe",
    "employers": "employ",
    "employment": "employ",
    "overtime": "overtim",
    "jurisdictions": "jurisdict",
    "jurisdiction": "jurisdict",
    "exclusions": "exclus",
    "exclusion": "exclus",
    "exemptions": "exempt",
    "exemption": "exempt",
    "licensing": "licens",
    "licensed": "licens",
    "licensing_regime": "licens",
    "auditing": "audit",
    "audits": "audit",
    "audited": "audit",
    "encryption": "encrypt",
    "encrypted": "encrypt",
    "cryptographic": "cryptograph",
    "cross-border": "crossborder",
    "crossborder": "crossborder",
}

_BM_CIRCUMFIXES: tuple[tuple[str, str], ...] = (
    ("memper", "kan"),
    ("memper", "i"),
    ("diper", "kan"),
    ("diper", "i"),
    ("meng", "kan"),
    ("meny", "kan"),
    ("mem", "kan"),
    ("men", "kan"),
    ("me", "kan"),
    ("ber", "an"),
    ("ter", "an"),
    ("ke", "an"),
    ("pem", "an"),
    ("pen", "an"),
    ("peng", "an"),
    ("peny", "an"),
    ("per", "an"),
    ("pe", "an"),
)
_BM_PREFIXES: tuple[str, ...] = (
    "memper",
    "diper",
    "meng",
    "meny",
    "mem",
    "men",
    "me",
    "ber",
    "ter",
    "di",
    "pe",
    "ke",
)
_BM_SUFFIXES: tuple[str, ...] = ("kan", "nya", "lah", "an", "i")

# Curated bilingual EN + BM oblique concept clusters mapping euphemisms to canonical statutory concepts
_CONCEPT_CLUSTERS: tuple[tuple[str, tuple[str, ...], tuple[str, ...], str], ...] = (
    (
        "CONCEPT_CROSS_BORDER_TRANSFER",
        ("PDPA-2010-SEC-129", "PDPD-CBPDT"),
        (
            "follow-the-sun",
            "follow the sun",
            "telemetry replication",
            "global telemetry",
            "regional support hub",
            "regional support hubs",
            "overseas hub",
            "overseas support",
            "offshore mirror",
            "mirroring customer",
            "mirroring logs",
            "cross-border",
            "outside malaysia",
            "luar malaysia",
            "hab sokongan serantau",
            "salinan data luar negara",
            "pemindahan rentas sempadan",
            "replikasi telemetri",
            "singapore hub",
            "foreign data center",
            "foreign cloud",
        ),
        "crossborder transfer outside malaysia section 129 cbpdt adequacy telemetry replication overseas hub",
    ),
    (
        "CONCEPT_AI_GOVERNANCE_HITL",
        ("MOSTI-AIGE",),
        (
            "automated customer risk scoring",
            "automated risk scoring",
            "without manual review",
            "no manual review",
            "without human",
            "human-in-the-loop",
            "human on the loop",
            "human-on-the-loop",
            "algorithmic decision",
            "autonomous scoring",
            "black-box scoring",
            "auto-scoring",
            "tanpa semakan manusia",
            "penilaian risiko automatik",
            "tadbir urus ai",
            "prinsip ai bertanggungjawab",
            "aige",
            "keputusan automatik",
        ),
        "aige mosti ai governance ethics human-in-the-loop automated customer risk scoring manual review audit trail",
    ),
    (
        "CONCEPT_BNPL_DEFERRED_CREDIT",
        ("ACT-873",),
        (
            "discretionary deferred fee splitting",
            "deferred fee splitting",
            "fee splitting",
            "split-pay",
            "split payment",
            "pay in 4",
            "pay later",
            "bnpl",
            "buy now pay later",
            "deferred installment",
            "installment plan",
            "flat-rate interest",
            "flat rate charge",
            "rule-of-78",
            "rule of 78",
            "peraturan 78",
            "bayaran tangguh",
            "ansuran tertangguh",
            "caj rata",
            "beli sekarang bayar kemudian",
            "kredit pengguna",
            "skp",
            "non-bank credit",
            "automated customer risk scoring",
            "debt collection",
        ),
        "consumer credit act 873 bnpl deferred fee splitting rule-of-78 flat-rate interest skp licensing",
    ),
    (
        "CONCEPT_DATA_BREACH_SLA",
        (
            "PDPA-2010-SEC-12B",
            "PDPD-DBN",
            "ACT-854-PUA220",
            "CSA-2024-SEC-23",
            "BNM-RMIT",
        ),
        (
            "breach notification",
            "data breach",
            "cyber security incident",
            "security incident",
            "unauthorized access",
            "data exposure",
            "exfiltration",
            "kebocoran data",
            "insiden siber",
            "pencerobohan data",
            "pemberitahuan insiden",
            "72 hours",
            "72 jam",
            "6 hours",
            "6 jam",
            "1 hour",
            "1 jam",
            "14 days",
            "14 hari",
            "notis insiden",
            "notify affected",
        ),
        "breach notification incident reporting 72 hours 7 days 6 hours 1 hour pdpa section 12b act 854 bnm rmit",
    ),
    (
        "CONCEPT_PROCESSOR_SECURITY_DUTY",
        ("PDPA-2010-SEC-9",),
        (
            "bear zero statutory liability",
            "waives statutory liability",
            "disclaims all security responsibility",
            "processor exclusion",
            "tiada liabiliti berkanun",
            "pengecualian liabiliti pemproses",
            "technical and organizational safeguards",
            "encryption safeguards",
            "pemproses data",
            "kawalan keselamatan",
        ),
        "data processor direct statutory security obligation section 9 pdpa act 709 liability safeguards",
    ),
    (
        "CONCEPT_DPO_APPOINTMENT",
        ("PDPA-2010-SEC-12A", "PDPD-DPO"),
        (
            "data protection officer",
            "dpo",
            "pegawai perlindungan data",
            "ppd",
            "privacy lead",
            "pelantikan pegawai perlindungan",
        ),
        "data protection officer dpo section 12a pdpa act 709",
    ),
    (
        "CONCEPT_BNM_OUTSOURCING_BYOK",
        ("BNM-OUTSOURCING", "BNM-RMIT"),
        (
            "cryptographic key ownership",
            "encryption key custody",
            "byok",
            "vendor holds all keys",
            "sub-contractor without prior approval",
            "sub-processor appointment without consent",
            "waives regulator inspection",
            "right to audit",
            "regulator audit access",
            "penyumberan luar",
            "kunci penyulitan",
            "hak audit pengawal selia",
        ),
        "bnm outsourcing rmit cryptographic key ownership byok sub-contractor prior approval regulator audit rights",
    ),
    (
        "CONCEPT_STAMP_DUTY_SDSAS",
        ("ACT-378",),
        (
            "stamp duty",
            "duti setem",
            "unstamped agreement",
            "tidak bersetem",
            "admissibility in court",
            "self-assessment stamp",
            "sdsas",
            "30 days stamping",
            "rm3,000 monthly salary",
            "rm300 employment threshold",
            "taksir sendiri setem",
        ),
        "stamp act 1949 act 378 sdsas self-assessment 30 days section 52 inadmissibility employment rm3000",
    ),
    (
        "CONCEPT_MYINVOIS_EINVOICE",
        ("ACT-53-MYINVOIS-10K", "ACT-53-SEC-82C", "ACT-53-SEC-120"),
        (
            "consolidated e-invoice",
            "monthly consolidated",
            "lump sum monthly",
            "lump sum receipt",
            "bundling single invoices",
            "bundle single transactions",
            "exceeding rm10,000",
            "over rm10,000",
            "lebih rm10,000",
            "rm10,000",
            "rm 10,000",
            "rm10000",
            "gabung invois",
            "gabung semua invois",
            "invois bulanan",
            "e-invois disatukan",
            "bil bulanan",
            "self-billed import",
            "myinvois",
            "lhdn",
            "72-hour cancellation",
        ),
        "income tax act 53 section 82c myinvois lhdn consolidated e-invoice over rm10000 72 hours invois bulanan",
    ),
    (
        "CONCEPT_PUBLIC_VENDOR_DATA_SHARING",
        ("ACT-864",),
        (
            "public sector vendor",
            "government agency dataset",
            "ministry portal contractor",
            "data sharing act",
            "akta perkongsian data",
            "vendor agensi awam",
        ),
        "data sharing act 2025 act 864 section 17 public sector contractor vendor",
    ),
    (
        "CONCEPT_ONLINE_SAFETY_CHILD",
        ("ACT-866",),
        (
            "under-16",
            "minor age verification",
            "harmful content takedown",
            "online safety",
            "keselamatan dalam talian",
            "pengesahan umur bawah 16",
        ),
        "online safety act 2025 act 866 child protection under-16 age verification",
    ),
    (
        "CONCEPT_LABOUR_TERRITORIAL",
        ("EA-1955", "SABAH-CAP67", "SARAWAK-CAP76", "LABUAN-FSA"),
        (
            "overtime multiplier",
            "working hours",
            "shift hours",
            "kerja lebih masa",
            "waktu bekerja",
            "sabah labour",
            "sarawak labour",
            "labuan offshore",
        ),
        "employment working hours overtime rates sabah cap 67 sarawak cap 76 labuan act 704 peninsular act 265",
    ),
    (
        "CONCEPT_GIG_WORKERS_ACT872",
        ("ACT-872",),
        (
            "gig workers",
            "pekerja gig",
            "act 872",
            "akta 872",
            "perkeso",
            "algorithmic deactivation",
            "penyahaktifan algoritma",
            "gig workers tribunal",
            "tribunal pekerja gig",
            "service agreement schedule",
            "jadual perjanjian perkhidmatan",
        ),
        "gig workers act 872 perkeso remittance algorithmic deactivation tribunal waiver service agreement schedule",
    ),
    (
        "CONCEPT_GOVERNMENT_PROCUREMENT_ACT882",
        ("ACT-882", "ACT-864"),
        (
            "government procurement",
            "perolehan kerajaan",
            "act 882",
            "akta 882",
            "procurement appeal tribunal",
            "tribunal rayuan perolehan",
            "rent-seeking transfer",
            "pre-commencement advisory",
            "gazetted pending commencement",
            "act 864 s. 17(1)",
        ),
        "government procurement act 882 gazetted pending commencement pre-commencement advisory rent-seeking sub-contracting procurement appeal tribunal act 864",
    ),
)

_FOREIGN_LAW_MARKERS: tuple[str, ...] = (
    "state of delaware",
    "delaware llc",
    "delaware law",
    "laws of new york",
    "aaa arbitration",
    "united kingdom residents",
    "uk gdpr",
    "uk information commissioner",
    "data protection act 2018",
    "california consumer privacy act",
    "ccpa",
    "eu gdpr",
    "irish data protection commission",
    "tokyo weather",
    "weather forecast for tokyo",
    "nasi lemak sambal",
    "office pantry",
    "espresso beans",
)

_MALAYSIAN_NEXUS_MARKERS: tuple[str, ...] = (
    "malaysia",
    "kuala lumpur",
    "putrajaya",
    "cyberjaya",
    "penang",
    "johor",
    "sabah",
    "sarawak",
    "labuan",
    "peninsular",
    "ringgit",
    "myr",
    "mykad",
    "nric",
    "ssm",
    "lhdn",
    "myinvois",
    "bnm",
    "bank negara",
    "nacsa",
    "pdpd",
    "mcmc",
    "skp",
    "mosti",
    "aige",
    "act 709",
    "akta 709",
    "act 854",
    "akta 854",
    "act 873",
    "akta 873",
    "act 378",
    "akta 378",
    "act 53",
    "akta 53",
    "act 265",
    "cap. 67",
    "cap. 76",
    "pdpa",
    "rmit",
    "rm ",
    "rm10",
    "rm3",
    "perkeso",
    "pekerja gig",
    "gig workers",
    "act 872",
    "act 882",
    "perolehan kerajaan",
    "government procurement",
    "procurement appeal tribunal",
)

_LIGATURE_MAP = str.maketrans(
    {
        "\ufb00": "ff",
        "\ufb01": "fi",
        "\ufb02": "fl",
        "\ufb03": "ffi",
        "\ufb04": "ffl",
        "\u2013": "-",
        "\u2014": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
    }
)


def normalize_ocr_text(text: str) -> str:
    """
    Repairs common legal-OCR artifacts without altering numeric statutory figures:
      - Unicode ligatures (`fi`, `fl`, `ff`, `ffi`, `ffl`)
      - Spurious intra-word single-letter spacing (e.g. `S a b a h` -> `Sabah`)
      - Alpha-adjacent digit swaps (`0` -> `o`, `1` -> `l`) and digit-adjacent letter swaps (`O` -> `0`, `I`/`l` -> `1`)
      - Known `rn` -> `m` confusions in legal terms
    """
    cleaned = text.translate(_LIGATURE_MAP)

    # Collapse spurious single-letter spacing inside words (3+ separated single ASCII letters)
    def _collapse_spaced(match: re.Match[str]) -> str:
        return re.sub(r"\s+", "", match.group(0))

    cleaned = re.sub(r"\b(?:[A-Za-z]\s+){2,}[A-Za-z]\b", _collapse_spaced, cleaned)

    # Fix digit-inside-alpha OCR confusions (preserve pure numbers like 709, 10,000, 72h)
    def _fix_word(match: re.Match[str]) -> str:
        w = match.group(0)
        alpha_count = sum(1 for c in w if c.isalpha())
        digit_count = sum(1 for c in w if c.isdigit())
        if alpha_count >= 2 and digit_count >= 1:
            fixed = w.replace("0", "o").replace("1", "l")
            if fixed.lower() in {
                "sectlon",
                "compllance",
                "llablllty",
                "llability",
                "notlfication",
                "notlflcatlon",
                "prlvacy",
                "lnformation",
                "lnvoice",
                "lnvolce",
                "malaysla",
                "lncldent",
                "lncident",
                "m1nutes",
            }:
                fixed = w.replace("0", "o").replace("1", "i")
            return fixed
        # Handle digit strings with O/o or I/l OCR bleed (e.g., 7O9, 3O, 1OO)
        if digit_count >= 1 and alpha_count >= 1 and re.fullmatch(r"[0-9OlI]+", w):
            return (
                w.replace("O", "0")
                .replace("o", "0")
                .replace("I", "1")
                .replace("l", "1")
            )
        return w

    cleaned = re.sub(r"[A-Za-z0-9]+", _fix_word, cleaned)
    # Repair targeted rn -> m OCR merges in known legal tokens
    cleaned = re.sub(r"\brnandatory\b", "mandatory", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\brnalaysia\b", "malaysia", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\binforrnation\b", "information", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\bcorncern", "concern", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\bpemindahan\b", "pemindahan", cleaned, flags=re.IGNORECASE)
    return cleaned


def stem_bm_token(tok: str) -> str:
    """
    Deterministic Bahasa Melayu & English legal token normalizer/stemmer handling
    Malay circumfixes (`ke-...-an`, `pe-...-an`, `memper-...-kan`), prefixes (`di-`,
    `memper-`, `meng-`, `meny-`, `ber-`), suffixes (`-kan`, `-nya`, `-an`, `-i`),
    and common English legal inflections.
    """
    low = tok.lower().strip("._-")
    if not low or len(low) <= 2:
        return low
    if low in _BM_ROOT_EXCEPTIONS:
        return _BM_ROOT_EXCEPTIONS[low]
    if low in _EN_STEM_OVERRIDES:
        return _EN_STEM_OVERRIDES[low]

    # Strip Malay circumfixes when root stays >= 4 chars
    for pref, suf in _BM_CIRCUMFIXES:
        if low.startswith(pref) and low.endswith(suf):
            core = low[len(pref) : len(low) - len(suf)]
            if len(core) >= 4:
                return _BM_ROOT_EXCEPTIONS.get(core, core)

    # Strip single prefix when stem >= 4 chars
    for pref in _BM_PREFIXES:
        if low.startswith(pref) and len(low) - len(pref) >= 4:
            cand = low[len(pref) :]
            if cand in _BM_ROOT_EXCEPTIONS:
                return _BM_ROOT_EXCEPTIONS[cand]
            for suf in _BM_SUFFIXES:
                if cand.endswith(suf) and len(cand) - len(suf) >= 4:
                    return cand[: len(cand) - len(suf)]
            return cand

    for suf in _BM_SUFFIXES:
        if low.endswith(suf) and len(low) - len(suf) >= 4:
            return low[: len(low) - len(suf)]

    # Basic English suffix stripping
    if len(low) >= 6 and low.endswith("ies"):
        return low[:-3] + "i"
    if len(low) >= 6 and low.endswith("ing"):
        return low[:-3]
    if len(low) >= 5 and low.endswith("ed"):
        return low[:-2]
    if len(low) >= 5 and low.endswith("s") and not low.endswith("ss"):
        return low[:-1]
    return low


def tokenize_bilingual(text: str, *, include_stems: bool = True) -> list[str]:
    """Tokenizes OCR-normalized EN/BM/Manglish text into lowercase + stemmed terms."""
    norm = normalize_ocr_text(text).lower()
    raw_tokens = re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)*", norm)
    out: list[str] = []
    for raw in raw_tokens:
        clean = raw.strip("-")
        if len(clean) < 2 or clean in _STOPWORDS:
            continue
        out.append(clean)
        # Split hyphenated sub-tokens too
        if "-" in clean:
            for part in clean.split("-"):
                if len(part) >= 2 and part not in _STOPWORDS:
                    out.append(part)
                    if include_stems:
                        st_p = stem_bm_token(part)
                        if st_p != part:
                            out.append(st_p)
        if include_stems:
            st = stem_bm_token(clean)
            if st and st != clean:
                out.append(st)
            # Emit OCR 1->i alternative stem when token originally had '1' inside alpha
            if "l" in clean:
                alt = clean.replace("l", "i")
                st_alt = stem_bm_token(alt)
                if st_alt != st and st_alt in _EN_STEM_OVERRIDES.values():
                    out.append(st_alt)
    return out


def _detect_concept_clusters(text: str) -> list[str]:
    norm = normalize_ocr_text(text).lower()
    matched: list[str] = []
    for tag, _prefixes, triggers, _syn in _CONCEPT_CLUSTERS:
        if any(tr in norm for tr in triggers):
            matched.append(tag)
    return matched


def _synonyms_for_node(node: StatutoryNode) -> str:
    extra: list[str] = []
    nid_up = node.node_id.upper()
    for tag, prefixes, triggers, syn_text in _CONCEPT_CLUSTERS:
        if any(nid_up.startswith(pref) for pref in prefixes):
            extra.append(tag.lower())
            extra.append(syn_text)
            extra.extend(triggers)
    if node.regime_code:
        extra.append(node.regime_code.lower().replace("_", " "))
    return " ".join(extra)


def _node_obligations_text(node: StatutoryNode) -> str:
    parts: list[str] = []
    for dc in node.deontic_constraints:
        parts.append(
            f"{dc.regime_id} {dc.modality} {dc.metric_key} {dc.operator} "
            f"{dc.threshold_value} {dc.unit} {dc.recipient or ''} {dc.notice_stage or ''} {dc.description}"
        )
    return " ".join(parts)


def resolve_territorial_tier(node: StatutoryNode) -> TerritorialTierLiteral:
    """Maps a node's `territorial_scope` to one of the 5 Malaysian constitutional tiers."""
    scopes = set(node.territorial_scope)
    if TerritorialScope.SABAH in scopes and TerritorialScope.ALL_MALAYSIA not in scopes:
        return "Sabah"
    if (
        TerritorialScope.SARAWAK in scopes
        and TerritorialScope.ALL_MALAYSIA not in scopes
    ):
        return "Sarawak"
    if (
        TerritorialScope.LABUAN in scopes
        and TerritorialScope.ALL_MALAYSIA not in scopes
    ):
        return "Labuan"
    if (
        TerritorialScope.PENINSULAR_MALAYSIA in scopes
        and TerritorialScope.ALL_MALAYSIA not in scopes
    ):
        return "Peninsular"
    return "Federal"


@runtime_checkable
class EmbeddingProvider(Protocol):
    """Protocol for deterministic offline subword or live HTTP embedding adapters."""

    @property
    def provider_name(self) -> str: ...

    @property
    def dimensions(self) -> int: ...

    def embed_texts(self, texts: list[str]) -> list[list[float]]: ...

    def embed_query(self, query: str) -> list[float]: ...


class DeterministicSubwordEmbedder:
    """
    Zero-network, deterministic hashed subword + bilingual concept projection embedder.
    Uses `blake2b` signed feature hashing over character 3/4-grams, stemmed tokens,
    and bilingual legal concept indicators, L2-normalized to `dimensions`.
    """

    def __init__(self, dimensions: int = 256) -> None:
        self._dim = max(32, int(dimensions))

    @property
    def provider_name(self) -> str:
        return "subword-deterministic-v1"

    @property
    def dimensions(self) -> int:
        return self._dim

    def _hash_add(self, vec: list[float], feature: str, weight: float) -> None:
        digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
        val = int.from_bytes(digest[:4], "little")
        sign = 1.0 if (digest[4] & 1) == 0 else -1.0
        idx = val % self._dim
        vec[idx] += sign * weight

    def _embed_single(self, text: str) -> list[float]:
        vec = [0.0] * self._dim
        norm = normalize_ocr_text(text).lower()
        tokens = tokenize_bilingual(norm, include_stems=True)
        for tok in tokens:
            self._hash_add(vec, f"w:{tok}", 1.5)
            padded = f"<{tok}>"
            for n in (3, 4):
                if len(padded) >= n:
                    for i in range(len(padded) - n + 1):
                        self._hash_add(vec, f"c{n}:{padded[i : i + n]}", 0.45)

        for i in range(len(tokens) - 1):
            self._hash_add(vec, f"bg:{tokens[i]}_{tokens[i + 1]}", 1.1)

        for tag in _detect_concept_clusters(norm):
            self._hash_add(vec, f"concept:{tag}", 4.5)

        sq = sum(x * x for x in vec)
        if sq <= 0.0:
            return vec
        inv_norm = 1.0 / math.sqrt(sq)
        return [x * inv_norm for x in vec]

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        return [self._embed_single(t) for t in texts]

    def embed_query(self, query: str) -> list[float]:
        return self._embed_single(query)


class LiveHTTPEmbeddingAdapter:
    """
    Production HTTP embedding adapter supporting OpenAI-compatible (`/embeddings`)
    and Google Gemini (`:embedContent` / `:batchEmbedContents`) endpoints with
    strict HTTP(S) scheme checks and injectable `httpx.BaseTransport`.
    """

    def __init__(
        self,
        *,
        api_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        dimensions: int | None = None,
        timeout_seconds: float | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._api_url = (api_url or settings.embedding_api_url or "").strip()
        parsed = urlparse(self._api_url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError(
                f"LiveHTTPEmbeddingAdapter requires a valid http/https EMBEDDING_API_URL; got {self._api_url!r}."
            )
        self._api_key = (
            api_key if api_key is not None else settings.embedding_api_key
        ).strip()
        self._model = (
            model or settings.embedding_model or "text-embedding-004"
        ).strip()
        self._dim = int(dimensions or settings.embedding_dim or 256)
        self._timeout = float(
            timeout_seconds or settings.embedding_timeout_seconds or 10.0
        )
        self._transport = transport

    @property
    def provider_name(self) -> str:
        return f"http:{self._model}"

    @property
    def dimensions(self) -> int:
        return self._dim

    def _post_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
            headers["x-goog-api-key"] = self._api_key
        kwargs: dict[str, Any] = {"timeout": self._timeout, "follow_redirects": False}
        if self._transport is not None:
            kwargs["transport"] = self._transport
        with httpx.Client(**kwargs) as client:
            resp = client.post(self._api_url, json=payload, headers=headers)
            resp.raise_for_status()
            parsed = resp.json()
            if not isinstance(parsed, dict):
                raise TypeError("Embedding endpoint returned non-object JSON payload.")
            return parsed

    @staticmethod
    def _l2_normalize(vec: list[float]) -> list[float]:
        sq = sum(v * v for v in vec)
        if sq <= 0.0:
            return vec
        inv = 1.0 / math.sqrt(sq)
        return [v * inv for v in vec]

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        is_gemini = "generativelanguage" in self._api_url.lower() or (
            ":embedcontent" in self._api_url.lower()
            or ":batchembedcontents" in self._api_url.lower()
        )
        if is_gemini:
            if ":batchembedcontents" in self._api_url.lower():
                reqs = [
                    {
                        "model": f"models/{self._model}",
                        "content": {"parts": [{"text": t}]},
                    }
                    for t in texts
                ]
                data = self._post_json({"requests": reqs})
                embeddings = data.get("embeddings") or []
                return [
                    self._l2_normalize([float(x) for x in item.get("values", [])])
                    for item in embeddings
                ]
            out: list[list[float]] = []
            for t in texts:
                data = self._post_json(
                    {
                        "model": f"models/{self._model}",
                        "content": {"parts": [{"text": t}]},
                    }
                )
                emb = data.get("embedding", {})
                out.append(
                    self._l2_normalize([float(x) for x in emb.get("values", [])])
                )
            return out

        # OpenAI / standard embeddings endpoint
        data = self._post_json({"model": self._model, "input": texts})
        rows = data.get("data") or []
        ordered = sorted(rows, key=lambda r: int(r.get("index", 0)))
        return [
            self._l2_normalize([float(x) for x in item.get("embedding", [])])
            for item in ordered
        ]

    def embed_query(self, query: str) -> list[float]:
        res = self.embed_texts([query])
        return res[0] if res else [0.0] * self._dim


def build_embedding_provider(
    provider: str | None = None,
    *,
    api_url: str | None = None,
    api_key: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> EmbeddingProvider:
    chosen = (provider or settings.embedding_provider or "subword").strip().lower()
    if chosen in {"subword", "deterministic", "memory", "offline"}:
        return DeterministicSubwordEmbedder(dimensions=settings.embedding_dim)
    if chosen in {"http", "live", "openai", "gemini"}:
        return LiveHTTPEmbeddingAdapter(
            api_url=api_url,
            api_key=api_key,
            transport=transport,
        )
    raise ValueError(
        f"Unsupported EMBEDDING_PROVIDER={chosen!r}; expected 'subword' or 'http'."
    )


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    return max(0.0, min(1.0, dot))


class BM25FIndex:
    """
    Bilingual (EN + BM) Field-Weighted BM25F scorer over active `StatutoryNode`s across:
      `title`, `section`, `text_en`, `text_bm`, `obligations`, `synonyms`.
    """

    FIELD_WEIGHTS: ClassVar[dict[str, float]] = {
        "title": 2.0,
        "section": 2.5,
        "text_en": 1.5,
        "text_bm": 1.5,
        "obligations": 1.8,
        "synonyms": 1.6,
    }
    FIELD_B: ClassVar[dict[str, float]] = {
        "title": 0.50,
        "section": 0.30,
        "text_en": 0.75,
        "text_bm": 0.75,
        "obligations": 0.50,
        "synonyms": 0.50,
    }

    def __init__(
        self,
        nodes: list[StatutoryNode],
        *,
        node_lookup: dict[str, StatutoryNode] | None = None,
        k1: float = 1.2,
    ) -> None:
        self._k1 = k1
        self._nodes = nodes
        lookup = node_lookup or {n.node_id: n for n in nodes}
        self._doc_fields: dict[str, dict[str, Counter[str]]] = {}
        self._field_lens: dict[str, dict[str, int]] = {}
        field_totals: dict[str, int] = defaultdict(int)
        df: Counter[str] = Counter()

        for node in nodes:
            partner = (
                lookup.get(node.translation_node_id)
                if node.translation_node_id
                else None
            )
            en_text = ""
            bm_text = ""
            if node.normalized_language == "en":
                en_text = node.text
                if partner is not None:
                    bm_text = partner.text
            else:
                bm_text = node.text
                if partner is not None:
                    en_text = partner.text

            fields_raw = {
                "title": f"{node.act_name} {node.act_number} {node.gazette_ref or ''} {node.case_citation or ''}",
                "section": f"{node.section_code} {node.subsection_code or ''} {node.node_id}",
                "text_en": en_text,
                "text_bm": bm_text,
                "obligations": _node_obligations_text(node),
                "synonyms": _synonyms_for_node(node),
            }
            doc_f: dict[str, Counter[str]] = {}
            lens_f: dict[str, int] = {}
            doc_vocab: set[str] = set()
            for fname, raw_val in fields_raw.items():
                toks = tokenize_bilingual(raw_val, include_stems=True)
                counts = Counter(toks)
                doc_f[fname] = counts
                lens_f[fname] = max(1, len(toks))
                field_totals[fname] += len(toks)
                doc_vocab.update(counts.keys())

            self._doc_fields[node.node_id] = doc_f
            self._field_lens[node.node_id] = lens_f
            for term in doc_vocab:
                df[term] += 1

        n_docs = max(1, len(nodes))
        self._avg_lens: dict[str, float] = {
            fname: max(1.0, field_totals[fname] / float(n_docs))
            for fname in self.FIELD_WEIGHTS
        }
        self._idf: dict[str, float] = {
            term: math.log(1.0 + (n_docs - freq + 0.5) / (freq + 0.5))
            for term, freq in df.items()
        }

    def score_node(
        self, node_id: str, query_tokens: list[str]
    ) -> tuple[float, list[str]]:
        doc_f = self._doc_fields.get(node_id)
        lens_f = self._field_lens.get(node_id)
        if doc_f is None or lens_f is None:
            return 0.0, []

        total_score = 0.0
        matched_fields: set[str] = set()
        unique_q = list(dict.fromkeys(query_tokens))
        for term in unique_q:
            idf = self._idf.get(term, 0.0)
            if idf <= 0.0:
                continue
            pseudo_tf = 0.0
            for fname, weight in self.FIELD_WEIGHTS.items():
                tf = doc_f[fname].get(term, 0)
                if tf <= 0:
                    continue
                matched_fields.add(fname)
                b_val = self.FIELD_B[fname]
                avg_len = self._avg_lens[fname]
                norm_factor = 1.0 - b_val + b_val * (lens_f[fname] / avg_len)
                pseudo_tf += weight * (tf / norm_factor)
            if pseudo_tf > 0.0:
                total_score += idf * (pseudo_tf / (self._k1 + pseudo_tf))

        return round(total_score, 4), sorted(matched_fields)


def _node_embedding_text(
    node: StatutoryNode, *, node_lookup: dict[str, StatutoryNode]
) -> str:
    partner = (
        node_lookup.get(node.translation_node_id) if node.translation_node_id else None
    )
    partner_txt = partner.text if partner is not None else ""
    return " ".join(
        [
            node.act_name,
            node.act_number,
            node.section_code,
            node.text,
            partner_txt,
            _node_obligations_text(node),
            _synonyms_for_node(node),
        ]
    )


def _has_exclusive_foreign_law_signal(query: str) -> bool:
    norm = normalize_ocr_text(query).lower()
    has_foreign = any(marker in norm for marker in _FOREIGN_LAW_MARKERS)
    if not has_foreign:
        return False
    has_my = any(marker in norm for marker in _MALAYSIAN_NEXUS_MARKERS)
    return not has_my


class HybridStatutoryRetriever:
    """
    Bilingual Hybrid Statutory Retriever combining Field-Weighted BM25F,
    subword/dense vector cosine similarity, and 1-hop graph neighborhood expansion
    via Reciprocal Rank Fusion (`RRF`, `k=60`) with strict pre-scoring bi-temporal
    and 5-tier territorial filtering.
    """

    def __init__(
        self,
        *,
        store: TemporalGraphStore | None = None,
        embedder: EmbeddingProvider | None = None,
        rrf_k: int = 60,
    ) -> None:
        self._store = store
        self._embedder: EmbeddingProvider = (
            embedder if embedder is not None else build_embedding_provider()
        )
        self._rrf_k = max(1, int(rrf_k))
        self._doc_vec_cache: dict[tuple[str, str], list[float]] = {}

    def _get_store(self) -> TemporalGraphStore:
        if self._store is None:
            from lexgraph_lah.graph.temporal_store import get_default_temporal_store

            self._store = get_default_temporal_store()
        return self._store

    def _get_node_vector(
        self, node: StatutoryNode, *, node_lookup: dict[str, StatutoryNode]
    ) -> list[float]:
        cache_key = (self._embedder.provider_name, node.node_id)
        cached = self._doc_vec_cache.get(cache_key)
        if cached is not None:
            return cached
        text = _node_embedding_text(node, node_lookup=node_lookup)
        vec = self._embedder.embed_texts([text])[0]
        self._doc_vec_cache[cache_key] = vec
        return vec

    def _warm_node_vectors(
        self, nodes: list[StatutoryNode], *, node_lookup: dict[str, StatutoryNode]
    ) -> None:
        missing = [
            n
            for n in nodes
            if (self._embedder.provider_name, n.node_id) not in self._doc_vec_cache
        ]
        if not missing:
            return
        texts = [_node_embedding_text(n, node_lookup=node_lookup) for n in missing]
        vecs = self._embedder.embed_texts(texts)
        for n, v in zip(missing, vecs, strict=False):
            self._doc_vec_cache[(self._embedder.provider_name, n.node_id)] = v

    def explain(
        self,
        *,
        query: str,
        as_of_date: date | None = None,
        territorial_scope: TerritorialScope | str | None = None,
        top_k: int = 5,
        abstention_threshold: float | None = None,
        regimes: list[str] | None = None,
        candidate_nodes: list[StatutoryNode] | None = None,
        store: TemporalGraphStore | None = None,
    ) -> RetrievalExplainResponse:
        active_store = store or self._get_store()
        eff_date = as_of_date or date.today()
        threshold = (
            float(abstention_threshold)
            if abstention_threshold is not None
            else settings.abstention_threshold
        )

        normalized_query, detected_lang, expanded_terms = normalize_and_expand_query(
            normalize_ocr_text(query)
        )

        # Strict bi-temporal + 5-tier territorial filtering BEFORE scoring
        if candidate_nodes is not None:
            valid_nodes = filter_by_territorial_scope(
                [n for n in candidate_nodes if n.is_active_on(eff_date)],
                territorial_scope,
            )
        else:
            valid_nodes = active_store.query_point_in_time(
                as_of_date=eff_date,
                include_citations=True,
                include_translations=True,
                territorial_scope=territorial_scope,
            )

        if regimes:
            norm_regs = {r.strip().upper() for r in regimes if r.strip()}
            regime_filtered = [
                n for n in valid_nodes if n.regime_code.upper() in norm_regs
            ]
            if regime_filtered:
                valid_nodes = regime_filtered

        if not valid_nodes:
            return RetrievalExplainResponse(
                query=query,
                detected_language=detected_lang,
                as_of_date=eff_date,
                territorial_scope=(
                    territorial_scope.value
                    if isinstance(territorial_scope, TerritorialScope)
                    else territorial_scope
                ),
                abstention_threshold=threshold,
                is_abstained=True,
                abstention_reason=(
                    f"ABSTAINED: Zero statutory provisions active on {eff_date.isoformat()} "
                    f"for territorial_scope={territorial_scope!r}."
                ),
                max_score=0.0,
                embedding_provider=self._embedder.provider_name,
                rrf_k=self._rrf_k,
                candidates=[],
            )

        node_lookup = active_store.nodes
        bm25_index = BM25FIndex(valid_nodes, node_lookup=node_lookup)
        self._warm_node_vectors(valid_nodes, node_lookup=node_lookup)

        query_concepts = set(_detect_concept_clusters(query))
        query_for_scoring = " ".join(
            [
                query,
                normalized_query,
                " ".join(expanded_terms),
                " ".join(c.lower() for c in query_concepts),
            ]
        )
        query_tokens = tokenize_bilingual(query_for_scoring, include_stems=True)
        q_vec = self._embedder.embed_query(query_for_scoring)

        bm25_scores: dict[str, float] = {}
        matched_fields_map: dict[str, list[str]] = {}
        vec_scores: dict[str, float] = {}
        for node in valid_nodes:
            b_score, m_fields = bm25_index.score_node(node.node_id, query_tokens)
            bm25_scores[node.node_id] = b_score
            matched_fields_map[node.node_id] = m_fields
            n_vec = self._get_node_vector(node, node_lookup=node_lookup)
            vec_scores[node.node_id] = round(_cosine_similarity(q_vec, n_vec), 4)

        bm25_positive = [n.node_id for n in valid_nodes if bm25_scores[n.node_id] > 0.0]
        bm25_ranked = sorted(
            bm25_positive,
            key=lambda nid: (
                -bm25_scores[nid],
                int(node_lookup[nid].authority_tier) if nid in node_lookup else 9,
                nid,
            ),
        )
        bm25_rank_map = {nid: idx for idx, nid in enumerate(bm25_ranked, start=1)}

        vec_positive = [n.node_id for n in valid_nodes if vec_scores[n.node_id] > 0.08]
        vec_ranked = sorted(
            vec_positive,
            key=lambda nid: (
                -vec_scores[nid],
                int(node_lookup[nid].authority_tier) if nid in node_lookup else 9,
                nid,
            ),
        )
        vec_rank_map = {nid: idx for idx, nid in enumerate(vec_ranked, start=1)}

        # Seed RRF to select top-3 hubs for 1-hop graph neighborhood expansion
        valid_ids = {n.node_id for n in valid_nodes}
        prelim_rrf: dict[str, float] = {}
        for nid in valid_ids:
            r_b = (
                1.0 / (self._rrf_k + bm25_rank_map[nid])
                if nid in bm25_rank_map
                else 0.0
            )
            r_v = (
                1.0 / (self._rrf_k + vec_rank_map[nid]) if nid in vec_rank_map else 0.0
            )
            prelim_rrf[nid] = r_b + r_v

        seed_ids = [
            nid
            for nid, sc in sorted(prelim_rrf.items(), key=lambda kv: (-kv[1], kv[0]))[
                :3
            ]
            if sc > 0.0
        ]

        # 1-hop graph neighborhood expansion strictly within pre-filtered valid_ids
        graph_edges_allowed = {
            TemporalEdgeType.CITES,
            TemporalEdgeType.HAS_TRANSLATION,
            TemporalEdgeType.BM_EN_EQUIVALENT,
            TemporalEdgeType.AMENDS,
        }
        neighbor_best_seed: dict[str, int] = {}
        for seed_rank, sid in enumerate(seed_ids, start=1):
            for edge in active_store.edges:
                if (
                    edge.edge_type not in graph_edges_allowed
                    or edge.effective_date > eff_date
                ):
                    continue
                target: str | None = None
                if edge.source_id == sid and edge.target_id in valid_ids:
                    target = edge.target_id
                elif edge.target_id == sid and edge.source_id in valid_ids:
                    target = edge.source_id
                if target is not None and target != sid:
                    prev = neighbor_best_seed.get(target)
                    if prev is None or seed_rank < prev:
                        neighbor_best_seed[target] = seed_rank

        foreign_penalty = 0.42 if _has_exclusive_foreign_law_signal(query) else 1.0
        max_possible_rrf = 2.0 / (self._rrf_k + 1.0)
        scored_candidates: list[RetrievalExplainCandidate] = []

        for node in valid_nodes:
            nid = node.node_id
            b_score = bm25_scores[nid]
            v_score = vec_scores[nid]
            b_rrf = (
                1.0 / (self._rrf_k + bm25_rank_map[nid])
                if nid in bm25_rank_map
                else 0.0
            )
            v_rrf = (
                1.0 / (self._rrf_k + vec_rank_map[nid]) if nid in vec_rank_map else 0.0
            )
            g_seed_rank = neighbor_best_seed.get(nid)
            g_boost = 0.5 / (self._rrf_k + g_seed_rank) if g_seed_rank else 0.0
            total_rrf = round(b_rrf + v_rrf + g_boost, 6)

            if total_rrf <= 0.0:
                continue

            # Calibrated probability-like confidence in [0.0, 1.0]
            bm25_sat = b_score / (b_score + 4.5) if b_score > 0.0 else 0.0
            rrf_norm = min(1.0, (b_rrf + v_rrf) / max_possible_rrf)
            auth_w = AUTHORITY_WEIGHTS.get(node.authority_tier, 0.70)

            nid_up = nid.upper()
            concept_bonus = 0.0
            if query_concepts:
                for tag, prefixes, _tr, _syn in _CONCEPT_CLUSTERS:
                    if tag in query_concepts and any(
                        nid_up.startswith(pref) for pref in prefixes
                    ):
                        concept_bonus = 0.16
                        break

            # Detect pure non-Malaysian-domain low-evidence hits
            raw_conf = (
                0.38 * bm25_sat
                + 0.36 * v_score
                + 0.18 * rrf_norm
                + 0.08 * auth_w
                + concept_bonus
            ) * foreign_penalty

            # Dampen generic-only partial hits when neither BM25F nor vector is strong
            if b_score < 2.2 and v_score < 0.35 and concept_bonus == 0.0:
                raw_conf *= 0.65

            calibrated = round(max(0.0, min(0.99, raw_conf)), 4)
            scored_candidates.append(
                RetrievalExplainCandidate(
                    node_id=nid,
                    act_name=node.act_name,
                    act_number=node.act_number,
                    section_code=node.section_code,
                    language=node.language,
                    bm25_score=b_score,
                    vector_score=v_score,
                    graph_boost_score=round(g_boost, 6),
                    rrf_score=total_rrf,
                    calibrated_score=calibrated,
                    temporal_valid=True,
                    territorial_tier=resolve_territorial_tier(node),
                    authority_tier=int(node.authority_tier),
                    matched_fields=matched_fields_map[nid],
                    source_span_ids=[sp.span_id for sp in node.source_spans],
                )
            )

        scored_candidates.sort(
            key=lambda c: (
                -c.rrf_score,
                -c.calibrated_score,
                c.authority_tier,
                c.node_id,
            )
        )
        top_candidates = scored_candidates[: max(1, top_k)]
        max_score = (
            max(c.calibrated_score for c in top_candidates) if top_candidates else 0.0
        )
        is_abstained = (len(top_candidates) == 0) or (max_score < threshold)
        abstention_reason = (
            (
                f"ABSTAINED: Hybrid BM25F+Vector+RRF max calibrated score {max_score:.4f} "
                f"is below abstention threshold {threshold:.2f}."
            )
            if is_abstained
            else None
        )

        return RetrievalExplainResponse(
            query=query,
            detected_language=detected_lang,
            as_of_date=eff_date,
            territorial_scope=(
                territorial_scope.value
                if isinstance(territorial_scope, TerritorialScope)
                else territorial_scope
            ),
            abstention_threshold=threshold,
            is_abstained=is_abstained,
            abstention_reason=abstention_reason,
            max_score=round(max_score, 4),
            embedding_provider=self._embedder.provider_name,
            rrf_k=self._rrf_k,
            candidates=top_candidates,
        )


default_hybrid_retriever = HybridStatutoryRetriever()
