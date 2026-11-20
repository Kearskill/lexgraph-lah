import re

# Bidirectional Malaysian Legal Bilingual Lexicon (Bahasa Melayu <-> English)
BM_TO_EN_PHRASES: dict[str, list[str]] = {
    "akta perlindungan data peribadi": ["personal data protection act", "act 709", "pdpa"],
    "akta 709": ["act 709", "personal data protection act 2010", "pdpa"],
    "kanun keseksaan": ["penal code", "act 574"],
    "akta 574": ["act 574", "penal code", "kanun keseksaan"],
    "akta kontrak 1950": ["contracts act 1950", "act 136"],
    "akta kontrak": ["contracts act 1950", "act 136"],
    "akta 136": ["act 136", "contracts act 1950", "akta kontrak 1950"],
    "mahkamah persekutuan": ["federal court"],
    "mahkamah rayuan": ["court of appeal"],
    "mahkamah tinggi": ["high court"],
    "tanggungan berkanun": ["statutory liability", "liability"],
    "pecah kontrak": ["breach of contract", "section 75", "liquidated damages"],
    "ganti rugi": ["compensation", "damages", "reasonable compensation"],
    "penipuan": ["cheating", "fraud", "section 420"],
    "pindaan": ["amendment", "amended"],
    "akta pindaan": ["amendment act", "act a1727"],
    "pecah data": ["data breach", "personal data breach", "breach notification"],
    "kebocoran data": ["data breach", "personal data breach", "breach notification"],
    "pelanggaran data peribadi": ["personal data breach", "breach notification", "12b"],
    "notis pelanggaran": ["breach notification", "notice of breach", "72 hours"],
    "notifikasi": ["notification", "notify"],
    "pemproses data": ["data processor", "processor"],
    "pengguna data": ["data user", "data controller"],
    "subjek data": ["data subject"],
    "pegawai perlindungan data": ["data protection officer", "dpo", "12a"],
    "ppd": ["data protection officer", "dpo", "12a"],
    "prinsip keselamatan": ["security principle", "section 9", "sec-9"],
    "prinsip am": ["general principle", "section 6", "consent"],
    "prinsip notis dan pilihan": ["notice and choice principle", "section 7"],
    "prinsip penzahiran": ["disclosure principle", "section 8"],
    "prinsip penyimpanan": ["retention principle", "section 10"],
    "prinsip integriti data": ["data integrity principle", "section 11"],
    "prinsip akses": ["access principle", "section 12"],
    "persetujuan": ["consent", "authorized"],
    "penzahiran tanpa kebenaran": ["unlawful disclosure", "unauthorized disclosure", "section 130"],
    "keselamatan": ["security", "safeguards"],
    "pampasan": ["liability", "indemnity", "compensation", "damages"],
    "liabiliti": ["liability", "statutory liability"],
    "penalti": ["penalty", "penalties", "fine"],
    "denda": ["fine", "rm"],
    "penjara": ["imprisonment"],
    "seksyen": ["section", "sec"],
    "perlembagaan persekutuan": ["federal constitution", "article"],
    "perkara": ["article", "art"],
    "kesamarataan": ["equality", "equal protection", "article 8"],
    "kebebasan": ["liberty", "personal liberty", "article 5"],
    "akta kerja": ["employment act 1955", "act 265"],
    "akta 265": ["act 265", "employment act 1955"],
    "ordinan buruh sabah": ["sabah labour ordinance", "cap. 67", "sabah"],
    "ordinan buruh sarawak": ["sarawak labour ordinance", "cap. 76", "sarawak"],
    "waktu kerja": ["hours of work", "working hours", "overtime"],
    "kerja lebih masa": ["overtime", "hours of work"],
    "pekerja": ["employee", "worker"],
    "majikan": ["employer"],
    "warta": ["gazette", "p.u. (a)", "p.u. (b)"],
    "pekeliling": ["circular", "guideline", "jpdp"],
    "pesuruhjaya": ["commissioner", "jpdp"],
    "rentas sempadan": ["cross-border", "transfer outside malaysia"],
    "jam": ["hours", "hour"],
    "hari": ["days", "day"],
    "akta keselamatan siber": ["cyber security act 2024", "act 854", "ncii", "nacsa"],
    "akta 854": ["act 854", "cyber security act 2024", "p.u. (a) 220/2024"],
    "keselamatan siber": ["cyber security", "cyber incident", "act 854"],
    "insiden keselamatan siber": ["cyber security incident", "6 hours", "14 days", "ncii"],
    "infrastruktur maklumat kritikal negara": ["national critical information infrastructure", "ncii"],
    "penilaian risiko siber": ["cyber security risk assessment", "audit", "section 22"],
    "pengurusan risiko teknologi": ["risk management in technology", "rmit", "bnm"],
    "perkhidmatan awan": ["cloud", "cloud audit", "exit plan"],
    "pelan keluar": ["exit plan", "cloud", "bnm rmit"],
    "walau apa pun": ["notwithstanding", "override"],
    "akta tafsiran": ["interpretation acts", "act 388", "authoritative text", "section 63"],
    "akta 388": ["act 388", "interpretation acts", "section 63"],
    "teks sahih": ["authoritative text", "act 388", "section 63"],
    "labuan": ["labuan", "act 704", "labuan financial services"],
    "akta 704": ["act 704", "labuan financial services", "labuan"],
    "akta perdagangan elektronik": ["electronic commerce act 2006", "act 658", "electronic message"],
    "akta 658": ["act 658", "electronic commerce act 2006"],
    "mesej elektronik": ["electronic message", "electronic consent", "act 658"],
}

EN_TO_BM_PHRASES: dict[str, list[str]] = {
    "personal data protection act": ["akta perlindungan data peribadi", "akta 709"],
    "pdpa": ["akta perlindungan data peribadi", "akta 709"],
    "act 709": ["akta 709", "akta perlindungan data peribadi"],
    "cyber security act": ["akta keselamatan siber", "akta 854"],
    "act 854": ["akta 854", "akta keselamatan siber"],
    "ncii": ["infrastruktur maklumat kritikal negara", "akta 854", "seksyen 23"],
    "cyber security incident": ["insiden keselamatan siber", "6 jam", "14 hari"],
    "risk assessment": ["penilaian risiko siber", "audit"],
    "rmit": ["pengurusan risiko teknologi", "bnm"],
    "bnm rmit": ["pengurusan risiko teknologi", "bank negara malaysia", "1 jam"],
    "cloud": ["perkhidmatan awan", "audit awan", "pelan keluar"],
    "exit plan": ["pelan keluar", "perkhidmatan awan"],
    "notwithstanding": ["walau apa pun"],
    "penal code": ["kanun keseksaan", "akta 574"],
    "act 574": ["akta 574", "kanun keseksaan"],
    "contracts act 1950": ["akta kontrak 1950", "akta 136"],
    "contracts act": ["akta kontrak 1950", "akta 136"],
    "act 136": ["akta 136", "akta kontrak 1950"],
    "federal court": ["mahkamah persekutuan"],
    "court of appeal": ["mahkamah rayuan"],
    "high court": ["mahkamah tinggi"],
    "breach of contract": ["pecah kontrak", "seksyen 75"],
    "reasonable compensation": ["pampasan munasabah", "ganti rugi", "seksyen 75"],
    "liquidated damages": ["ganti rugi jumlah tertentu", "ganti rugi", "seksyen 75"],
    "cheating": ["penipuan", "seksyen 420", "kanun keseksaan"],
    "amendment": ["pindaan"],
    "data breach": ["pecah data", "kebocoran data", "pelanggaran data peribadi"],
    "breach notification": ["notis pelanggaran data", "pemberitahuan pelanggaran data", "72 jam"],
    "data processor": ["pemproses data"],
    "data user": ["pengguna data"],
    "data subject": ["subjek data"],
    "data protection officer": ["pegawai perlindungan data", "ppd"],
    "dpo": ["pegawai perlindungan data", "ppd"],
    "security principle": ["prinsip keselamatan", "seksyen 9"],
    "general principle": ["prinsip am", "seksyen 6", "persetujuan"],
    "notice and choice": ["notis dan pilihan", "seksyen 7"],
    "disclosure principle": ["prinsip penzahiran", "seksyen 8"],
    "retention principle": ["prinsip penyimpanan", "seksyen 10"],
    "data integrity": ["integriti data", "seksyen 11"],
    "access principle": ["prinsip akses", "seksyen 12"],
    "consent": ["persetujuan", "kebenaran"],
    "unlawful disclosure": ["penzahiran tanpa kebenaran", "seksyen 130"],
    "statutory liability": ["liabiliti berkanun", "tanggungan berkanun"],
    "liability": ["liabiliti", "pampasan", "tanggungan"],
    "section": ["seksyen"],
    "federal constitution": ["perlembagaan persekutuan"],
    "equality": ["kesamarataan", "sama rata"],
    "article": ["perkara"],
    "employment act": ["akta kerja 1955", "akta 265"],
    "sabah labour ordinance": ["ordinan buruh sabah", "cap. 67"],
    "sarawak labour ordinance": ["ordinan buruh sarawak", "cap. 76"],
    "overtime": ["kerja lebih masa", "waktu kerja"],
    "working hours": ["waktu kerja", "jam kerja"],
    "commissioner": ["pesuruhjaya"],
    "cross-border": ["rentas sempadan", "pemindahan data"],
    "hours": ["jam"],
    "days": ["hari"],
    "interpretation acts": ["akta tafsiran", "akta 388", "teks sahih", "seksyen 63"],
    "act 388": ["akta 388", "akta tafsiran", "seksyen 63"],
    "authoritative text": ["teks sahih", "akta 388"],
    "labuan": ["labuan", "akta 704", "perkhidmatan kewangan labuan"],
    "act 704": ["akta 704", "perkhidmatan kewangan labuan", "labuan"],
    "electronic commerce act": ["akta perdagangan elektronik 2006", "akta 658", "mesej elektronik"],
    "act 658": ["akta 658", "akta perdagangan elektronik 2006", "mesej elektronik"],
    "electronic consent": ["persetujuan elektronik", "mesej elektronik", "akta 658"],
}

STATUTE_CROSSWALK_ALIASES: dict[str, tuple[str, ...]] = {
    "act 709": (
        "act 709",
        "akta 709",
        "personal data protection act 2010",
        "akta perlindungan data peribadi 2010",
        "pdpa",
    ),
    "act 854": (
        "act 854",
        "akta 854",
        "cyber security act 2024",
        "akta keselamatan siber 2024",
        "p.u. (a) 220/2024",
        "ncii",
        "nacsa",
    ),
    "bnm rmit": (
        "bnm rmit",
        "rmit",
        "risk management in technology",
        "pengurusan risiko teknologi",
        "bnm/rh/pd 028-98",
    ),
    "act 574": (
        "act 574",
        "akta 574",
        "penal code",
        "kanun keseksaan",
    ),
    "act 136": (
        "act 136",
        "akta 136",
        "contracts act 1950",
        "akta kontrak 1950",
    ),
    "act 265": (
        "act 265",
        "akta 265",
        "employment act 1955",
        "akta kerja 1955",
    ),
    "federal constitution": (
        "federal constitution",
        "perlembagaan persekutuan",
    ),
    "act 388": (
        "act 388",
        "akta 388",
        "interpretation acts 1948 and 1967",
        "akta tafsiran 1948 dan 1967",
    ),
    "act 704": (
        "act 704",
        "akta 704",
        "labuan financial services and securities act 2010",
        "akta perkhidmatan kewangan dan sekuriti labuan 2010",
    ),
    "act 658": (
        "act 658",
        "akta 658",
        "electronic commerce act 2006",
        "akta perdagangan elektronik 2006",
    ),
}

_BM_MARKERS = {
    "akta",
    "seksyen",
    "perkara",
    "perlembagaan",
    "peribadi",
    "perlindungan",
    "pecah",
    "kebocoran",
    "pelanggaran",
    "pemproses",
    "pengguna",
    "subjek",
    "pegawai",
    "prinsip",
    "keselamatan",
    "persetujuan",
    "penzahiran",
    "penyimpanan",
    "pekerja",
    "majikan",
    "ordinan",
    "buruh",
    "warta",
    "pekeliling",
    "pesuruhjaya",
    "boleh",
    "ke",
    "kalau",
    "kena",
    "apakah",
    "bagaimana",
    "undang-undang",
    "syarat",
    "peraturan",
    "dalam",
    "untuk",
    "dengan",
    "jam",
    "hari",
    "denda",
    "penjara",
    "hukuman",
    "tiada",
    "tidak",
    "wajib",
    "rentas",
    "sempadan",
    "kanun",
    "keseksaan",
    "kontrak",
    "tanggungan",
    "berkanun",
    "ganti",
    "rugi",
    "penipuan",
    "pindaan",
    "mahkamah",
    "rayuan",
    "tinggi",
    "pampasan",
    "liabiliti",
    "di",
    "bawah",
    "tafsiran",
    "sahih",
    "kewangan",
    "luar",
    "pesisir",
}

_EN_MARKERS = {
    "act",
    "section",
    "article",
    "constitution",
    "personal",
    "protection",
    "breach",
    "notification",
    "processor",
    "user",
    "subject",
    "officer",
    "principle",
    "security",
    "consent",
    "disclosure",
    "retention",
    "integrity",
    "access",
    "employee",
    "employer",
    "ordinance",
    "labour",
    "gazette",
    "circular",
    "commissioner",
    "liability",
    "penalty",
    "fine",
    "imprisonment",
    "what",
    "how",
    "under",
    "with",
    "hours",
    "days",
    "cross-border",
    "equality",
    "overtime",
    "waive",
    "penal",
    "code",
    "contracts",
    "damages",
    "compensation",
    "cheating",
    "court",
    "interpretation",
    "authoritative",
    "offshore",
    "labuan",
}


def resolve_cross_lingual_statute_aliases(query: str) -> list[str]:
    """Resolves Malaysian statute titles across Bahasa Melayu and English aliases."""
    lowered = query.lower()
    matched: list[str] = []
    seen: set[str] = set()
    for aliases in STATUTE_CROSSWALK_ALIASES.values():
        if any(alias in lowered for alias in aliases):
            for alias in aliases:
                if alias not in seen:
                    seen.add(alias)
                    matched.append(alias)
    return matched


def detect_query_language(query: str) -> str:
    """Detects whether a Malaysian legal query is 'bm', 'en', or 'code_switched'."""
    tokens = set(re.findall(r"[a-z0-9-]+", query.lower()))
    bm_hits = len(tokens & _BM_MARKERS)
    en_hits = len(tokens & _EN_MARKERS)
    if bm_hits > 0 and en_hits > 0:
        return "code_switched"
    if bm_hits > en_hits:
        return "bm"
    return "en"


def normalize_and_expand_query(query: str) -> tuple[str, str, list[str]]:
    """
    Normalizes Malaysian BM, English, or code-switched queries and produces
    cross-lingual expansion terms so both Bahasa Melayu (Seksyen) and English (Section)
    provisions are retrieved synchronously.
    """
    clean = re.sub(r"\s+", " ", query.strip())
    lowered = clean.lower()
    detected_lang = detect_query_language(lowered)

    expanded_terms: list[str] = []
    seen: set[str] = set()

    def _add_term(term: str) -> None:
        norm = term.strip().lower()
        if norm and norm not in seen:
            seen.add(norm)
            expanded_terms.append(norm)

    # Normalize Malaysian code-switched shorthand (e.g., "Sek. 9", "Sec 12B", "s.9")
    normalized = lowered
    normalized = re.sub(r"\b(?:sek\.?|seksyen)\s*(\d+[a-z]?)\b", r"seksyen \1 section \1 sec-\1", normalized)
    normalized = re.sub(r"\b(?:sec\.?|section|s\.)\s*(\d+[a-z]?)\b", r"section \1 seksyen \1 sec-\1", normalized)
    normalized = re.sub(r"\b(?:art\.?|perkara)\s*(\d+[a-z]?)\b", r"article \1 perkara \1 art-\1", normalized)

    for alias in resolve_cross_lingual_statute_aliases(lowered):
        _add_term(alias)

    for phrase, translations in BM_TO_EN_PHRASES.items():
        if phrase in lowered:
            for t in translations:
                _add_term(t)

    for phrase, translations in EN_TO_BM_PHRASES.items():
        if phrase in lowered:
            for t in translations:
                _add_term(t)

    # Add sub-tokens from expanded phrases
    for phrase in expanded_terms:
        for tok in re.findall(r"[a-z0-9.-]+", phrase):
            if len(tok) >= 2:
                _add_term(tok)

    if expanded_terms:
        full_normalized = f"{normalized} {' '.join(expanded_terms)}".strip()
    else:
        full_normalized = normalized

    return full_normalized, detected_lang, expanded_terms
