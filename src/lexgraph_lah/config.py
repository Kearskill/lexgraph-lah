from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    gemini_api_key: str = "mock-key-for-ci"
    model_name: str = "gemini-2.5-flash"
    fast_model_name: str = "gemini-4-hydrogen"
    complex_model_name: str = "gemini-4-neon"
    usd_to_myr_rate: float = 4.40
    phoenix_collector_endpoint: str = "http://localhost:6006/v1/traces"

    input_cost_per_1m_usd: float = 0.15
    output_cost_per_1m_usd: float = 0.60
    cached_input_cost_per_1m_usd: float = 0.0375

    abstention_threshold: float = 0.78
    pii_scrub_enabled: bool = True
    attestation_db_path: str = ":memory:"

    # Phase 2: Graph persistence backend & OCR adapter
    graph_backend: str = "memory"
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_http_url: str = "http://localhost:7474"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "lexgraph-dev-password"
    neo4j_database: str = "neo4j"
    ocr_provider: str = "none"

    # Phase 3: AuthN/RBAC, rate limiting, OOXML zip-bomb limits, PII vault, Ed25519 attestation
    env: str = "development"
    auth_mode: str = "disabled"
    auth_api_keys_json: str = ""
    jwt_secret: str = ""
    jwt_public_key_pem: str = ""
    jwt_issuer: str | None = None
    jwt_audience: str | None = None
    rate_limit_enabled: bool = False
    rate_limit_rpm: int = 120
    rate_limit_window_seconds: int = 60

    docx_max_uncompressed_bytes: int = 25 * 1024 * 1024
    docx_max_compression_ratio: float = 100.0
    docx_max_entries: int = 500

    pii_vault_backend: str = "memory"
    pii_vault_db_path: str = ":memory:"
    pii_vault_redis_url: str = "redis://localhost:6379/0"
    pii_vault_ttl_seconds: int = 1800
    pii_vault_encryption_key_b64: str = ""

    attestation_backend: str = "sqlite"
    attestation_postgres_dsn: str = ""
    attestation_ed25519_private_key_pem: str = ""
    attestation_ed25519_key_id: str = "lexgraph-ed25519-v1"

    # Phase 4: Production Gemini tier aliasing, LLM retry/backoff & live BNM FX adapter
    lexgraph_model_fast: str = "gemini-2.5-flash"
    lexgraph_model_reasoning: str = "gemini-2.5-pro"
    llm_max_retries: int = 3
    llm_backoff_base_seconds: float = 0.5
    bnm_fx_enabled: bool = False
    bnm_fx_api_url: str = "https://api.bnm.gov.my/public/exchange-rate"
    bnm_fx_cache_ttl_seconds: int = 86400
    lexgraph_usd_myr_fallback: float | None = None

    # Phase 5: Firewall XML limits, durable portfolio jobs/webhooks, clause AST cache & tenant FinOps budget
    docx_max_xml_part_bytes: int = 5 * 1024 * 1024
    portfolio_job_store: str = "memory"
    portfolio_job_db_path: str = ":memory:"
    portfolio_job_postgres_dsn: str = ""
    portfolio_webhook_hmac_secret: str = "lexgraph-webhook-dev-secret"
    portfolio_webhook_timeout_seconds: float = 5.0
    portfolio_webhook_max_attempts: int = 3
    portfolio_webhook_backoff_base_seconds: float = 0.25
    clause_cache_backend: str = "memory"
    clause_cache_redis_url: str = "redis://localhost:6379/0"
    clause_cache_ttl_seconds: int = 3600
    lexgraph_tenant_monthly_budget_myr: float = 0.0
    lexgraph_budget_exceeded_policy: Literal["deterministic_fallback", "reject_429"] = (
        "deterministic_fallback"
    )

    # Phase 6: Hybrid retrieval embeddings, lease-based portfolio worker & HITL ledger
    embedding_provider: str = "subword"
    embedding_api_url: str = ""
    embedding_api_key: str = ""
    embedding_model: str = "text-embedding-004"
    embedding_dim: int = 256
    embedding_timeout_seconds: float = 10.0

    portfolio_worker_mode: Literal["embedded", "external"] = "embedded"
    portfolio_job_lease_seconds: float = 60.0
    portfolio_job_max_attempts: int = 3

    hitl_db_path: str = ":memory:"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def is_production(self) -> bool:
        return (
            self.env.strip().lower() == "production"
            or self.app_env.strip().lower() == "production"
        )


settings = Settings()
