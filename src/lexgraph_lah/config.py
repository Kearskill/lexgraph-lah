from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    gemini_api_key: str = "mock-key-for-ci"
    model_name: str = "gemini-2.5-flash"
    usd_to_myr_rate: float = 4.40
    phoenix_collector_endpoint: str = "http://localhost:6006/v1/traces"

    input_cost_per_1m_usd: float = 0.15
    output_cost_per_1m_usd: float = 0.60

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
