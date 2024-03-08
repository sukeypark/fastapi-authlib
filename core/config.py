from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyHttpUrl


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        case_sensitive=True, env_file=(".env", ".env_local"), extra="ignore"
    )

    OAUTH2_CLIENT_ID: str
    OAUTH2_CLIENT_SECRET: str
    OAUTH2_AUTH_HOST: str
    OAUTH2_REDIRECT_URL: str
    OAUTH2_AUTHORIZE_ENDPOINT: str
    OAUTH2_TOKEN_ENDPOINT: str
    OAUTH2_TOKEN_REVOKE_ENDPOINT: str


settings = Settings()
