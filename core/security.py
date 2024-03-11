from authlib.integrations.starlette_client import OAuth

from core.config import settings


oauth = OAuth()
oauth.register(
    name="dhub",
    client_id=settings.OAUTH2_CLIENT_ID,
    client_secret=settings.OAUTH2_CLIENT_SECRET,
    access_token_url=settings.OAUTH2_TOKEN_ENDPOINT,
    authorize_url=settings.OAUTH2_AUTHORIZE_ENDPOINT,
    api_base_url=settings.OAUTH2_AUTH_HOST,
)
