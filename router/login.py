from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from core.security import oauth
from core.config import settings


router = APIRouter()


@router.get("/login", status_code=status.HTTP_302_FOUND)
async def redirect_to_oauth2(request: Request):
    redirect_url = settings.OAUTH2_AUTHORIZATION_REDIRECT_URL
    return await oauth.dhub.authorize_redirect(request, redirect_url)


@router.get("/token")
async def authorize(request: Request, response: Response):
    if "code" not in request.query_params:
        raise HTTPException("missing code", status_code=status.HTTP_401_UNAUTHORIZED)
    if "state" not in request.query_params:
        raise HTTPException("missing state", status_code=status.HTTP_401_UNAUTHORIZED)
    token = await oauth.dhub.authorize_access_token(request)
    token_type = token["token_type"]
    access_token = token["access_token"]
    response.set_cookie(key="access_token", value=f"{token_type} {access_token}")
    return token


@router.get("/logout")
def logout():
    return
