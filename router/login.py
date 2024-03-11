from fastapi import APIRouter, Request, status
from fastapi.responses import RedirectResponse

from core.security import oauth
from core.config import settings
from service.auth import get_user_info, set_user_session


router = APIRouter()


@router.get("/login", status_code=status.HTTP_302_FOUND)
async def redirect_to_oauth2(request: Request):
    redirect_url = settings.OAUTH2_REDIRECT_URL
    return await oauth.dhub.authorize_redirect(request, redirect_url)


@router.get("/token")
async def authorize(request: Request):
    if "code" not in request.query_params or "state" not in request.query_params:
        RedirectResponse(settings.LOGIN_FAILURE_URL)
    token_info = await oauth.dhub.authorize_access_token(request)
    access_token = token_info["access_token"]
    user_info = await get_user_info(oauth.dhub, token=token_info)

    set_user_session(request.session, token_info=token_info, user_info=user_info)
    return RedirectResponse(settings.LOGIN_SUCCESS_URL)


@router.get("/sessioninfo")
def session_info(request: Request):
    return request.session.get("info")
