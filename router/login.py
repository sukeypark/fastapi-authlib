from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, status
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
    # 원래는 code랑 state가 없으면 로그인 실패응답을 해야하지만 
    # dhub oauth가 최초로 로그인 할 때 빈 응답을 보내므로(아마도 버그인 듯)
    # 다시 login 페이지로 redirect 하도록 함 
    if "code" not in request.query_params or "state" not in request.query_params:
        return RedirectResponse(request.url_for("redirect_to_oauth2"))
    #     return RedirectResponse(settings.LOGIN_FAILURE_URL)
    token_info = await oauth.dhub.authorize_access_token(request)
    access_token = token_info["access_token"]
    user_info = await get_user_info(oauth.dhub, token=token_info)

    set_user_session(request.session, token_info=token_info, user_info=user_info)
    return RedirectResponse(settings.LOGIN_SUCCESS_URL)

async def refresh_token(refresh_token, **kwargs):
    return await oauth.dhub.refresh_token(settings.OAUTH2_TOKEN_ENDPOINT, refresh_token=refresh_token)


async def get_session_info(request: Request):
    session = request.session
    info = session.get("info")
    if not info:
        raise HTTPException(status_code=401)
    token_info = info.get("token_info")
    if not token_info:
        raise HTTPException(status_code=401)
    if datetime.now().timestamp() > token_info.get("expires_in"):
        token_info = await oauth.dhub.refresh_token(**token_info).json()
        session["info"]["token_info"] = token_info
    return session["info"]


        


@router.get("/sessioninfo")
def session_info(request: Request, session_info = Depends(get_session_info)):
    return session_info
