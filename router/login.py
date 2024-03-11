from datetime import datetime
from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import RedirectResponse

from core.security import oauth
from core.config import settings
from service.auth import (
    get_session_info,
    get_sessioned_token_info,
    get_sessioned_user_info,
    parse_token,
    set_user_session,
)


router = APIRouter()


@router.get("/login", status_code=status.HTTP_302_FOUND)
async def redirect_to_oauth2(request: Request):
    redirect_url = settings.OAUTH2_REDIRECT_URL
    return await oauth.dhub.authorize_redirect(request, redirect_url)


# 유효기간이 지난 access_token을 session에 저장하는 endpoint
# /test 요청 후 /sessioninfo 호출하여
# refresh_token으로 token을 갱신하는 것을 확인할 수 있음
@router.get("/test")
def set_test_session(request: Request):
    request.session["info"] = {
        "user_info": {
            "user_id": "user01",
            "nickname": "user",
            "name": "user",
            "email": "user@example.com",
            "phone": "01033335555",
            "role": "Dhub_User",
        },
        "token_info": {
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoidXNlclN5c3RlbSIsInVzZXJJZCI6InVzZXIwMSIsIm5pY2tuYW1lIjoidXNlciIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSIsInJvbGUiOiJEaHViX1VzZXIiLCJpYXQiOjE3MTAxMjcxMTYsImV4cCI6MTcxMDEzMDcxNiwiYXVkIjoiM2VSb2Zocmw2d1BXYXVYMnUwR1QiLCJpc3MiOiJ1cm46ZGF0YWh1YjpjaXR5aHViOnNlY3VyaXR5In0.KcPPTREvxtbl0fIML3o6e--1YsPtbAl-eY30gUDd8-JqK6Gs5vBjnQDS5hT9gznqHGUGDDrc9AVFUpFLPhVSqZLyo6gAl-XqJwZNhcB73iGOu-I6WA3xcEi-ULWUTaNMqm074x0gqkQzIBICLTQ8w9z2zft5v2ibTm7ZtQ6y4Q80D1RGix-fTjUwBMrEvesscOj9KdKwVJzYQcSd2AmK9YGQo_kgsGKlLO3WINjl73DYXXqa7F-kllfnbiHTlM4ZIdXYzrcWGRNAdzjD09xCaa2Rp3iY-Ghb8YRCbrij6BgnqMZnpNt1wTbL0a3vHSo0P-3oA-Djf_OI8ACWeJoTiw",
            "refresh_token": "lZCoy8SGVUf5z2mWKk4LjNKX5hgXWmcL4ii5Zoyf74IkkyHSBCOrPMqCKKSzdV3yUkdaE85J2V0DDjUCdtR5944O0YVcqMWzBIcDvW0m1Xs0CwSN3v3fVcvid99FWjZO",
            "expires_in": 1710130716,
            "refresh_expires_in": 1711855116,
            "token_type": "Bearer",
        },
    }
    return request.session["info"]


@router.get("/token")
async def authorize(request: Request):
    # 원래는 code랑 state가 없으면 로그인 실패응답을 해야하지만
    # dhub oauth가 최초로 로그인 할 때 state와 code를 보내지 않으므로(아마도 버그인 듯)
    # 다시 login 페이지로 redirect 하도록 함
    if "code" not in request.query_params or "state" not in request.query_params:
        return RedirectResponse(request.url_for("redirect_to_oauth2"))
    #     return RedirectResponse(settings.LOGIN_FAILURE_URL)
    token_info = await oauth.dhub.authorize_access_token(request)
    user_info = await parse_token(oauth.dhub, token_info)

    set_user_session(request.session, token_info=token_info, user_info=user_info)
    return RedirectResponse(settings.LOGIN_SUCCESS_URL)


@router.get("/sessioninfo")
async def session_info(request: Request):
    return await get_session_info(request)


@router.get("/logout")
async def logout(
    request: Request,
    user_info=Depends(get_sessioned_user_info),
    token=Depends(get_sessioned_token_info),
):
    resp = await oauth.dhub.post(
        f"{settings.OAUTH2_AUTH_HOST}/security/logout",
        data={"userId": user_info["user_id"]},
        token=token,
    )
    request.session.clear()
    return resp.json()
