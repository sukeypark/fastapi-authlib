from datetime import datetime
import time
from jose import jwt
from fastapi import HTTPException, Request
from starlette import status

from core.security import oauth


async def refresh_access_token(request):
    if (
        "info" not in request.session
        or "token_info" not in request.session["info"]
        or "refresh_token" not in request.session["info"]["token_info"]
    ):
        raise HTTPException("No session", status_code=status.HTTP_401_UNAUTHORIZED)
    refresh_token = request.session["info"]["token_info"]["refresh_token"]
    # authlib oauth client(이 코드에서는 "oauth.dhub" <- httpx client임)를 이용하여
    # api요청을 하면(예시: await oaht.dhub.get) 자동으로 refresh하는 로직이 되어 있음
    # 그러므로 dhub api를 이용하는 부분은 매번 토큰 만료 여부 체크하여 수동으로 refresh를 하지 않아도 됨.
    return await oauth.dhub.fetch_access_token(
        refresh_token=refresh_token, grant_type="refresh_token"
    )


async def get_session_info(request: Request):
    session = request.session
    info = session.get("info")
    if not info:
        raise HTTPException(status_code=401)
    token_info = info.get("token_info")
    if not token_info:
        raise HTTPException(status_code=401)
    if datetime.now().timestamp() > token_info.get("expires_in"):
        token_info = await refresh_access_token(request)
        session["info"]["token_info"].update(token_info)
    return session["info"]


async def get_publickey(client, token):
    resp = await client.get("/security/publickey", token=token)
    if resp.status_code != status.HTTP_200_OK:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Not able to get publickey",
        )
    return resp.json()["publickey"]


def decode_token(token, publickey):
    algorithm = jwt.get_unverified_header(token).get("alg")
    audience = jwt.get_unverified_claims(token).get("aud")
    return jwt.decode(token, publickey, audience=audience, algorithms=[algorithm])


def get_sessioned_user_info(request: Request):
    session = request.session
    try:
        return session["info"]["user_info"]
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No session"
        )


def get_sessioned_token_info(request: Request):
    session = request.session
    try:
        return session["info"]["token_info"]
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No session"
        )


async def parse_token(client, token):
    publickey = await get_publickey(client, token=token)
    token_info = decode_token(token["access_token"], publickey)
    # user_info from oauth server <- 만일 더 정보가 필요하면 api로 요청
    return {
        "user_id": token_info["userId"],
        "nickname": token_info["nickname"],
        "email": token_info["email"],
        "role": token_info["role"],
    }


def set_user_session(session, *, user_info, token_info):
    exp = token_info["expires_in"]
    session["info"] = {"user_info": user_info, "token_info": token_info, "exp": exp}
