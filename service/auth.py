import time
from jose import jwt
from fastapi import HTTPException
from starlette import status

from core.security import oauth
from schema.user import UserInfo


async def get_publickey(client, token):
    resp = await client.get("/security/publickey", token=token)
    if resp.status_code != status.HTTP_200_OK:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Not able to get publickey",
        )
    return resp.json()["publickey"]


def parse_token(token, publickey):
    algorithm = jwt.get_unverified_header(token).get("alg")
    audience = jwt.get_unverified_claims(token).get("aud")
    return jwt.decode(token, publickey, audience=audience, algorithms=[algorithm])


async def get_user_info(client, token):
    publickey = await get_publickey(client, token=token)
    token_info = parse_token(token["access_token"], publickey)
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
