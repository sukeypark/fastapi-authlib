from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from router import login
from core.config import settings

import logging
import sys

log = logging.getLogger("authlib")
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)


app = FastAPI()


app.include_router(login.router)
app.add_middleware(SessionMiddleware, secret_key="session-secret-key")
