import secrets
from typing import Optional
from typing_extensions import Annotated
from urllib.parse import quote

from fastapi import (Cookie, Depends, FastAPI, Query, Security)
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from fastapi_openid_connect import AuthData, OpenIdConnect

THIS_APP_HOST = "http://127.0.0.1:8000"
# NOTE: We need this in order to ensure proper redirects

OIDC_PROVIDER_URI = "https://samples.auth0.com"
# NOTE: Use whatever OP domain has `/.well-known/openid-configuration` for proper auto-disovery
oidc_provider = OpenIdConnect(
    baseUrl=OIDC_PROVIDER_URI,
    description="Delegated authorization using OpenID Connect",
    # The name of this product (for display purposes in Swagger)
    app_name="OpenID Connect Demo Client",
    # This is the ID of the product registered with the Authorization Server
    client_id="kbyuFDidLLm280LIwVFiazOqjO3ty8KH",
    # If this application needs to do something with authorization codes, add this
    # client_secret="60Op4HFM0I8ajz0WdiStAbziZ-VFQttXuxixHHs2R7r7-CW8GR79l-mmLqMhc-Sa",
    # The scopes you want to access from the OP (passed to OAuth request)
    # NOTE: The `openid` scope is always added when missing
    scopes={"profile", "email"},
)

# NOTE: We have a convienence function for properly configuring Swagger UI
app = FastAPI(swagger_ui_init_oauth=oidc_provider.swagger_ui_init_oauth_config)

# NOTE: We need CORS middleware to allow the redirect (even in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[OIDC_PROVIDER_URI],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# NOTE: Use a better system for tracking session tokens and state, probably a db like redis
#       Also beware of timing attacks when finding session tokens
sessions = {}
# NOTE: use this to look up state from request nonce (returned in id_token)
state_by_nonce = {}


class AuthenticationError(HTTPException):
    def __init__(self, detail):
        super().__init__(detail=detail, status_code=HTTP_403_FORBIDDEN)


@app.get("/auth")
def delegated_auth_test(
    auth: Annotated[AuthData, Security(oidc_provider)],
    redirect_uri: Optional[str] = None,
    state: Annotated[Optional[str], Query()] = None,
):
    if auth.id_token is None:
        raise AuthenticationError("Expected id_token")

    if not (nonce := auth.id_token.get("nonce")):
        raise AuthenticationError("Expected nonce in id_token")

    if (
        not (expected_state := state_by_nonce.pop(nonce, None))
        or expected_state != state
    ):
        raise AuthenticationError("CSRF Attack!")

    response = RedirectResponse(url="/" if redirect_uri is None else redirect_uri)

    # Ussue a session cookie for access to the rest of the service
    session_id = secrets.token_urlsafe(16)
    sessions[session_id] = auth.id_token[
        "sub"
    ]
    # NOTE: Use `sub` as `id` for sessions/resources
    response.set_cookie(
        key="session",
        value=session_id,
        # NOTE: Make sure the cookie is well-secured
        secure=True,
        httponly=True,
    )
    return response


# NOTE: Have some sort of auth-based redirect to get auth from our oidc provider
class AuthorizationError(HTTPException):
    def __init__(self):
        super().__init__(detail="Not authorized.", status_code=HTTP_401_UNAUTHORIZED)


# NOTE: Make a dependency to get your user_id from local session auth
async def get_user_id(session: Annotated[Optional[str], Cookie()] = None) -> str:
    if session is None or not (user_id := sessions.get(session)):
        # Raise if we don't have session established
        raise AuthorizationError()

    return user_id


@app.get("/")
def protected_resource(user_id: str = Depends(get_user_id)):
    return f"{user_id} is here!"


async def redirect_oidc_auth(request, exc):
    nonce = secrets.token_urlsafe(11)
    state = secrets.token_urlsafe(11)
    state_by_nonce[nonce] = state
    inner_redirect = quote(str(request.url), safe="")
    return await oidc_provider.create_auth_redirect(
        f"{THIS_APP_HOST}/auth?redirect_uri={inner_redirect}", state=state, nonce=nonce
    )


# NOTE: Add an exception handler to execute OAuth2-style redirect to our OIDC provider
app.add_exception_handler(AuthorizationError, redirect_oidc_auth)
