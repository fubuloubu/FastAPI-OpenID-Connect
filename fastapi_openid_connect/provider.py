from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Set
from urllib.parse import quote

import httpx
from fastapi import Form, Query, Request
from fastapi.responses import RedirectResponse
from fastapi.security import OpenIdConnect as _BaseOIDC
from fastapi.security import SecurityScopes
from jose import jwt
from pydantic import BaseModel
from starlette.exceptions import HTTPException
from starlette.status import HTTP_403_FORBIDDEN
from typing_extensions import Annotated, Doc

from .models import OpenIDConfig
from .types import ResponseType, ResponseMode


class AuthData(BaseModel):
    # NOTE: We decode id_token per OpenID Connect 1.0
    id_token: Optional[dict] = None
    access_token: Optional[str] = None
    access_code: Optional[str] = None


class OpenIdConnect(_BaseOIDC):
    """
    OpenID Connect 1.0 authentication class. An instance of it would be used as a
    dependency to parse token.

    Example::

        >>> example_oidc = OpenIdConnect(baseUrl="https://example.com")
        >>> @app.get("/auth")
        ... def auth_callback_example(auth: AuthData = Depends(example_oidc)):
        ...     user = db.add(User, id=auth.id_token["sub"])
    """

    def __init__(
        self,
        *,
        baseUrl: Annotated[
            Optional[str],
            Doc(
                """
            The Base URL of the OIDC Service.

            If this is provided, then `openIdConnectUrl` will be computed as
            `<baseUrl>/.well-known/openid-configuration`.

            Exactly one of `openIdConnectUrl` and `baseUrl` must be specified.
            """
            ),
        ] = None,
        # NOTE: Besides the modified Doc here, everything was copied below
        openIdConnectUrl: Annotated[
            Optional[str],
            Doc(
                """
            The OpenID Connect URL.

            Use this if there is a non-standard OIDC Configuration URL.

            Exactly one of `openIdConnectUrl` and `baseUrl` must be specified.
            """
            ),
        ] = None,
        scheme_name: Annotated[
            Optional[str],
            Doc(
                """
                Security scheme name.

                It will be included in the generated OpenAPI (e.g. visible at `/docs`).
                """
            ),
        ] = None,
        description: Annotated[
            Optional[str],
            Doc(
                """
                Security scheme description.

                It will be included in the generated OpenAPI (e.g. visible at `/docs`).
                """
            ),
        ] = None,
        auto_error: Annotated[
            bool,
            Doc(
                """
                By default, if no HTTP Authorization header is provided, required for
                OpenID Connect authentication, it will automatically cancel the request
                and send the client an error.

                If `auto_error` is set to `False`, when the HTTP Authorization header
                is not available, instead of erroring out, the dependency result will
                be `None`.

                This is useful when you want to have optional authentication.

                It is also useful when you want to have authentication that can be
                provided in one of multiple optional ways (for example, with OpenID
                Connect or in a cookie).
                """
            ),
        ] = True,
        # NOTE: Below here are things we added as new options
        discovery_ttl: Annotated[
            Union[int, timedelta],
            Doc(
                """Discovery Time to Live, in either seconds or a timedelta value. Defaults to 4 hours."""
            ),
        ] = timedelta(hours=4),
        audience: Annotated[
            Optional[str],
            Doc(
                """The address of the Relaying Party server (aka this App's host URL)."""
            ),
        ] = None,
        app_name: Annotated[
            Optional[str],
            Doc("The name of the app (for display purposes in Swagger UI)."),
        ] = None,
        client_id: Annotated[
            Optional[str],
            Doc("The client id registered for this app with the Authorization Server."),
        ] = None,
        client_secret: Annotated[
            Optional[str],
            Doc(
                "The client secret registered for this app with the Authorization Server."
            ),
        ] = None,
        scopes: Annotated[
            Optional[Set[str]],
            Doc("The set of OAuth scopes that are requested by this app."),
        ] = None,
    ):
        if (baseUrl is None) == (openIdConnectUrl is None):
            raise ValueError("Must provide one of `baseUrl` or `openIdConnectUrl`")

        super().__init__(
            openIdConnectUrl=(
                f"{baseUrl.strip('/')}/.well-known/openid-configuration"
                if baseUrl
                else openIdConnectUrl
            ),
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )

        self.audience = audience
        self.app_name = app_name
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = {"openid"} if scopes is None else scopes | {"openid"}

        self.discovery_ttl = (
            discovery_ttl
            if isinstance(discovery_ttl, timedelta)
            else timedelta(seconds=discovery_ttl)
        )
        self.last_discovery: Optional[datetime] = None

    @property
    def swagger_ui_init_oauth_config(self, add_client_secret: bool = False) -> dict:
        swagger_config = dict(
            clientId=self.client_id,
            appName=self.app_name,
            scopes=" ".join(self.scopes),
        )

        if add_client_secret:
            # NOTE: That it is recommended not to run this in production
            swagger_config["clientSecret"] = self.client_secret

        return swagger_config

    async def create_auth_redirect(
        self,
        auth_redirect_uri: str,
        response_mode: ResponseMode = ResponseMode.QUERY,
        response_types: Set[ResponseType] = None,
        state: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> str:
        await self.perform_discovery()

        if response_mode not in self.config.response_modes_supported:
            supported_modes = ", ".join(self.config.response_modes_supported)
            raise ValueError(
                f"Unsupported response mode '{response_mode}', should be one of: {supported_modes}"
            )

        if response_types is None:
            response_types = {ResponseType.ID_TOKEN}

        if unsupported_response_types := ", ".join(
            response_types - self.config.response_types_supported
        ):
            raise ValueError(
                f"Unsupported response_types: {unsupported_response_types}"
            )

        params = dict(
            client_id=self.client_id,
            redirect_uri=quote(auth_redirect_uri, safe=""),
            response_mode=str(response_mode),
            response_type=" ".join(map(str, response_types)),
            scope=" ".join(map(str, self.scopes)),
        )

        if state is not None:
            params["state"] = state

        if nonce is not None:
            params["nonce"] = nonce

        params_str = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
        return RedirectResponse(
            url=f"{self.config.authorization_endpoint}?{params_str}"
        )

    async def perform_discovery(self):
        async with httpx.AsyncClient() as client:
            if not hasattr(self, "config"):
                response = await client.get(self.model.openIdConnectUrl)
                # NOTE: Assumes discovery info does not change
                self.config = OpenIDConfig.model_validate_json(response.text)

            utc_now = datetime.now(timezone.utc)
            if (
                self.last_discovery is None
                or (utc_now - self.last_discovery) > self.discovery_ttl
            ):
                response = await client.get(str(self.config.jwks_uri))
                self.jwks = response.json()
                self.last_discovery = utc_now

    async def __call__(
        self,
        request: Request,
        security_scopes: SecurityScopes = None,
    ) -> AuthData:
        """
        Can use either with `token: dict = Depends(oidc_provider)`
        or `token: dict = Security(oidc_provider, scopes=[...])` to provide additonal scopes
        """
        return await self._parse(
            id_token=request.query_params.get("id_token"),
            access_token=request.query_params.get("token"),
            access_code=request.query_params.get("code"),
            security_scopes=security_scopes,
        )

    # NOTE: We don't handle `ResponseMode.FRAGMENT` because that is entirely client-side
    async def form_post(
        self,
        id_token: Annotated[Optional[str], Form()] = None,
        token: Annotated[Optional[str], Form()] = None,
        code: Annotated[Optional[str], Form()] = None,
        security_scopes: SecurityScopes = None,
    ) -> AuthData:
        return await self._parse(
            id_token=id_token,
            access_token=token,
            access_code=code,
            security_scopes=security_scopes,
        )

    async def query(
        self,
        id_token: Annotated[Optional[str], Query()] = None,
        access_token: Annotated[Optional[str], Query(alias="token")] = None,
        access_code: Annotated[Optional[str], Query(alias="code")] = None,
        security_scopes: SecurityScopes = None,
    ) -> AuthData:
        return await self._parse(
            id_token=id_token,
            access_token=access_token,
            access_code=access_code,
            security_scopes=security_scopes,
        )

    async def _parse(
        self,
        id_token: Optional[str] = None,
        access_token: Optional[str] = None,
        access_code: Optional[str] = None,
        security_scopes: SecurityScopes = None,
    ) -> AuthData:
        try:
            await self.perform_discovery()

        except Exception as e:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail=f"Error performing discovery: {e}",
            )

        if id_token is None and access_token is None and access_code is None:
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="No authentication data detected.",
                )
            else:
                # NOTE: Mimic base class behavior of returning empty auth
                return AuthData()

        auth_data = AuthData(access_token=access_token, access_code=access_code)
        if id_token is not None:
            try:
                auth_data.id_token = jwt.decode(
                    id_token,
                    self.jwks,
                    options=dict(
                        # NOTE: Required per OpenID Connect Core 1.0
                        require_iss=True,
                        require_sub=True,
                        require_exp=True,
                        require_iat=True,
                        # NOTE: We allow no audience for local dev, should use in practice
                        require_aud=self.audience is not None,
                        verify_aud=self.audience is not None,
                    ),
                    algorithms=self.config.id_token_signing_alg_values_supported,
                    issuer=str(self.config.issuer).strip("/"),
                    audience=self.audience,
                    # TODO: Figure out `at_hash` detection to set `access_token=`
                )

            except Exception as e:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail=f"Error decoding token: {e}",
                )

        return auth_data
