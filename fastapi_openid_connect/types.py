from enum import Enum


class ResponseType(str, Enum):
    ID_TOKEN = "id_token"
    TOKEN = "token"
    CODE = "code"

    def __str__(self) -> str:
        return self.value


class ResponseMode(str, Enum):
    QUERY = "query"
    FORM_POST = "form_post"
    FRAGMENT = "fragment"

    def __str__(self) -> str:
        return self.value


class GrantType(str, Enum):
    # NOTE: Only those conforming to the specification
    AUTHORIZATION_CODE = "authorization_code"
    IMPLICIT = "implicit"
    CLIENT_CREDENTIALS = "client_credentials"
    PASSWORD = "password"
    REFRESH_TOKEN = "refresh_token"

    def __str__(self) -> str:
        return self.value

