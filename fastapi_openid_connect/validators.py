from typing import Optional
from pydantic import AfterValidator
from pydantic_core import Url


def https_or_localhost_url(url:Optional[Url]) -> Optional[Url]:
    if url is None:
        # Allow usage with Optional types
        return url

    assert url.scheme == "https" or url.host in (
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
    ), "Not https or localhost"
    return url


# NOTE: Allows using localhost for development and testing of OPs
HttpsUrlOrLocalhost = AfterValidator(https_or_localhost_url)


def url_no_fragment(url: Optional[Url]) -> Optional[Url]:
    if url is None:
        # Allow usage with Optional types
        return url

    assert url.fragment is None, "Fragment present"
    return url


UrlNoFragment = AfterValidator(url_no_fragment)


def url_no_query(url: Optional[Url]) -> Optional[Url]:
    if url is None:
        # Allow usage with Optional types
        return url

    assert url.query is None, "Query params present"
    return url


UrlNoQuery = AfterValidator(url_no_query)
