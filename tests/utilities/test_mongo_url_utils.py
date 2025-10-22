from oidcauthlib.utilities.mongo_url_utils import MongoUrlHelpers


def test_add_credentials_to_mongo_url() -> None:
    url: str = "mongodb://mongo:27017?appName=fhir-server"
    username: str = "user"
    password: str = "pass"
    new_url: str = MongoUrlHelpers.add_credentials_to_mongo_url(
        mongo_url=url, username=username, password=password
    )
    expected_prefix = "mongodb://user:pass@mongo:27017"  # pragma: allowlist secret
    assert new_url.startswith(expected_prefix)

    # No credentials
    assert (
        MongoUrlHelpers.add_credentials_to_mongo_url(
            mongo_url=url, username=None, password=None
        )
        == url
    )

    # Already has credentials
    url2: str = "mongodb://old:creds@mongo:27017"  # pragma: allowlist secret
    new_url2: str = MongoUrlHelpers.add_credentials_to_mongo_url(
        mongo_url=url2,
        username="new",
        password="creds",  # pragma: allowlist secret
    )
    expected_prefix = "mongodb://new:creds@mongo:27017"  # pragma: allowlist secret
    assert new_url2.startswith(expected_prefix)
