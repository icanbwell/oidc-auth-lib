from oidcauthlib.utilities.mongo_url_utils import MongoUrlHelpers


def test_extract_hostname_simple() -> None:
    url = "mongodb://mongo:27017"
    assert MongoUrlHelpers.extract_hostname(url) == "mongo"


def test_extract_hostname_with_credentials() -> None:
    url = "mongodb://user:pass@mongo:27017"  # pragma: allowlist secret
    assert MongoUrlHelpers.extract_hostname(url) == "mongo"


def test_extract_hostname_with_query() -> None:
    url = "mongodb://mongo:27017/?appName=test"
    assert MongoUrlHelpers.extract_hostname(url) == "mongo"


def test_extract_hostname_replica_set() -> None:
    url = "mongodb://mongo1:27017,mongo2:27018"
    assert MongoUrlHelpers.extract_hostname(url) == "mongo1,mongo2"


def test_extract_hostname_replica_set_with_credentials() -> None:
    url = "mongodb://user:pass@mongo1:27017,mongo2:27018"  # pragma: allowlist secret
    assert MongoUrlHelpers.extract_hostname(url) == "mongo1,mongo2"


def test_extract_hostname_ipv6() -> None:
    url = "mongodb://[::1]:27017"
    assert MongoUrlHelpers.extract_hostname(url) == "[::1]"


def test_extract_hostname_ipv6_replica_set() -> None:
    url = "mongodb://[::1]:27017,[fe80::1]:27018"
    assert MongoUrlHelpers.extract_hostname(url) == "[::1],[fe80::1]"
