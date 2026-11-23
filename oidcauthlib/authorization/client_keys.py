"""Parsers for a client-key mapping: a ``name -> key`` map held in one setting.

The raw value is either a JSON object (``{"One": "key-1"}``) or a comma-separated
list (``One=key-1,Two=key-2``). Two parsers read it:

* ``parse_client_keys_lenient`` keeps the historical behavior of services that
  read this setting: a malformed JSON object falls back to comma parsing and an
  entry without ``=`` is dropped silently.
* ``parse_client_keys_strict`` is for startup validation: it refuses anything the
  lenient parser would silently repair or drop.

Error messages name the rule that failed, never a client name or a key.
"""

import json
import logging

from oidcauthlib.authorization.client_slugs import normalize_slug

logger = logging.getLogger(__name__)


class ClientKeysFormatError(ValueError):
    """The raw client-key mapping is malformed."""


def parse_client_keys_lenient(*, raw: str) -> dict[str, str]:
    """Parse the mapping, repairing or dropping what it cannot read.

    An empty value gives ``{}``. A JSON object keeps its string values (a repeated name
    keeps the last value); invalid JSON falls back to comma parsing. In the comma form,
    an entry without ``=`` is dropped. The fallback, the number of repeated JSON names
    and the number of dropped entries are each logged once, never the entries.

    Args:
        raw: the setting's value, a JSON object or a comma-separated ``name=key`` list.
    """
    if not raw:
        return {}
    if raw.strip().startswith("{"):
        try:
            pairs: list[tuple[str, object]] = json.loads(raw, object_pairs_hook=lambda items: items)
        except json.JSONDecodeError:
            logger.warning("The client-key mapping is not a valid JSON object; falling back to comma parsing")
        else:
            return _string_entries(pairs)
    clients: dict[str, str] = {}
    dropped = 0
    for entry in raw.split(","):
        entry = entry.strip()
        if "=" in entry:
            name, value = entry.split("=", 1)
            clients[name.strip()] = value.strip()
        elif entry:
            dropped += 1
    if dropped:
        # Count only: an entry can hold a client name or key.
        logger.warning("Dropped %d client-key entries that have no '='", dropped)
    return clients


def _string_entries(pairs: list[tuple[str, object]]) -> dict[str, str]:
    clients: dict[str, str] = {}
    repeated = 0
    not_strings = 0
    for name, value in pairs:
        if name in clients:
            repeated += 1
        if not isinstance(value, str):
            not_strings += 1
            continue
        clients[name] = value
    # Counts only: a name or a value can identify a client.
    if repeated:
        logger.warning("Found %d repeated names in the client-key mapping; the last value is kept", repeated)
    if not_strings:
        logger.warning("Dropped %d client-key entries whose value is not a string", not_strings)
    return clients


def parse_client_keys_strict(*, raw: str) -> dict[str, str]:
    """Parse the mapping and refuse anything the lenient parser would repair.

    Two different names may share one key: each is an alias that selects that key.

    Args:
        raw: the setting's value, a JSON object or a comma-separated ``name=key`` list.

    Raises:
        ClientKeysFormatError: invalid JSON (no fall-back to comma parsing), a
            JSON value that is not an object of strings, duplicate JSON keys, a
            comma entry without ``=``, a blank name or key, or a name repeated
            after stripping and lowercasing ASCII letters, the way the resolver
            matches slugs (exact repeats included).
    """
    text = raw.strip()
    if not text:
        return {}
    pairs = _json_pairs(text) if text.startswith("{") else _comma_pairs(text)
    clients: dict[str, str] = {}
    seen: set[str] = set()
    for position, (name, key) in enumerate(pairs, start=1):
        clean_name = name.strip()
        clean_key = key.strip()
        if not clean_name or not clean_key:
            raise ClientKeysFormatError(f"entry {position} has a blank name or key")
        folded = normalize_slug(slug=clean_name)
        if folded in seen:
            raise ClientKeysFormatError(f"entry {position} repeats a name after stripping and ignoring ASCII case")
        seen.add(folded)
        clients[clean_name] = clean_key
    return clients


def _json_pairs(text: str) -> list[tuple[str, str]]:
    # The caller passes text that starts with "{", so a successful parse is always an
    # object, and ``object_pairs_hook`` gives its (name, value) pairs in order.
    try:
        parsed: list[tuple[str, object]] = json.loads(text, object_pairs_hook=lambda pairs: pairs)
    except json.JSONDecodeError as exc:
        raise ClientKeysFormatError("the value is not valid JSON") from exc
    pairs: list[tuple[str, str]] = []
    for position, (name, key) in enumerate(parsed, start=1):
        if not isinstance(key, str):
            raise ClientKeysFormatError(f"entry {position} has a value that is not a string")
        pairs.append((name, key))
    return pairs


def _comma_pairs(text: str) -> list[tuple[str, str]]:
    if text.startswith("["):
        raise ClientKeysFormatError("the JSON value is not an object")
    pairs: list[tuple[str, str]] = []
    for position, entry in enumerate(text.split(","), start=1):
        if "=" not in entry:
            raise ClientKeysFormatError(f"entry {position} has no '='")
        name, key = entry.split("=", 1)
        pairs.append((name, key))
    return pairs
