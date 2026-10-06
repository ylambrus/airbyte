# Copyright (c) 2026 Airbyte, Inc., all rights reserved.

"""Unit tests for the PII redaction policy in `components.py`.

These tests exercise path matching, every action, rule precedence, protected fields, allowlist
mode, config validation and schema adaptation directly on `RedactionPolicy`. The wiring of the
policy into the manifest is covered by `test_pii_redaction_manifest.py`.
"""

import copy
import hashlib
import hmac
import logging
import time

import pytest
from _helpers import load_components

from airbyte_cdk.models import FailureType
from airbyte_cdk.utils.traced_exception import AirbyteTracedException


components = load_components()

HASH_KEY = "unit-test-hash-key-0123456789"


def _policy(rules, stream="extensiveCalls", protected=("id", "startdatetime"), **section):
    config = {"pii_redaction": {"rules": rules, "hash_key": HASH_KEY, **section}}
    return components.RedactionPolicy.from_config(config, stream, list(protected))


def _redact(record, rules, **kwargs):
    redacted = copy.deepcopy(record)
    _policy(rules, **kwargs).apply(redacted)
    return redacted


def _hmac(value: str) -> str:
    return hmac.new(HASH_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()


def _extensive_call() -> dict:
    return {
        "id": 7782342274025937895,
        "startdatetime": "2024-01-02T10:00:00Z",
        "metaData": {"id": "7782342274025937895", "title": "Acme <> Mirakl", "isPrivate": False},
        "parties": [
            {"id": "p1", "name": "Jane Roe", "emailAddress": "Jane.Roe@acme.com", "phoneNumber": "+1 555 123 4567", "methods": ["Invitee"]},
            {"id": "p2", "name": "John Doe", "emailAddress": "john.doe@mirakl.com", "context": [{"system": "Salesforce", "objects": []}]},
            {"id": "p3", "name": None},
        ],
        "content": {
            "brief": "Jane (jane.roe@acme.com, +33 6 12 34 56 78) wants a demo.",
            "highlights": [{"title": "Next steps", "items": [{"text": "Send the contract to legal@acme.com", "startTimes": [12.5]}]}],
        },
        "media": {"audioUrl": "https://gong/audio", "videoUrl": "https://gong/video"},
    }


# -- path syntax ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path, expected",
    [
        ("emailAddress", "[_Key(pattern='emailAddress', is_glob=False)]"),
        ("$.parties.emailAddress", "[_Key(pattern='parties', is_glob=False), _Key(pattern='emailAddress', is_glob=False)]"),
        ("parties[*].email*", "[_Key(pattern='parties', is_glob=False), _Index(index=None), _Key(pattern='email*', is_glob=True)]"),
        ("parties[].x", "[_Key(pattern='parties', is_glob=False), _Index(index=None), _Key(pattern='x', is_glob=False)]"),
        ("parties[2]", "[_Key(pattern='parties', is_glob=False), _Index(index=2)]"),
        ("**.**.x", "[**, _Key(pattern='x', is_glob=False)]"),
        ("a\\.b.c", "[_Key(pattern='a.b', is_glob=False), _Key(pattern='c', is_glob=False)]"),
    ],
)
def test_parse_path(path, expected):
    assert repr(list(components.parse_path(path))) == expected


@pytest.mark.parametrize("path", ["", "  ", "a..b", "a.", ".a", "a.**", "/parties/0/emailAddress"])
def test_parse_path_rejects_invalid_syntax(path):
    with pytest.raises(ValueError):
        components.parse_path(path)


# -- matching -------------------------------------------------------------------------------


def test_arrays_are_traversed_transparently():
    redacted = _redact(_extensive_call(), [{"action": "remove", "paths": ["parties.emailAddress"]}])
    assert [sorted(party) for party in redacted["parties"]] == [
        ["id", "methods", "name", "phoneNumber"],
        ["context", "id", "name"],
        ["id", "name"],
    ]


@pytest.mark.parametrize("path", ["parties.*.emailAddress", "parties[*].emailAddress", "parties[].emailAddress"])
def test_explicit_array_wildcards_match_every_element(path):
    redacted = _redact(_extensive_call(), [{"action": "remove", "paths": [path]}])
    assert all("emailAddress" not in party for party in redacted["parties"])


def test_array_index_selects_one_element():
    redacted = _redact(_extensive_call(), [{"action": "remove", "paths": ["parties[1].emailAddress"]}])
    assert "emailAddress" in redacted["parties"][0]
    assert "emailAddress" not in redacted["parties"][1]


def test_deep_wildcard_matches_any_depth_including_top_level():
    record = {"id": 1, "emailAddress": "a@b.co", "x": {"emailAddress": "c@d.co", "y": [[{"emailAddress": "e@f.co"}]]}}
    redacted = _redact(record, [{"action": "nullify", "paths": ["**.emailAddress"]}], protected=("id",))
    assert redacted == {"id": 1, "emailAddress": None, "x": {"emailAddress": None, "y": [[{"emailAddress": None}]]}}


def test_glob_patterns_match_key_names():
    redacted = _redact(_extensive_call(), [{"action": "remove", "paths": ["parties.*Address", "media.*Url"]}])
    assert all("emailAddress" not in party for party in redacted["parties"])
    assert redacted["media"] == {}


def test_path_that_does_not_exist_is_a_no_op():
    record = _extensive_call()
    assert _redact(record, [{"action": "remove", "paths": ["nope.nothing", "parties.name.first", "**.missing"]}]) == record


def test_deep_wildcard_hits_each_value_once():
    """`**` reaches some slots through several routes; a hash must still be applied exactly once."""
    record = {"id": 1, "a": [{"email": "X@y.co"}, [{"email": "z@y.co"}]]}
    redacted = _redact(record, [{"action": "hash", "paths": ["**.email"]}], protected=("id",))
    assert redacted["a"][0]["email"] == _hmac("x@y.co")
    assert redacted["a"][1][0]["email"] == _hmac("z@y.co")


# -- actions --------------------------------------------------------------------------------


def test_remove_deletes_keys_and_array_elements():
    redacted = _redact(_extensive_call(), [{"action": "remove", "paths": ["media", "parties[0]", "parties.*.methods"]}])
    assert "media" not in redacted
    assert [party["id"] for party in redacted["parties"]] == ["p2", "p3"]


def test_nullify_keeps_the_key():
    redacted = _redact(_extensive_call(), [{"action": "nullify", "paths": ["media", "parties.phoneNumber"]}])
    assert redacted["media"] is None
    assert redacted["parties"][0]["phoneNumber"] is None
    assert "phoneNumber" not in redacted["parties"][1]  # absent values are not created


def test_mask_replaces_every_leaf_and_preserves_structure():
    redacted = _redact(_extensive_call(), [{"action": "mask", "paths": ["parties.name", "content.highlights"]}], mask_value="***")
    assert [party["name"] for party in redacted["parties"]] == ["***", "***", None]  # nulls stay null
    assert redacted["content"]["highlights"] == [{"title": "***", "items": [{"text": "***", "startTimes": ["***"]}]}]


def test_hash_is_a_keyed_normalized_hmac():
    redacted = _redact(_extensive_call(), [{"action": "hash", "paths": ["parties.emailAddress", "parties.methods"]}])
    assert redacted["parties"][0]["emailAddress"] == _hmac("jane.roe@acme.com")  # trimmed and lowercased first
    assert redacted["parties"][0]["methods"] == [_hmac("invitee")]  # arrays are hashed element-wise
    # the same value hashes identically, so pseudonymized emails can be joined across streams
    users_record = _redact(
        {"id": "1", "emailAddress": " JANE.ROE@ACME.COM "}, [{"action": "hash", "paths": ["emailAddress"]}], stream="users"
    )
    assert users_record["emailAddress"] == redacted["parties"][0]["emailAddress"]


def test_hash_depends_on_the_key():
    rules = [{"action": "hash", "paths": ["emailAddress"]}]
    first = _redact({"emailAddress": "a@b.co"}, rules, protected=())
    second = _redact({"emailAddress": "a@b.co"}, rules, protected=(), hash_key="another-key-0123456789")
    assert first["emailAddress"] != second["emailAddress"]


def test_hash_of_non_string_values():
    redacted = _redact({"n": 42, "b": True, "f": 1.5, "z": None}, [{"action": "hash", "paths": ["*"]}], protected=())
    assert redacted == {"n": _hmac("42"), "b": _hmac("true"), "f": _hmac("1.5"), "z": None}


def test_redact_text_scrubs_nested_strings():
    redacted = _redact(_extensive_call(), [{"action": "redact_text", "paths": ["content"]}])
    assert redacted["content"]["brief"] == "Jane ([EMAIL], [PHONE]) wants a demo."
    assert redacted["content"]["highlights"][0]["items"][0] == {"text": "Send the contract to [EMAIL]", "startTimes": [12.5]}


@pytest.mark.parametrize(
    "text, expected",
    [
        ("mail me at first.last+tag@sub.example.co.uk!", "mail me at [EMAIL]!"),
        ("call +33 6 12 34 56 78 or 06.12.34.56.78", "call [PHONE] or [PHONE]"),
        ("US office (555) 123-4567, UK 020 7946 0958", "US office [PHONE], UK [PHONE]"),
        ("+1 (555) 123-4567 or +33 (0)6 12 34 56 78", "[PHONE] or [PHONE]"),
        ("(mobile: 0612345678)", "(mobile: [PHONE])"),
        ("0612345678 - 0698765432", "[PHONE] - [PHONE]"),
        ("card 4111 1111 1111 1111 expires", "card [CREDIT_CARD] expires"),
        ("IBAN FR76 3000 6000 0112 3456 7890 189 OK", "IBAN [IBAN] OK"),
        ("from 192.168.10.254.", "from [IP_ADDRESS]."),
    ],
)
def test_redact_text_detectors(text, expected):
    redacted = _redact({"t": text}, [{"action": "redact_text", "paths": ["t"]}], protected=())
    assert redacted["t"] == expected


@pytest.mark.parametrize(
    "text",
    [
        "Call 7782342274025937895 lasted 3600 seconds",  # Gong call ids are 19 digits
        "Meeting on 2024-01-15 at 10:30, 25 attendees, 12.5% growth",
        "We sell 10 000 000 products in 4 countries",
        "card 4111 1111 1111 1112 fails the Luhn check",
        "IBAN FR76 3000 6000 0112 3456 7890 188 has a bad checksum",
        "version 300.1.2.3 is not an address",
    ],
)
def test_redact_text_leaves_non_pii_untouched(text):
    redacted = _redact({"t": text}, [{"action": "redact_text", "paths": ["t"]}], protected=())
    assert redacted["t"] == text


def test_redact_text_detector_selection_and_custom_patterns():
    rules = [{"action": "redact_text", "paths": ["t"], "detectors": ["email"], "custom_patterns": [r"\bACME-\d+\b"]}]
    redacted = _redact({"t": "a@b.co, +33 6 12 34 56 78, ticket ACME-123"}, rules, protected=(), mask_value="<x>")
    assert redacted["t"] == "[EMAIL], +33 6 12 34 56 78, ticket <x>"


@pytest.mark.parametrize(
    "text",
    [
        "abc.def_" * 30000 + "@",  # one long run of email local-part characters
        "x@" + "b." * 100000,
        "1" * 200000,
        "12 " * 70000,
        "(1)" * 60000,
        "FR76" + " AAAA" * 50000,
    ],
)
def test_redact_text_runs_in_linear_time_on_adversarial_strings(text):
    started = time.monotonic()
    _redact({"t": text}, [{"action": "redact_text", "paths": ["t"]}], protected=())
    # Linear patterns take milliseconds here; a quadratic one takes tens of seconds.
    assert time.monotonic() - started < 2


def test_redact_text_ignores_non_strings():
    redacted = _redact({"t": [12345678901, {"x": True}]}, [{"action": "redact_text", "paths": ["t"]}], protected=())
    assert redacted["t"] == [12345678901, {"x": True}]


# -- precedence -----------------------------------------------------------------------------


def test_strongest_action_wins_regardless_of_rule_order():
    rules = [
        {"action": "hash", "paths": ["parties"]},
        {"action": "remove", "paths": ["parties.emailAddress"]},
        {"action": "mask", "paths": ["parties.name"]},
        {"action": "redact_text", "paths": ["parties.name"]},
    ]
    for ordered in (rules, list(reversed(rules))):
        party = _redact(_extensive_call(), ordered)["parties"][0]
        assert "emailAddress" not in party
        assert party["name"] == "[REDACTED]"
        assert party["phoneNumber"] == _hmac("+1 555 123 4567")


def test_overlapping_redact_text_rules_combine_their_detectors():
    rules = [
        {"action": "redact_text", "paths": ["t"], "detectors": ["email"]},
        {"action": "redact_text", "paths": ["**.t"], "detectors": ["phone"]},
    ]
    redacted = _redact({"t": "a@b.co +33 6 12 34 56 78"}, rules, protected=())
    assert redacted["t"] == "[EMAIL] [PHONE]"


# -- streams and protected fields -----------------------------------------------------------


def test_rules_only_apply_to_their_streams():
    rules = [{"action": "remove", "paths": ["emailAddress"], "streams": ["users"]}]
    assert _redact({"emailAddress": "a@b.co"}, rules, stream="extensiveCalls", protected=()) == {"emailAddress": "a@b.co"}
    assert _redact({"emailAddress": "a@b.co"}, rules, stream="users", protected=()) == {}


def test_protected_fields_are_never_modified(caplog):
    rules = [{"action": "remove", "paths": ["*"]}, {"action": "hash", "paths": ["**.id"]}]
    with caplog.at_level(logging.WARNING, logger="airbyte"):
        redacted = _redact(_extensive_call(), rules)
    assert redacted == {"id": 7782342274025937895, "startdatetime": "2024-01-02T10:00:00Z"}
    assert "primary key or cursor field" in caplog.text


def test_protected_fields_are_only_protected_at_the_top_level():
    redacted = _redact(_extensive_call(), [{"action": "hash", "paths": ["**.id"]}])
    assert redacted["id"] == 7782342274025937895
    assert redacted["metaData"]["id"] == _hmac("7782342274025937895")
    assert redacted["parties"][0]["id"] == _hmac("p1")


# -- allowlist ------------------------------------------------------------------------------


def test_keep_rules_emit_only_kept_fields_and_protected_fields():
    rules = [{"action": "keep", "paths": ["metaData.isPrivate", "parties.id", "parties.methods", "content.highlights.title"]}]
    redacted = _redact(_extensive_call(), rules)
    assert redacted == {
        "id": 7782342274025937895,
        "startdatetime": "2024-01-02T10:00:00Z",
        "metaData": {"isPrivate": False},
        # array elements are pruned rather than dropped, so arrays keep their length
        "parties": [{"id": "p1", "methods": ["Invitee"]}, {"id": "p2"}, {"id": "p3"}],
        "content": {"highlights": [{"title": "Next steps"}]},
    }


def test_keep_combines_with_destructive_rules():
    rules = [{"action": "keep", "paths": ["parties.emailAddress"]}, {"action": "hash", "paths": ["**.emailAddress"]}]
    redacted = _redact(_extensive_call(), rules)
    assert redacted["parties"] == [{"emailAddress": _hmac("jane.roe@acme.com")}, {"emailAddress": _hmac("john.doe@mirakl.com")}, {}]


def test_keep_rules_of_other_streams_do_not_apply():
    record = _extensive_call()
    assert _redact(record, [{"action": "keep", "paths": ["id"], "streams": ["users"]}]) == record


# -- config validation ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "section, message",
    [
        ({"rules": [{"action": "delete", "paths": ["a"]}]}, "unknown action"),
        ({"rules": [{"action": "remove"}]}, "has no `paths`"),
        ({"rules": [{"action": "remove", "paths": ["a..b"]}]}, "invalid path"),
        ({"rules": [{"action": "hash", "paths": ["a"]}]}, "requires `pii_redaction.hash_key`"),
        ({"rules": [{"action": "hash", "paths": ["a"]}], "hash_key": "short"}, "at least 16 characters"),
        ({"rules": [{"action": "redact_text", "paths": ["a"], "detectors": ["ssn"]}]}, "unknown detector"),
        ({"rules": [{"action": "redact_text", "paths": ["a"], "custom_patterns": ["("]}]}, "invalid custom pattern"),
        ({"rules": "remove everything"}, "must be a list"),
        ({"rules": ["a.b"]}, "must be an object"),
    ],
)
def test_invalid_config_is_a_config_error(section, message):
    with pytest.raises(AirbyteTracedException) as error:
        components.RedactionPolicy.from_config({"pii_redaction": section}, "users", ["id"])
    assert error.value.failure_type == FailureType.config_error
    assert message in error.value.message


def test_hash_key_is_validated_even_when_the_hash_rule_targets_another_stream():
    section = {"rules": [{"action": "hash", "paths": ["a"], "streams": ["calls"]}]}
    with pytest.raises(AirbyteTracedException):
        components.RedactionPolicy.from_config({"pii_redaction": section}, "users", ["id"])


@pytest.mark.parametrize("config", [{}, {"pii_redaction": None}, {"pii_redaction": {}}, {"pii_redaction": {"rules": []}}])
def test_no_rules_leaves_records_untouched(config):
    record = _extensive_call()
    redacted = copy.deepcopy(record)
    components.RedactionPolicy.from_config(config, "extensiveCalls", ["id"]).apply(redacted)
    assert redacted == record


# -- schema adaptation ----------------------------------------------------------------------

_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": ["null", "integer"]},
        "startdatetime": {"type": ["null", "string"], "format": "date-time"},
        "duration": {"type": ["null", "integer"], "description": "Seconds"},
        "parties": {
            "type": ["null", "array"],
            "items": {
                "type": ["null", "object"],
                "properties": {
                    "emailAddress": {"type": ["null", "string"]},
                    "name": {"type": "string"},
                    "methods": {"type": ["null", "array"], "items": {"type": ["null", "string"]}},
                    "context": {"type": ["null", "object"]},
                },
            },
        },
        "media": {"type": "object", "properties": {"audioUrl": {"type": "string"}}},
    },
}


def test_schema_drops_removed_properties_and_retypes_hashed_ones():
    rules = [
        {"action": "remove", "paths": ["media", "parties.emailAddress"]},
        {"action": "hash", "paths": ["duration", "parties.methods", "parties.context"]},
        {"action": "nullify", "paths": ["parties.name"]},
        {"action": "redact_text", "paths": ["**.name"]},
    ]
    schema = _policy(rules).adapt_schema(_SCHEMA)
    assert set(schema["properties"]) == {"id", "startdatetime", "duration", "parties"}
    assert schema["properties"]["duration"] == {"type": ["null", "string"], "description": "Seconds"}
    party = schema["properties"]["parties"]["items"]["properties"]
    assert set(party) == {"name", "methods", "context"}
    assert party["methods"]["items"] == {"type": ["null", "string"]}
    assert party["context"] == {"type": ["null", "object"]}  # free-form objects keep their type: leaves are hashed in place
    assert party["name"] == {"type": ["null", "string"]}
    assert _SCHEMA["properties"]["media"], "the input schema must not be mutated"


def test_schema_keep_prunes_everything_else_but_protected_fields():
    schema = _policy([{"action": "keep", "paths": ["parties.name"]}]).adapt_schema(_SCHEMA)
    assert set(schema["properties"]) == {"id", "startdatetime", "parties"}
    assert set(schema["properties"]["parties"]["items"]["properties"]) == {"name"}


def test_schema_never_changes_protected_fields():
    schema = _policy([{"action": "remove", "paths": ["*"]}, {"action": "hash", "paths": ["**.id"]}]).adapt_schema(_SCHEMA)
    assert schema["properties"] == {"id": _SCHEMA["properties"]["id"], "startdatetime": _SCHEMA["properties"]["startdatetime"]}


def test_schema_warns_about_paths_matching_no_declared_field(caplog):
    rules = [
        {"action": "remove", "paths": ["parties.emial"], "streams": ["extensiveCalls"]},
        {"action": "remove", "paths": ["unscoped.typo"]},  # rules for all streams legitimately miss some schemas
    ]
    with caplog.at_level(logging.WARNING, logger="airbyte"):
        _policy(rules).adapt_schema(_SCHEMA)
    assert "`parties.emial` matches no field declared" in caplog.text
    assert "unscoped.typo" not in caplog.text
