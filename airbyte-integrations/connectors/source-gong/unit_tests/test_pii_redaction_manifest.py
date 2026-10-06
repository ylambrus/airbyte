# Copyright (c) 2026 Airbyte, Inc., all rights reserved.

"""Tests for the wiring of PII redaction into `manifest.yaml`.

Every stream must run the redaction transformation last and wrap its schema loader, otherwise a
stream added later would silently emit unredacted data. These tests check the manifest statically
and run full syncs against mocked Gong responses.
"""

import copy
import logging
from pathlib import Path

import requests_mock
import yaml
from _helpers import get_source

from airbyte_cdk.models import FailureType, Status, SyncMode
from airbyte_cdk.test.catalog_builder import CatalogBuilder
from airbyte_cdk.test.entrypoint_wrapper import discover, read
from airbyte_cdk.utils.traced_exception import AirbyteTracedException


_MANIFEST = yaml.safe_load((Path(__file__).parent.parent / "manifest.yaml").read_text())
_STREAMS = _MANIFEST["definitions"]["streams"]

_BASE_CONFIG = {
    "credentials": {
        "auth_type": "APIKey",
        "access_key": "test_access_key",
        "access_key_secret": "test_access_key_secret",
    },
    "start_date": "2024-01-01T00:00:00Z",
}
_HASH_KEY = "manifest-test-hash-key-0123456789"


def _config(*rules, **section) -> dict:
    return {**_BASE_CONFIG, "pii_redaction": {"hash_key": _HASH_KEY, "rules": list(rules), **section}}


def _sync(stream_name: str, config: dict, mocks: dict):
    catalog = CatalogBuilder().with_stream(stream_name, SyncMode.full_refresh).build()
    with requests_mock.Mocker() as mocker:
        for (method, url), payload in mocks.items():
            getattr(mocker, method)(url, json=payload)
        output = read(get_source(config=config), config, catalog)
    assert not output.errors, [error.trace.error.message for error in output.errors]
    return [message.record.data for message in output.records]


def _page(key: str, *items: dict) -> dict:
    return {key: list(items), "records": {"totalRecords": len(items), "currentPageSize": len(items), "currentPageNumber": 0}}


_USER = {
    "id": "u1",
    "emailAddress": "Jane.Roe@mirakl.com",
    "emailAliases": ["jane@mirakl.com"],
    "firstName": "Jane",
    "lastName": "Roe",
    "phoneNumber": "+33 6 12 34 56 78",
    "title": "AE",
}
_EXTENSIVE_CALL = {
    "metaData": {"id": "c1", "started": "2024-01-02T10:00:00Z", "isPrivate": False, "title": "Acme <> Mirakl"},
    "parties": [
        {"id": "p1", "name": "Jane Roe", "emailAddress": "jane.roe@mirakl.com", "userId": "u1"},
        {"id": "p2", "name": "John Doe", "emailAddress": "john@acme.com", "phoneNumber": "+1 555 123 4567"},
    ],
    "content": {"brief": "John (john@acme.com) asked for pricing."},
    "media": {"audioUrl": "https://gong/audio"},
}
_PRIVATE_EXTENSIVE_CALL = {**copy.deepcopy(_EXTENSIVE_CALL), "metaData": {"id": "c2", "started": "2024-01-03T10:00:00Z", "isPrivate": True}}

_USERS_MOCK = {("get", "https://api.gong.io/v2/users"): _page("users", _USER)}
_EXTENSIVE_MOCK = {("post", "https://api.gong.io/v2/calls/extensive"): _page("calls", _EXTENSIVE_CALL, _PRIVATE_EXTENSIVE_CALL)}


# -- static wiring --------------------------------------------------------------------------


def test_every_stream_runs_pii_redaction_last_and_wraps_its_schema_loader():
    declared = {stream["$ref"].rsplit("/", 1)[-1] for stream in _MANIFEST["streams"]}
    assert declared == set(_STREAMS)
    for name, stream in _STREAMS.items():
        assert stream["$parameters"]["pii_stream_name"] == name
        assert stream["transformations"][-1] == {"$ref": "#/definitions/pii_redaction_transformation"}, name
        assert stream["schema_loader"]["$ref"] == "#/definitions/pii_redaction_schema_loader", name
        assert stream["schema_loader"]["schema_loader"]["schema"] == {"$ref": f"#/schemas/{name}"}, name


def test_primary_keys_and_cursors_are_protected():
    for name, stream in _STREAMS.items():
        expected = set(stream["primary_key"])
        if "incremental_sync" in stream:
            expected.add(stream["incremental_sync"]["cursor_field"])
        assert set(stream["$parameters"]["pii_protected_fields"]) == expected, name


def test_spec_stream_choices_match_the_manifest_streams():
    rule_schema = _MANIFEST["spec"]["connection_specification"]["properties"]["pii_redaction"]["properties"]["rules"]["items"]
    assert set(rule_schema["properties"]["streams"]["items"]["enum"]) == set(_STREAMS)


# -- syncs ----------------------------------------------------------------------------------


def test_records_are_unchanged_without_pii_config():
    assert _sync("users", _BASE_CONFIG, _USERS_MOCK) == [_USER]


def test_users_stream_is_redacted():
    config = _config(
        {"action": "hash", "paths": ["**.emailAddress", "emailAliases"]},
        {"action": "remove", "paths": ["firstName", "lastName", "**.phoneNumber"], "streams": ["users"]},
    )
    [user] = _sync("users", config, _USERS_MOCK)
    assert set(user) == {"id", "emailAddress", "emailAliases", "title"}
    assert len(user["emailAddress"]) == 64 and user["emailAliases"][0] != "jane@mirakl.com"


def test_extensive_calls_are_redacted_and_hashes_join_across_streams():
    config = _config(
        {"action": "hash", "paths": ["**.emailAddress"]},
        {"action": "remove", "paths": ["media", "parties.name", "parties.phoneNumber"]},
        {"action": "redact_text", "paths": ["content"]},
    )
    [call] = _sync("extensiveCalls", config, _EXTENSIVE_MOCK)
    assert "media" not in call
    assert [sorted(party) for party in call["parties"]] == [["emailAddress", "id", "userId"], ["emailAddress", "id"]]
    assert call["content"]["brief"] == "John ([EMAIL]) asked for pricing."
    assert (call["id"], call["startdatetime"]) == ("c1", "2024-01-02T10:00:00Z")

    [user] = _sync("users", config, _USERS_MOCK)
    assert call["parties"][0]["emailAddress"] == user["emailAddress"], "the same email must hash to the same value in every stream"


def test_private_calls_are_still_dropped_when_rules_remove_is_private():
    config = _config({"action": "remove", "paths": ["metaData", "**.isPrivate"]})
    records = _sync("extensiveCalls", config, _EXTENSIVE_MOCK)
    assert [record["id"] for record in records] == ["c1"]
    assert "metaData" not in records[0]

    calls_mock = {
        ("get", "https://api.gong.io/v2/calls"): _page(
            "calls",
            {"id": "c1", "started": "2024-01-02T10:00:00Z", "isPrivate": False, "title": "public"},
            {"id": "c2", "started": "2024-01-02T11:00:00Z", "isPrivate": True, "title": "private"},
        )
    }
    assert _sync("calls", config, calls_mock) == [{"id": "c1", "started": "2024-01-02T10:00:00Z", "title": "public"}]


def test_call_transcripts_are_redacted_and_keep_their_keys():
    config = _config(
        {"action": "redact_text", "paths": ["transcript.sentences.text"]},
        {"action": "remove", "paths": ["*"], "streams": ["callTranscripts"]},  # protected fields survive
        {"action": "keep", "paths": ["transcript"], "streams": ["callTranscripts"]},
    )
    mocks = {
        ("get", "https://api.gong.io/v2/calls"): _page("calls", {"id": "c1", "started": "2024-01-02T10:00:00Z", "isPrivate": False}),
        ("post", "https://api.gong.io/v2/calls/transcript"): _page(
            "callTranscripts",
            {
                "callId": "c1",
                "transcript": [{"speakerId": "s1", "sentences": [{"start": 0, "end": 900, "text": "reach me at +33 6 12 34 56 78"}]}],
            },
        ),
    }
    # `keep` only restricts what is emitted; destructive rules still apply on top of it.
    assert _sync("callTranscripts", config, mocks) == [{"callId": "c1", "started": "2024-01-02T10:00:00Z"}]

    config["pii_redaction"]["rules"].pop(1)
    [transcript] = _sync("callTranscripts", config, mocks)
    assert transcript["transcript"][0]["sentences"][0]["text"] == "reach me at [PHONE]"


def test_discovered_schemas_reflect_the_rules():
    config = _config(
        {"action": "remove", "paths": ["media", "parties.phoneNumber"], "streams": ["extensiveCalls"]},
        {"action": "hash", "paths": ["parties.speakerId"]},
        {"action": "keep", "paths": ["emailAddress", "active"], "streams": ["users"]},
    )
    output = discover(get_source(config=config), config)
    assert not output.errors
    schemas = {stream.name: stream.json_schema for stream in output.catalog.catalog.streams}

    extensive = schemas["extensiveCalls"]["properties"]
    assert "media" not in extensive
    assert "phoneNumber" not in extensive["parties"]["items"]["properties"]
    assert extensive["parties"]["items"]["properties"]["speakerId"]["type"] == ["null", "string"]
    assert set(schemas["users"]["properties"]) == {"id", "emailAddress", "active"}
    assert "media" in _MANIFEST["schemas"]["extensiveCalls"]["properties"]


def test_check_reports_invalid_pii_config_as_config_error():
    config = {**_BASE_CONFIG, "pii_redaction": {"rules": [{"action": "hash", "paths": ["emailAddress"]}]}}
    with requests_mock.Mocker() as mocker:
        mocker.get("https://api.gong.io/v2/users", json=_page("users", _USER))
        try:
            status = get_source(config=config).check(logging.getLogger("airbyte"), config)
        except AirbyteTracedException as error:
            assert error.failure_type == FailureType.config_error
            assert "hash_key" in error.message
        else:
            assert status.status == Status.FAILED
            assert "hash_key" in status.message
