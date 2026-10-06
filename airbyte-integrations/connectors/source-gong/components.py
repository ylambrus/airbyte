#
# Copyright (c) 2026 Airbyte, Inc., all rights reserved.
#

"""Configurable PII redaction for `source-gong`.

Every stream runs `PiiRedactionTransformation` as its last record transformation and wraps its
schema loader in `PiiRedactionSchemaLoader`. Both read the `pii_redaction` section of the
connector config, so personal data is removed or pseudonymized before records leave the
connector, and the discovered schema matches what is actually emitted.

Rules address fields with dotted paths:

- `parties.emailAddress`: a nested key. Arrays are traversed transparently, so this matches the
  `emailAddress` of every element of the `parties` array.
- `parties[*].emailAddress`, `parties.*.emailAddress`: the same, with an explicit array wildcard.
- `parties[0].emailAddress`: only the first element.
- `**.emailAddress`: an `emailAddress` key at any depth, including the top level.
- `*Address`, `email*`: glob patterns on key names (`*`, `?` and `[...]`, case-sensitive).
- `a\\.b`: a literal dot inside a key name.

Supported actions, from strongest to weakest: `remove`, `nullify`, `mask`, `hash` (HMAC-SHA256),
`redact_text` (pattern-based scrubbing inside strings), plus `keep`, which switches a stream to
allowlist mode where only the kept paths survive. When several rules hit the same value, the
strongest action wins. Primary key and cursor fields are never modified, because doing so would
break deduplication and incremental syncs.
"""

import copy
import fnmatch
import hashlib
import hmac
import json
import logging
import re
from dataclasses import InitVar, dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple, Union

from airbyte_cdk.models import FailureType
from airbyte_cdk.sources.declarative.schema.schema_loader import SchemaLoader
from airbyte_cdk.sources.declarative.transformations.transformation import RecordTransformation
from airbyte_cdk.sources.types import Config, StreamSlice, StreamState
from airbyte_cdk.utils.traced_exception import AirbyteTracedException


logger = logging.getLogger("airbyte")

CONFIG_KEY = "pii_redaction"
DEFAULT_MASK_VALUE = "[REDACTED]"
MIN_HASH_KEY_LENGTH = 16

KEEP = "keep"
# Destructive actions ranked from weakest to strongest: when several rules hit the same value,
# the strongest one wins so that overlapping rules can only make the output more private.
ACTION_STRENGTH = {"redact_text": 1, "hash": 2, "mask": 3, "nullify": 4, "remove": 5}
ACTIONS = (KEEP, *ACTION_STRENGTH)
# Actions applied to every scalar leaf under the targeted value, preserving the JSON structure.
LEAF_ACTIONS = frozenset({"redact_text", "hash", "mask"})

Container = Union[Dict[str, Any], List[Any]]
Edge = Tuple[int, Any]  # (id(container), key or index): identifies one value slot in a document


def _config_error(message: str) -> AirbyteTracedException:
    return AirbyteTracedException(message=message, internal_message=message, failure_type=FailureType.config_error)


# ---------------------------------------------------------------------------------------------
# Path parsing
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Key:
    pattern: str
    is_glob: bool

    @property
    def is_wildcard(self) -> bool:
        return self.pattern == "*"

    def matches(self, key: Any) -> bool:
        if not isinstance(key, str):
            return False
        return fnmatch.fnmatchcase(key, self.pattern) if self.is_glob else key == self.pattern


@dataclass(frozen=True)
class _Index:
    index: Optional[int]  # None selects every element


class _DeepWildcard:
    def __repr__(self) -> str:
        return "**"


DEEP = _DeepWildcard()
Segment = Union[_Key, _Index, _DeepWildcard]

_BRACKETS_SUFFIX = re.compile(r"(?:\[(?:\*|\d*)\])+$")
_BRACKET = re.compile(r"\[(\*|\d*)\]")


def _split_unescaped_dots(path: str) -> List[str]:
    pieces, current, index = [], [], 0
    while index < len(path):
        char = path[index]
        if char == "\\" and index + 1 < len(path) and path[index + 1] == ".":
            current.append(".")
            index += 2
            continue
        if char == ".":
            pieces.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    pieces.append("".join(current))
    return pieces


def parse_path(path: str) -> Tuple[Segment, ...]:
    """Parse a dotted field path into segments. Raises `ValueError` on invalid syntax."""
    if not isinstance(path, str) or not path.strip():
        raise ValueError("the path is empty")
    path = path.strip()
    if path.startswith("$."):  # tolerate JSONPath-style roots instead of silently matching nothing
        path = path[2:]
    if path.startswith("/"):
        raise ValueError("JSON Pointer syntax is not supported, use dotted paths such as `parties.emailAddress`")

    segments: List[Segment] = []
    for piece in _split_unescaped_dots(path):
        if piece == "":
            raise ValueError("the path contains an empty segment (check for leading, trailing or doubled dots)")
        if piece == "**":
            if not segments or segments[-1] is not DEEP:
                segments.append(DEEP)
            continue
        brackets = _BRACKETS_SUFFIX.search(piece)
        base = piece[: brackets.start()] if brackets else piece
        if base:
            segments.append(_Key(pattern=base, is_glob=any(char in base for char in "*?[")))
        if brackets:
            for selector in _BRACKET.findall(brackets.group(0)):
                segments.append(_Index(index=int(selector) if selector.isdigit() else None))

    if segments[-1] is DEEP:
        raise ValueError("a path cannot end with `**`; target a key instead, for example `**.emailAddress`")
    return tuple(segments)


# ---------------------------------------------------------------------------------------------
# Path matching
# ---------------------------------------------------------------------------------------------

HitCallback = Callable[[Container, Any, Tuple[Tuple[Container, Any], ...]], None]


def _children(node: Container) -> Iterator[Tuple[Any, Any]]:
    return iter(node.items()) if isinstance(node, dict) else enumerate(node)


def find_matches(root: Any, segments: Sequence[Segment], on_hit: HitCallback, track_trail: bool = False) -> None:
    """Call `on_hit(container, key, trail)` for every value slot matched by `segments`.

    A slot is reported as its parent container plus the key (dicts) or index (lists) holding it,
    so callers can replace or delete it. `trail` lists the (container, key) edges from the root
    down to the container and is only computed when `track_trail` is set. The same slot can be
    reported more than once when a path contains `**`; callers deduplicate by edge.
    """
    last = len(segments) - 1

    def descend(trail: Optional[Tuple], container: Container, key: Any) -> Optional[Tuple]:
        return trail + ((container, key),) if track_trail else trail

    def visit(node: Container, position: int, trail: Tuple) -> None:
        segment = segments[position]
        if segment is DEEP:
            following = segments[position + 1]
            # On a list, a plain key segment would be applied to each element anyway, which the
            # recursion below already does: skip the zero-level match to avoid duplicate work.
            if not (isinstance(node, list) and isinstance(following, _Key) and not following.is_wildcard):
                visit(node, position + 1, trail)
            for key, child in _children(node):
                if isinstance(child, (dict, list)):
                    visit(child, position, descend(trail, node, key))
            return

        if isinstance(node, list):
            if isinstance(segment, _Index) or segment.is_wildcard:
                if isinstance(segment, _Index) and segment.index is not None:
                    indexes = [segment.index] if segment.index < len(node) else []
                else:
                    indexes = range(len(node))
                for index in indexes:
                    step(node, index, position, trail)
            else:
                # Arrays are transparent to key segments: apply the segment to each element.
                for index, child in enumerate(node):
                    if isinstance(child, (dict, list)):
                        visit(child, position, descend(trail, node, index))
            return

        if isinstance(segment, _Key):
            if segment.is_glob:
                for key in [key for key in node if segment.matches(key)]:
                    step(node, key, position, trail)
            elif segment.pattern in node:
                step(node, segment.pattern, position, trail)

    def step(container: Container, key: Any, position: int, trail: Tuple) -> None:
        if position == last:
            on_hit(container, key, trail)
            return
        child = container[key]
        if isinstance(child, (dict, list)):
            visit(child, position + 1, descend(trail, container, key))

    if isinstance(root, (dict, list)) and segments:
        visit(root, 0, ())


def unique_matches(root: Any, segments: Sequence[Segment]) -> List[Tuple[Container, Any]]:
    """Return the (container, key) slots matched by `segments`, each slot once."""
    hits: Dict[Edge, Tuple[Container, Any]] = {}
    find_matches(root, segments, lambda container, key, _: hits.setdefault((id(container), key), (container, key)))
    return list(hits.values())


def _iter_leaves(container: Container, key: Any) -> Iterator[Tuple[Container, Any]]:
    value = container[key]
    if isinstance(value, (dict, list)):
        for child_key, _ in _children(value):
            yield from _iter_leaves(value, child_key)
    else:
        yield container, key


# ---------------------------------------------------------------------------------------------
# Text detectors
# ---------------------------------------------------------------------------------------------


def _luhn_is_valid(candidate: str) -> bool:
    digits = [int(char) for char in candidate if char.isdigit()]
    if not 13 <= len(digits) <= 16:
        return False
    checksum = 0
    for position, digit in enumerate(reversed(digits)):
        if position % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _iban_is_valid(candidate: str) -> bool:
    compact = candidate.replace(" ", "")
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    return int("".join(str(int(char, 36)) for char in rearranged)) % 97 == 1


def _phone_is_valid(candidate: str) -> bool:
    digits = sum(char.isdigit() for char in candidate)
    international = candidate.startswith("+") or candidate.startswith("00")
    return (8 if international else 9) <= digits <= 15


@dataclass(frozen=True)
class _Detector:
    name: str
    pattern: "re.Pattern[str]"
    replacement: str
    validate: Optional[Callable[[str], bool]] = None
    # Cheap substring that must be present for the pattern to match at all; avoids running the
    # regex on the vast majority of strings.
    requires: Optional[str] = None

    def redact(self, text: str) -> str:
        if self.requires is not None and self.requires not in text:
            return text
        if self.validate is None:
            return self.pattern.sub(self.replacement, text)
        validate = self.validate
        return self.pattern.sub(lambda match: self.replacement if validate(match.group(0)) else match.group(0), text)


# Ordered so that more specific detectors run first: an IBAN or a card number must not be
# partially consumed by the phone detector, and an IPv4 address looks like a dotted number.
BUILTIN_DETECTORS: Dict[str, _Detector] = {
    detector.name: detector
    for detector in (
        _Detector(
            name="email",
            # The lookbehind only lets a match start at the beginning of a run of local-part
            # characters, which keeps matching linear on long runs that contain no `@`.
            pattern=re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}"),
            replacement="[EMAIL]",
            requires="@",
        ),
        _Detector(
            name="iban",
            pattern=re.compile(r"(?<![\w])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![\w])"),
            replacement="[IBAN]",
            validate=_iban_is_valid,
        ),
        _Detector(
            name="credit_card",
            # 13 to 16 digits: longer runs are left to the phone detector because Gong call ids are
            # 18-19 digit numbers and one in ten of them passes the Luhn check.
            pattern=re.compile(r"(?<![\w.\-])\d(?:[ \-]?\d){12,15}(?![\w])"),
            replacement="[CREDIT_CARD]",
            validate=_luhn_is_valid,
        ),
        _Detector(
            name="ip_address",
            pattern=re.compile(r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\w|\.\d)"),
            replacement="[IP_ADDRESS]",
        ),
        _Detector(
            name="phone",
            # Digit groups joined by single separators, with balanced parenthesized groups such as
            # `(555) 123-4567` or `+33 (0)6 12 34 56 78`. Plain digit groups always need a separator
            # between them, so a digit run can only be split one way and matching stays linear.
            pattern=re.compile(
                r"(?<![\w+.\-])\+?(?:\(\d+\)[ .\-\u00a0]?)?\d+" r"(?:[ .\-\u00a0]\d+|[ .\-\u00a0]?\(\d+\)[ .\-\u00a0]?\d+)*(?!\w)"
            ),
            replacement="[PHONE]",
            validate=_phone_is_valid,
        ),
    )
}


# ---------------------------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Rule:
    number: int  # 1-based position in the config, used in log and error messages
    action: str
    paths: Tuple[Tuple[str, Tuple[Segment, ...]], ...]  # (as configured, parsed)
    streams: Tuple[str, ...]
    detectors: Tuple[_Detector, ...] = ()


@dataclass
class _Planned:
    container: Container
    key: Any
    action: str
    detectors: List[_Detector] = field(default_factory=list)


def _as_string_list(value: Any, what: str, rule_number: int) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _config_error(f"PII redaction rule #{rule_number}: `{what}` must be a list of strings.")
    return value


def _parse_rule(number: int, raw: Any, mask_value: str) -> _Rule:
    if not isinstance(raw, Mapping):
        raise _config_error(f"PII redaction rule #{number} must be an object with `paths` and `action`.")

    action = raw.get("action")
    if action not in ACTIONS:
        raise _config_error(f"PII redaction rule #{number}: unknown action {action!r}. Valid actions are: {', '.join(ACTIONS)}.")

    raw_paths = _as_string_list(raw.get("paths"), "paths", number)
    if not raw_paths:
        raise _config_error(f"PII redaction rule #{number} has no `paths`.")
    paths = []
    for raw_path in raw_paths:
        try:
            paths.append((raw_path, parse_path(raw_path)))
        except ValueError as error:
            raise _config_error(f"PII redaction rule #{number}: invalid path {raw_path!r}: {error}.") from error

    detectors: List[_Detector] = []
    if action == "redact_text":
        names = _as_string_list(raw.get("detectors"), "detectors", number) or list(BUILTIN_DETECTORS)
        unknown = [name for name in names if name not in BUILTIN_DETECTORS]
        if unknown:
            raise _config_error(
                f"PII redaction rule #{number}: unknown detector(s) {', '.join(unknown)}. "
                f"Valid detectors are: {', '.join(BUILTIN_DETECTORS)}."
            )
        detectors = [detector for name, detector in BUILTIN_DETECTORS.items() if name in names]
        for pattern in _as_string_list(raw.get("custom_patterns"), "custom_patterns", number):
            try:
                compiled = re.compile(pattern)
            except re.error as error:
                raise _config_error(f"PII redaction rule #{number}: invalid custom pattern {pattern!r}: {error}.") from error
            detectors.append(_Detector(name=f"custom:{pattern}", pattern=compiled, replacement=mask_value))
    elif raw.get("custom_patterns") or raw.get("detectors"):
        logger.warning(f"PII redaction rule #{number}: `detectors` and `custom_patterns` only apply to `redact_text` and are ignored.")

    streams = _as_string_list(raw.get("streams"), "streams", number)
    return _Rule(number=number, action=action, paths=tuple(paths), streams=tuple(streams), detectors=tuple(detectors))


def _canonical_text(value: Any) -> str:
    if isinstance(value, str):
        # Normalized so that the same email or name hashes identically across streams and casings.
        return value.strip().lower()
    return json.dumps(value, sort_keys=True, default=str)


class RedactionPolicy:
    """The `pii_redaction` rules that apply to one stream, ready to run on records and schemas."""

    def __init__(
        self,
        stream_name: str,
        protected_fields: Sequence[str],
        rules: Sequence[_Rule],
        hash_key: Optional[bytes],
        mask_value: str,
    ) -> None:
        self.stream_name = stream_name
        self.protected_fields = frozenset(protected_fields)
        self.rules = tuple(rules)
        self.keep_rules = tuple(rule for rule in self.rules if rule.action == KEEP)
        self.deny_rules = tuple(rule for rule in self.rules if rule.action != KEEP)
        self._hash_key = hash_key
        self._mask_value = mask_value
        self._warned: Set[Tuple[int, str, str]] = set()

    @classmethod
    def from_config(cls, config: Optional[Mapping[str, Any]], stream_name: Any, protected_fields: Any) -> "RedactionPolicy":
        if not isinstance(stream_name, str) or not stream_name:
            raise ValueError("PII redaction components need a `pii_stream_name` parameter naming their stream.")
        protected = list(protected_fields or [])

        section = (config or {}).get(CONFIG_KEY) or {}
        if not isinstance(section, Mapping):
            raise _config_error("`pii_redaction` must be an object.")
        raw_rules = section.get("rules") or []
        if not isinstance(raw_rules, list):
            raise _config_error("`pii_redaction.rules` must be a list.")
        mask_value = section.get("mask_value")
        mask_value = DEFAULT_MASK_VALUE if mask_value is None else str(mask_value)

        rules = [_parse_rule(number, raw_rule, mask_value) for number, raw_rule in enumerate(raw_rules, start=1)]

        # Validate the hash key against every rule, not only this stream's rules, so a missing key
        # fails the connection check instead of the first sync of the affected stream.
        hash_key = section.get("hash_key") or None
        hash_rules = [rule.number for rule in rules if rule.action == "hash"]
        if hash_rules:
            if not isinstance(hash_key, str) or len(hash_key) < MIN_HASH_KEY_LENGTH:
                raise _config_error(
                    f"PII redaction rule(s) #{', #'.join(map(str, hash_rules))} use the `hash` action, which requires "
                    f"`pii_redaction.hash_key` to be set to a secret of at least {MIN_HASH_KEY_LENGTH} characters."
                )

        applicable = [rule for rule in rules if not rule.streams or stream_name in rule.streams]
        return cls(
            stream_name=stream_name,
            protected_fields=protected,
            rules=applicable,
            hash_key=hash_key.encode("utf-8") if isinstance(hash_key, str) else None,
            mask_value=mask_value,
        )

    def describe(self) -> str:
        if not self.rules:
            return "no rules, records are emitted unchanged"
        return "; ".join(f"#{rule.number} {rule.action} {', '.join(raw for raw, _ in rule.paths)}" for rule in self.rules)

    # -- planning -----------------------------------------------------------------------------

    def _is_protected(self, root: Any, container: Container, key: Any, rule: _Rule, raw_path: str) -> bool:
        if container is not root or key not in self.protected_fields:
            return False
        warning = (rule.number, raw_path, key)
        if warning not in self._warned:
            self._warned.add(warning)
            logger.warning(
                f"PII redaction rule #{rule.number} path `{raw_path}` matches `{key}`, a primary key or cursor field of stream "
                f"`{self.stream_name}`. It is left untouched because modifying it would break deduplication and incremental syncs."
            )
        return True

    def _allowlist_edges(self, root: Any) -> Tuple[Set[Edge], Set[Edge]]:
        """Return the slots kept by `keep` rules and the slots of their ancestors."""
        kept: Set[Edge] = {(id(root), key) for key in self.protected_fields if isinstance(root, dict) and key in root}
        ancestors: Set[Edge] = set()

        def on_hit(container: Container, key: Any, trail: Tuple) -> None:
            kept.add((id(container), key))
            ancestors.update((id(parent), parent_key) for parent, parent_key in trail)

        for rule in self.keep_rules:
            for _, segments in rule.paths:
                find_matches(root, segments, on_hit, track_trail=True)
        return kept, ancestors

    def _plan(self, root: Any) -> Dict[Edge, _Planned]:
        plan: Dict[Edge, _Planned] = {}

        def add(container: Container, key: Any, rule: _Rule) -> None:
            edge = (id(container), key)
            current = plan.get(edge)
            if current is None or ACTION_STRENGTH[rule.action] > ACTION_STRENGTH[current.action]:
                plan[edge] = _Planned(container, key, rule.action, list(rule.detectors))
            elif current.action == "redact_text" and rule.action == "redact_text":
                current.detectors.extend(detector for detector in rule.detectors if detector not in current.detectors)

        for rule in self.deny_rules:
            for raw_path, segments in rule.paths:
                for container, key in unique_matches(root, segments):
                    if self._is_protected(root, container, key, rule, raw_path):
                        continue
                    if rule.action in LEAF_ACTIONS:
                        for leaf_container, leaf_key in _iter_leaves(container, key):
                            add(leaf_container, leaf_key, rule)
                    else:
                        add(container, key, rule)
        return plan

    # -- records ------------------------------------------------------------------------------

    def apply(self, record: MutableMapping[str, Any]) -> None:
        """Redact `record` in place."""
        if self.keep_rules:
            kept, ancestors = self._allowlist_edges(record)
            _prune(record, kept, ancestors)
        if not self.deny_rules:
            return

        list_removals: Dict[int, Tuple[List[Any], List[int]]] = {}
        dict_removals: List[_Planned] = []
        for planned in self._plan(record).values():
            if planned.action == "remove":
                if isinstance(planned.container, dict):
                    dict_removals.append(planned)
                else:
                    list_removals.setdefault(id(planned.container), (planned.container, []))[1].append(planned.key)
            elif planned.action == "nullify":
                planned.container[planned.key] = None
            else:
                planned.container[planned.key] = self._transform_leaf(planned, planned.container[planned.key])

        # Removals run last so that list indexes recorded in the plan stay valid until then.
        for planned in dict_removals:
            planned.container.pop(planned.key, None)
        for container, indexes in list_removals.values():
            for index in sorted(indexes, reverse=True):
                del container[index]

    def _transform_leaf(self, planned: _Planned, value: Any) -> Any:
        if value is None:
            return None
        if planned.action == "mask":
            return self._mask_value
        if planned.action == "hash":
            return hmac.new(self._hash_key, _canonical_text(value).encode("utf-8"), hashlib.sha256).hexdigest()
        if isinstance(value, str):  # redact_text only rewrites strings
            for detector in planned.detectors:
                value = detector.redact(value)
        return value

    # -- schemas ------------------------------------------------------------------------------

    def adapt_schema(self, schema: Mapping[str, Any]) -> Dict[str, Any]:
        """Return a copy of `schema` that describes the records this policy emits.

        The policy runs on a skeleton document built from the schema (one element per array, one
        key per declared property), so schema and records are always matched by the same code.
        Removed or non-kept properties disappear and hashed or masked scalars become strings.
        Fields that are not declared in the schema are still redacted in records.
        """
        adapted = copy.deepcopy(dict(schema))
        if not self.rules:
            return adapted

        registry: Dict[int, Tuple[Container, Dict[str, Any]]] = {}  # also keeps skeleton nodes alive
        skeleton = _skeleton(adapted, registry)
        if not isinstance(skeleton, dict):
            return adapted
        self.warn_on_unmatched_paths(skeleton)

        if self.keep_rules:
            kept, ancestors = self._allowlist_edges(skeleton)
            _prune(skeleton, kept, ancestors, registry)

        removals = []
        for planned in self._plan(skeleton).values():
            parent_schema = registry[id(planned.container)][1]
            if isinstance(planned.container, dict):
                subschema = parent_schema["properties"][planned.key]
            else:
                subschema = parent_schema["items"]
            if planned.action == "remove":
                if isinstance(planned.container, dict):
                    removals.append((parent_schema, planned.key))
            elif planned.action == "nullify":
                _make_nullable(subschema)
            elif planned.action in ("hash", "mask") and _is_scalar_schema(subschema):
                description = subschema.get("description")
                subschema.clear()
                subschema["type"] = ["null", "string"]
                if description:
                    subschema["description"] = description
        for parent_schema, key in removals:
            _drop_property(parent_schema, key)
        return adapted

    def warn_on_unmatched_paths(self, skeleton: Dict[str, Any]) -> None:
        """Warn about paths of rules scoped to this stream that match no declared field: likely typos."""
        for rule in self.rules:
            if self.stream_name not in rule.streams:
                continue
            for raw_path, segments in rule.paths:
                if not unique_matches(skeleton, segments):
                    logger.warning(
                        f"PII redaction rule #{rule.number} path `{raw_path}` matches no field declared in the `{self.stream_name}` "
                        f"schema. Check it for typos; undeclared fields are still redacted when present in records."
                    )


def _prune(
    node: Container,
    kept: Set[Edge],
    ancestors: Set[Edge],
    registry: Optional[Dict[int, Tuple[Container, Dict[str, Any]]]] = None,
) -> None:
    """Delete everything under `node` that is neither kept nor on the way to a kept value.

    Container elements of arrays are always pruned rather than dropped, so arrays keep their length.
    When `registry` is given, `node` is a schema skeleton and the matching schema properties are deleted too.
    """
    if isinstance(node, dict):
        for key in list(node):
            edge = (id(node), key)
            if edge in kept:
                continue
            if edge in ancestors and isinstance(node[key], (dict, list)):
                _prune(node[key], kept, ancestors, registry)
                continue
            del node[key]
            if registry is not None:
                _drop_property(registry[id(node)][1], key)
    else:
        survivors = []
        for index, child in enumerate(node):
            if (id(node), index) in kept:
                survivors.append(child)
            elif isinstance(child, (dict, list)):
                _prune(child, kept, ancestors, registry)
                survivors.append(child)
        node[:] = survivors


def _schema_types(schema: Mapping[str, Any]) -> Set[str]:
    types = schema.get("type")
    if isinstance(types, str):
        return {types}
    return set(types) if isinstance(types, list) else set()


def _skeleton(schema: Dict[str, Any], registry: Dict[int, Tuple[Container, Dict[str, Any]]]) -> Any:
    types = _schema_types(schema)
    properties = schema.get("properties")
    if isinstance(properties, dict) and (not types or "object" in types):
        node: Dict[str, Any] = {}
        registry[id(node)] = (node, schema)
        for key, subschema in properties.items():
            node[key] = _skeleton(subschema, registry) if isinstance(subschema, dict) else None
        return node
    items = schema.get("items")
    if isinstance(items, dict) and (not types or "array" in types):
        array = [_skeleton(items, registry)]
        registry[id(array)] = (array, schema)
        return array
    return None  # a leaf: the policy only needs its slot, not its value


def _is_scalar_schema(schema: Mapping[str, Any]) -> bool:
    types = _schema_types(schema) - {"null"}
    return bool(types) and types <= {"string", "number", "integer", "boolean"}


def _make_nullable(schema: Dict[str, Any]) -> None:
    types = schema.get("type")
    if isinstance(types, str) and types != "null":
        schema["type"] = ["null", types]
    elif isinstance(types, list) and "null" not in types:
        schema["type"] = ["null", *types]


def _drop_property(schema: Dict[str, Any], key: str) -> None:
    schema.get("properties", {}).pop(key, None)
    required = schema.get("required")
    if isinstance(required, list) and key in required:
        required.remove(key)


# ---------------------------------------------------------------------------------------------
# Declarative components
# ---------------------------------------------------------------------------------------------


@dataclass
class PiiRedactionTransformation(RecordTransformation):
    """Applies the `pii_redaction` config to each record of the stream named by `$parameters.pii_stream_name`.

    `$parameters.pii_protected_fields` lists the top-level fields (primary key, cursor) that rules must never modify.
    """

    config: Config
    parameters: InitVar[Mapping[str, Any]]

    def __post_init__(self, parameters: Mapping[str, Any]) -> None:
        self._policy = RedactionPolicy.from_config(self.config, parameters.get("pii_stream_name"), parameters.get("pii_protected_fields"))
        self._announced = False

    def transform(
        self,
        record: Dict[str, Any],
        config: Optional[Config] = None,
        stream_state: Optional[StreamState] = None,
        stream_slice: Optional[StreamSlice] = None,
    ) -> None:
        # Logged on the first record rather than at construction, so only synced streams report.
        if not self._announced:
            self._announced = True
            logger.info(f"PII redaction for stream `{self._policy.stream_name}`: {self._policy.describe()}")
        self._policy.apply(record)


@dataclass
class PiiRedactionSchemaLoader(SchemaLoader):
    """Wraps a schema loader and adapts its schema to the `pii_redaction` config, so discovery matches the emitted records."""

    schema_loader: SchemaLoader
    config: Config
    parameters: InitVar[Mapping[str, Any]]

    def __post_init__(self, parameters: Mapping[str, Any]) -> None:
        self._policy = RedactionPolicy.from_config(self.config, parameters.get("pii_stream_name"), parameters.get("pii_protected_fields"))
        self._schema: Optional[Mapping[str, Any]] = None

    def get_json_schema(self) -> Mapping[str, Any]:
        # The wrapped schema is static, so the adapted one is computed (and typos are reported) once.
        if self._schema is None:
            self._schema = self._policy.adapt_schema(self.schema_loader.get_json_schema())
        return self._schema
