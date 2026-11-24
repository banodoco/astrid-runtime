"""Validate detached commit values against the installed contract artifacts."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import sys
from collections import OrderedDict
from contextvars import ContextVar
from functools import cache, lru_cache
from importlib.resources import files
from threading import Lock
from typing import Protocol, cast

from ._timeline_reopen_diagnostics import count_reopen_work
from .contract_metadata import SCHEMA_DIGEST
from .errors import ValidationError
from .util import canonical_json

_CANONICAL_DOCUMENT = "CanonicalDocument"
_DOCUMENT_MEMO_LIMIT = 256
_document_memo = OrderedDict()
_document_memo_lock = Lock()

# Only the audited installed contract has the local, annotation-independent
# item references below. A regenerated bundle starts on the uncached path
# until its item schema closure is reviewed again.
_REVIEWED_CONTRACT = "sha256:2c6a76e17b4441398ab91e3e9d6283a719fd5b08807447db9dbf2ecc5e1339a2"
_REVIEWED_BUNDLE = "ce5490aedf1b2932f01219c0e317468ecf397cd9c1f715152faa62d3fa0694f2"
_SHOT_SCHEMA = "https://astrid.haus/workspace/v1/schemas/shot-composition.json"
_ITEM_LOCATIONS = (
    ("ParentComposition", "clips", "RawClip"),
    ("RawTimelinePayload", "clips", "RawClip"),
    ("RawTimelinePayload", "tracks", "RawTrack"),
)
_SUBTREE_DEPTH_LIMIT = 12
_SUBTREE_ENTRY_LIMIT = 4096
_SUBTREE_BYTES_LIMIT = 16 * 1024 * 1024
_SUBTREE_KEY_LIMIT = 128 * 1024
_prepared_memo_active = ContextVar("prepared_memo_active", default=False)


class _SubtreeMemo:
    """Bounded success-only LRU; no mutable instances or errors are retained."""

    def __init__(self, entries=_SUBTREE_ENTRY_LIMIT, size=_SUBTREE_BYTES_LIMIT,
                 key_size=_SUBTREE_KEY_LIMIT):
        self.entries = OrderedDict()
        self.size = 0
        self.entry_limit = entries
        self.byte_limit = size
        self.key_limit = key_size
        self.lock = Lock()

    def contains(self, key):
        with self.lock:
            if key not in self.entries:
                return False
            self.entries.move_to_end(key)
            return True

    def remember(self, key):
        size = len(key[1])
        if size > self.key_limit or size > self.byte_limit or self.entry_limit < 1:
            return
        with self.lock:
            if key in self.entries:
                self.entries.move_to_end(key)
                return
            self.entries[key] = None
            self.size += size
            while len(self.entries) > self.entry_limit or self.size > self.byte_limit:
                removed, _ = self.entries.popitem(last=False)
                self.size -= len(removed[1])


_prepared_subtrees = _SubtreeMemo()


def _subtree_bytes(instance):
    # finite_json has checked this privately captured graph. Bound the local
    # recursive schema depth before allowing a success to omit any traversal.
    pending = [(instance, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > _SUBTREE_DEPTH_LIMIT:
            return None
        if type(item) is dict or type(item) is list:
            children = item.values() if type(item) is dict else item
            pending.extend((child, depth + 1) for child in children
                           if type(child) is dict or type(child) is list)
    try:
        encoded = canonical_json(instance).encode()
    except (RecursionError, TypeError, ValueError):
        # In particular, a lone surrogate is valid in some schema positions
        # but cannot be encoded as strict UTF-8. Never infer a validation result.
        return None
    if len(encoded) > _prepared_subtrees.key_limit:
        return None
    return encoded


def _has_subtree_recursion_headroom():
    # A shallow subtree can still be evaluated from a nearly exhausted stack.
    # The three reference paths have fixed envelope depth; 512 frames is a
    # conservative allowance for them and twelve nested metadata containers.
    remaining = sys.getrecursionlimit()
    frame = sys._getframe()
    while frame is not None and remaining >= 512:
        remaining -= 1
        frame = frame.f_back
    return remaining >= 512


def _reviewed_item_nodes(bundle, registry):
    if SCHEMA_DIGEST != _REVIEWED_CONTRACT:
        return {}
    try:
        raw = files("runtime_protocol").joinpath(
            "schemas/timeline-commit-bundle.json"
        ).read_bytes()
    except OSError:
        return {}
    if hashlib.sha256(raw).hexdigest() != _REVIEWED_BUNDLE:
        return {}
    # Check the loaded generation as well as the installed bytes. Resource
    # contents are retained by the registry, not looked up by instance identity.
    if canonical_json(bundle) != canonical_json(json.loads(raw)):
        return {}
    for uri, resource in bundle["resources"].items():
        if canonical_json(registry.contents(uri)) != canonical_json(resource):
            return {}
    definitions = registry.contents(_SHOT_SCHEMA)["$defs"]
    generation = object()
    nodes = {}
    for parent, field, target in _ITEM_LOCATIONS:
        node = definitions[parent]["properties"][field]["items"]
        location = f"{_SHOT_SCHEMA}#/$defs/{parent}/properties/{field}/items"
        namespace = (generation, SCHEMA_DIGEST, _REVIEWED_BUNDLE, location, target)
        nodes[id(node)] = (node, definitions[target], namespace)
    return nodes


def _memoized_reference(original, nodes):
    from referencing.exceptions import Unresolvable

    def reference(validator, ref, instance, schema):
        if not _prepared_memo_active.get():
            return original(validator, ref, instance, schema)
        entry = nodes.get(id(schema))
        if entry is None or entry[0] is not schema:
            return original(validator, ref, instance, schema)
        # Match both the original item node and its resolved target. The
        # reviewed bundle has only static references in this closure.
        try:
            resolved = _validator_resolver(validator).lookup(ref)
        except Unresolvable:
            return original(validator, ref, instance, schema)
        if resolved.contents is not entry[1]:
            return original(validator, ref, instance, schema)
        encoded = _subtree_bytes(instance)
        if encoded is None:
            return original(validator, ref, instance, schema)
        memo = _prepared_subtrees
        key = (entry[2], encoded)
        if memo.contains(key):
            return ()
        return _remember_success(original(validator, ref, instance, schema), memo, key)

    return reference


def _remember_success(errors, memo, key):
    # Forward the original error iterator without changing its order or path.
    # A partial traversal, error or exception never publishes a success.
    failed = False
    for error in errors:
        failed = True
        yield error
    if not failed:
        memo.remember(key)


def finite_json(value) -> None:
    active = set()
    parents = []
    children = iter((value,))
    while True:
        for item in children:
            kind = type(item)
            if kind is str or kind is int or kind is bool or item is None:
                continue
            if kind is float and math.isfinite(item):
                continue
            if kind is not dict and kind is not list:
                raise ValidationError("commit value must contain only finite JSON")
            if id(item) in active:
                raise ValidationError("commit value must not contain cycles")
            if kind is dict and any(type(key) is not str for key in item):
                raise ValidationError("commit JSON object keys must be strings")
            active.add(id(item))
            # Keep only container frames; scalar children need no pending tuples.
            parents.append((item, children))
            # Capture sibling references when entering a container, matching
            # the eager pending stack without allocating one tuple per child.
            children = reversed(tuple(item.values() if kind is dict else item))
            break
        else:
            if not parents:
                return
            parent, children = parents.pop()
            active.remove(id(parent))


def _capture_json_containers(value):
    """Own the mutable containers while preserving raw types, aliases and cycles."""
    if type(value) is not dict and type(value) is not list:
        return value

    captured = value.copy()
    copies = {id(value): (value, captured)}
    pending = [captured]
    while pending:
        target = pending.pop()
        if type(target) is dict:
            # Let finite_json refuse invalid keys without looking them up.
            if any(type(key) is not str for key in target):
                continue
            keys = target
        else:
            keys = range(len(target))
        for key in keys:
            item = target[key]
            if type(item) is not dict and type(item) is not list:
                continue
            retained = copies.get(id(item))
            if retained is None:
                child = item.copy()
                # Keep the original alive while using its identity.
                copies[id(item)] = (item, child)
                pending.append(child)
            else:
                child = retained[1]
            target[key] = child
    return captured


def detached(value):
    finite_json(value)
    return copy.deepcopy(value)


def digest(value):
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()


class _ValidatorWithResolver(Protocol):
    _resolver: object


def _validator_resolver(validator):
    return cast(_ValidatorWithResolver, validator)._resolver


@cache
def _schema_resources():
    from referencing import Registry, Resource
    from referencing.exceptions import NoSuchResource
    from referencing.jsonschema import DRAFT202012

    def unavailable(uri):
        raise NoSuchResource(ref=uri)

    bundle = json.loads(
        files("runtime_protocol")
        .joinpath("schemas/timeline-commit-bundle.json")
        .read_text(encoding="utf-8")
    )
    registry = Registry(retrieve=unavailable)
    for uri, schema in bundle["resources"].items():
        resource = Resource.from_contents(
            copy.deepcopy(schema), default_specification=DRAFT202012
        )
        registry = registry.with_resource(uri, resource)
        if resource.id() is not None:
            registry = registry.with_resource(resource.id(), resource)
    return bundle, registry


@cache
def _validator(definition: str):
    from jsonschema import Draft202012Validator

    bundle, registry = _schema_resources()
    if definition not in bundle["resources"][bundle["root"]]["$defs"]:
        raise ValidationError("unknown commit schema definition")
    nodes = _reviewed_item_nodes(bundle, registry) if definition == "PreparedCommit" else {}
    validator = _reuse_schema_validators(Draft202012Validator, nodes)(
        {"$ref": bundle["root"] + "#/$defs/" + definition}, registry=registry
    )
    return validator.evolve(
        _resolver=_reuse_schema_resolution(_validator_resolver(validator))
    )


def _reuse_schema_validators(base, item_nodes=None):
    from threading import RLock

    from jsonschema.validators import extend

    keywords = {}
    if item_nodes:
        keywords["$ref"] = _memoized_reference(base.VALIDATORS["$ref"], item_nodes)
    validator = extend(base, validators=keywords)
    evolve = validator.evolve
    compiled = OrderedDict()
    lock = RLock()

    def reuse(self, **changes):
        if len(changes) != 2 or "schema" not in changes or "_resolver" not in changes:
            return evolve(self, **changes)
        schema, resolver = changes["schema"], changes["_resolver"]
        key = (id(self), id(schema), id(resolver))
        entry = compiled.get(key)
        if entry is not None:
            return entry[3]
        with lock:
            child = evolve(self, **changes)
            # Retain all identity-keyed objects until eviction. Only schema setup
            # is reused; validation still traverses each instance with fresh errors.
            compiled[key] = (self, schema, resolver, child)
            if len(compiled) > 256:
                compiled.popitem(last=False)
            return child

    validator.evolve = reuse
    return validator


def _reuse_schema_resolution(resolver):
    # Cache only schema lookups, keyed by the identity of the complete resolver
    # state (including registry, base URI and dynamic scope), never by a value.
    @lru_cache(maxsize=256)
    def lookup(state, ref):
        resolved = state.resolver.lookup(ref)
        return type(resolved)(resolved.contents, Resolver(resolved.resolver))

    class Resolver:
        def __init__(self, resolver):
            self.resolver = resolver

        def lookup(self, ref):
            return lookup(self, ref)

        def in_subresource(self, resource):
            child = self.resolver.in_subresource(resource)
            return self if child is self.resolver else Resolver(child)

        def dynamic_scope(self):
            return self.resolver.dynamic_scope()

    return Resolver(resolver)


def _validate_canonical_document(value, compiled):
    try:
        encoded = canonical_json(value).encode()
    except (RecursionError, TypeError, ValueError):
        # Some finite JSON accepted by the schema cannot be encoded here.
        count_reopen_work("document_schema_cache_misses")
        compiled.validate(value)
        return

    key = (SCHEMA_DIGEST, _CANONICAL_DOCUMENT, id(compiled), hashlib.sha256(encoded).digest())
    with _document_memo_lock:
        if _document_memo.get(key) is compiled:
            _document_memo.move_to_end(key)
            count_reopen_work("document_schema_cache_hits")
            return

    count_reopen_work("document_schema_cache_misses")
    compiled.validate(value)
    with _document_memo_lock:
        # Only successful checks enter the memo. Keep the validator alive while
        # its identity is part of the key so Python cannot recycle that identity.
        _document_memo[key] = compiled
        _document_memo.move_to_end(key)
        if len(_document_memo) > _DOCUMENT_MEMO_LIMIT:
            _document_memo.popitem(last=False)
            count_reopen_work("document_schema_cache_evictions")


def validate_commit_value(value, definition: str) -> None:
    """Raise Runtime ValidationError without changing the submitted JSON value.

    Schema dependencies are loaded only when validation is requested; importing
    this module or the provider ABI requires only the standard library.
    """
    if definition in (_CANONICAL_DOCUMENT, "PreparedCommit"):
        # Run the ordinary finite/raw guard on the same owned snapshot used
        # for the memo key and for schema validation.
        value = _capture_json_containers(value)
    finite_json(value)
    from jsonschema.exceptions import ValidationError as SchemaValidationError
    from referencing.exceptions import Unresolvable

    try:
        compiled = _validator(definition)
        if definition == _CANONICAL_DOCUMENT:
            _validate_canonical_document(value, compiled)
        elif definition == "PreparedCommit":
            token = _prepared_memo_active.set(_has_subtree_recursion_headroom())
            try:
                compiled.validate(value)
            finally:
                _prepared_memo_active.reset(token)
        else:
            compiled.validate(value)
    except SchemaValidationError as exc:
        raise ValidationError(f"invalid {definition}: {exc.message}") from exc
    except (Unresolvable, RecursionError) as exc:
        raise ValidationError(
            f"cannot validate {definition} against the installed contract"
        ) from exc
