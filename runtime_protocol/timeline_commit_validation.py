"""Validate detached commit values against the installed contract artifacts."""

from __future__ import annotations

import copy
import hashlib
import json
import math
from collections import OrderedDict
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
    validator = _reuse_schema_validators(Draft202012Validator)(
        {"$ref": bundle["root"] + "#/$defs/" + definition}, registry=registry
    )
    return validator.evolve(
        _resolver=_reuse_schema_resolution(_validator_resolver(validator))
    )


def _reuse_schema_validators(base):
    from threading import RLock

    from jsonschema.validators import extend

    validator = extend(base)
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
    if definition == _CANONICAL_DOCUMENT:
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
        else:
            compiled.validate(value)
    except SchemaValidationError as exc:
        raise ValidationError(f"invalid {definition}: {exc.message}") from exc
    except (Unresolvable, RecursionError) as exc:
        raise ValidationError(
            f"cannot validate {definition} against the installed contract"
        ) from exc
