"""Pinned canonical v33 structural fingerprints.

This module only inspects an already-open SQLite connection. It does not supply
WAL-safe detached observation, locking, data validation, or migration.
Callers must not treat it alone as an authorization to mutate a realm.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3

from .errors import ValidationError

_FORMAT = "astrid-runtime-sqlite-v1"
# Approved I-RT-01c Appendix A.2; C24-C27 each permit both spec profiles.
_FINGERPRINTS = {
    "V34": "8198adec85559f9208729c41b359c407d82fa68846f60888838eb243247ee51f",
    "C24": "d91108a71b88326707421fa36420f9f0c1a1067a5c36ff10889066c244bdb80a",
    "C24-nullable": "ed80756a94630bb4359496008578bd51436164107ba2d9caeee2b5b4fd168bac",
    "C25": "15eda06ce52e720a83629760f6c613170425beab0dd431445cec33f68d5e62f1",
    "C25-nullable": "02aa1b55f25d91543eff828e50f259e82c16ec5c548f6bd11dc6f6ec9cc8e9d9",
    "C26": "bcba25e75edb44f2e1c89a72d2fe2946cebdafb528c7c81d31bddf99f66c799e",
    "C26-nullable": "c522c90bae032cf2cfa769a1d358c4312140e69b447a841f7586a8578d713b34",
    "C27": "36ae4b9f9481b9a9227ce4cc081c44936a2b0766e799e65b3f6f7ded82498d7f",
    "C27-nullable": "f8bac0ffe53c5b42dc91d0b76821dafd468ad71b27d5ebe7d2444aef23385be6",
    "C28": "cb03be6e9d9f3c1c6923a5a8b5add1ca33156ac8490f412b03d56bbc93a327d7",
    "C29": "02a657c173dddf2a9ddc71ae79a25c3d3ffa0c390d92c002eb77d34c33cb107e",
    "C30": "6d17c99f837b249d0348ec21bee93fb7e3dbe63bd9f17f73e444269e361d7be4",
    "C31": "63fa7954507badb65757a216c17009431ef7df8e2b5830aff1e24897f9870563",
    "H31": "30234262d5ccc9f13cfb086234e9f33b6e97670825ddfbda826863802ccc84c0",
    "M32": "2fbfee0b6c85f60eca2412192b8d518c9e178c457af39649c86881e1904d0f7b",
    "TL32": "1bda1a5cd7f3051a23ed84d5ad5ac97edcd9385cf34fa4dbeb6baea84b21220d",
    "U33": "6ed4d1f145aa5fd8d9691b8b7d072f4e176ad857d4dda586f72b4a64c0e09ff3",
}
_TOKEN = re.compile(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|[A-Za-z_][A-Za-z_0-9]*|[0-9]+|<>|!=|<=|>=|[^\s]")


def _tokens(sql: str) -> list[str]:
    result = []
    for token in _TOKEN.findall(sql.strip().rstrip(";")):
        if token.startswith('"'):
            token = token[1:-1].replace('""', '"')
        result.append(token if token.startswith("'") else token.lower())
    return result


def _table_definition(sql: str) -> dict:
    tokens = _tokens(sql)
    try:
        start = tokens.index("(")
        depth = 0
        parts: list[list[str]] = []
        part: list[str] = []
        end = None
        for i in range(start + 1, len(tokens)):
            token = tokens[i]
            if token == ")" and depth == 0:
                if part:
                    parts.append(part)
                end = i
                break
            if token == "," and depth == 0:
                if not part:
                    raise ValueError("empty table element")
                parts.append(part)
                part = []
                continue
            part.append(token)
            if token == "(":
                depth += 1
            elif token == ")":
                depth -= 1
        if end is None or not parts:
            raise ValueError("unbalanced table definition")
        columns, constraints = [], []
        for part in parts:
            if part[0] in {"primary", "foreign", "unique", "check", "constraint"}:
                constraints.append(" ".join(part))
            else:
                columns.append([part[0], " ".join(part[1:])])
        return {"columns": sorted(columns), "constraints": sorted(constraints), "suffix": tokens[end + 1:]}
    except (ValueError, IndexError) as exc:
        raise ValidationError("unsupported SQLite table definition") from exc


def canonical_manifest(connection: sqlite3.Connection, *, expected_realm_id: str | None = None) -> dict:
    """Classify the exact canonical schema on a caller-owned observation.

    Raises ValidationError for unknown inventories and hybrids. This function is
    The caller must supply detached observation and lifecycle fencing.
    """
    try:
        schema_rows = connection.execute("SELECT id, format_id, version FROM runtime_schema").fetchall()
        if (len(schema_rows) != 1 or type(schema_rows[0][0]) is not int or schema_rows[0][0] != 1
                or schema_rows[0][1] != _FORMAT or type(schema_rows[0][2]) is not int):
            raise ValidationError("invalid canonical schema identity")
        version = schema_rows[0][2]
        realm_rows = connection.execute("SELECT id FROM realm").fetchall()
        if (len(realm_rows) != 1 or not isinstance(realm_rows[0][0], str)
                or not realm_rows[0][0].strip()):
            raise ValidationError("invalid realm identity")
        realm_id = realm_rows[0][0]
        if expected_realm_id is not None and realm_id != expected_realm_id:
            raise ValidationError("realm identity mismatch")
        objects = _objects(connection)
        data = {"format_id": _FORMAT, "version": version, "objects": objects}
        fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        family = next((key for key, value in _FINGERPRINTS.items() if value == fingerprint), None)
        if family is None:
            raise ValidationError(f"unsupported canonical v{version} manifest")
        return {"format_id": _FORMAT, "version": version, "kind": family,
                "realm_id": realm_id, "fingerprint": fingerprint}
    except sqlite3.DatabaseError as exc:
        raise ValidationError("cannot inspect canonical SQLite manifest") from exc


def _objects(connection: sqlite3.Connection) -> dict:
    objects = {}
    rows = connection.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY name").fetchall()
    for kind, name, owner, sql in rows:
        if name in {"sqlite_sequence", "sqlite_stat1", "sqlite_stat2", "sqlite_stat3", "sqlite_stat4"} and kind == "table":
            continue
        if name.startswith("sqlite_autoindex_") and kind == "index" and sql is None:
            quoted = '"' + owner.replace('"', '""') + '"'
            indexes = list(connection.execute(f"PRAGMA index_list({quoted})"))
            if not any(row[1] == name and row[2] == 1 and row[3] in ("u", "pk") for row in indexes):
                raise ValidationError("invalid SQLite automatic index")
            continue
        if name.startswith("sqlite_") or kind not in ("table", "index") or not isinstance(sql, str):
            raise ValidationError("unsupported SQLite schema object")
        quoted = '"' + name.replace('"', '""') + '"'
        if kind == "table":
            if _tokens(sql)[:2] != ["create", "table"]:
                raise ValidationError("virtual or unsupported table")
            columns = list(connection.execute(f"PRAGMA table_xinfo({quoted})"))
            if not columns or any(row[6] != 0 for row in columns):
                raise ValidationError("hidden or generated SQLite column")
        else:
            quoted_owner = '"' + owner.replace('"', '""') + '"'
            indexes = list(connection.execute(f"PRAGMA index_list({quoted_owner})"))
            if not any(row[1] == name and row[3] == "c" for row in indexes):
                raise ValidationError("invalid SQLite explicit index")
            if not list(connection.execute(f"PRAGMA index_xinfo({quoted})")):
                raise ValidationError("missing SQLite index metadata")
        objects[name] = {"type": kind, "owner": owner,
                         "definition": _table_definition(sql) if kind == "table" else " ".join(_tokens(sql))}
    return objects


def legacy_manifest(connection: sqlite3.Connection, *, expected_realm_id: str | None = None) -> dict:
    """Classify pinned v23 object combinations without validating their data.

    Callers still need the detached observation and complete v23 copy/closure
    checks. Definitions absent from the approved extractor are refused.
    """
    from .v33_legacy_manifests import BASES, COMPONENTS

    try:
        objects = _objects(connection)
        rows = connection.execute("SELECT version FROM schema_migrations").fetchall()
        if not rows or any(type(row[0]) is not int for row in rows) or max(row[0] for row in rows) != 23:
            raise ValidationError("invalid legacy migration identity")
        realms = connection.execute("SELECT id FROM realm").fetchall()
        if len(realms) != 1 or not isinstance(realms[0][0], str) or not realms[0][0].strip():
            raise ValidationError("invalid realm identity")
        realm_id = realms[0][0]
        if expected_realm_id is not None and realm_id != expected_realm_id:
            raise ValidationError("realm identity mismatch")
        digest = lambda obj: hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        observed = {name: digest(obj) for name, obj in objects.items()}
        for family, base in BASES.items():
            if any(observed.get(name) != value for name, value in base.items()):
                continue
            expected = dict(base)
            selected = []
            for owner in sorted({key.rsplit("-", 1)[0] if key.endswith(("-fixture", "-production")) else key for key in COMPONENTS}):
                if owner not in objects:
                    continue
                alternatives = [key for key in (owner, owner + "-fixture", owner + "-production") if key in COMPONENTS]
                matches = [key for key in alternatives if all(observed.get(name) == value for name, value in COMPONENTS[key].items())]
                if len(matches) != 1:
                    break
                selected.append(matches[0])
                expected.update(COMPONENTS[matches[0]])
            else:
                if observed == expected:
                    manifest = {"format_id": _FORMAT, "version": 23, "objects": objects}
                    return {"format_id": _FORMAT, "version": 23, "kind": family, "realm_id": realm_id,
                            "components": selected, "fingerprint": digest(manifest)}
        if "workers" in objects:
            raise ValidationError("legacy workers definition is not supported by the existing rebuild; preserve the source and use an inspect/export or backup-recovery route")
        raise ValidationError("unsupported legacy v23 manifest")
    except sqlite3.DatabaseError as exc:
        raise ValidationError("cannot inspect legacy SQLite manifest") from exc
