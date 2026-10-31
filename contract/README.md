# Workspace protocol contracts

Profile-owned long-running services use the independent
[`schemas/services.json`](schemas/services.json) declaration. See
[`profile-services.md`](../docs/profile-services.md) for the source-profile link,
portable argv tokens, lifecycle, logs and existing health/status readback.

## Artifact manifest

`artifacts.json` lists the sha256 of every file consumers copy or rely on (OpenAPI, schemas,
fixtures, generated clients), plus a `version` that is the digest of that list. It is generated, never
hand-edited: run `python scripts/artifact_manifest.py` after changing any listed file. The default
test lane runs `--check` and names each path that drifted. Consumers pin it through their
`vendor.lock.json` (producer version plus a per-file digest), so a change here fails their boundary job.

## Timeline shot composition boundary

The separately versioned shot-composition contract in
`schemas/shot-composition.json` is Runtime-owned. It defines publication
identity, exact-head/CAS context, dependencies, occurrences, and the known
shot-payload core. The payload stays open so consumers can preserve opaque app
extensions. Runtime-managed media metadata owns media identity and kind, and
the schema marks `ManagedMediaRegistry` as a Runtime-specific registry.

Nested `TimelineConfig` and clip semantics belong to the pinned
`@banodoco/timeline-schema` package. Runtime materializes that package's JSON
Schema and references it from the parent config and internal-timeline payload;
the shot envelope does not carry a second hand-maintained config definition.
Audio is optional in the shot payload. Nested timeline audio clips/bindings
remain authoritative, and a legacy aggregate descriptor is read-only when
present. Unknown payload fields are preserved by consumers. Visible clip
duration is source duration divided once by positive speed, with parent
occurrence duration acting as a visible interval cap; renderer frame rounding
is checked against the shared vectors.

`openapi/workspace-v1.yaml` is the canonical HTTP contract for the neutral
workspace runtime.  The schemas under `schemas/` are the closed JSON Schema
definitions referenced by the OpenAPI document.  They intentionally contain no
Astrid, Astrid App, or product-specific types.

The protocol uses a clean, digest-pinned version (`workspace.v1`).  A client
must complete the handshake before using any non-health operation.  Every
state-changing request carries an idempotency key and mutating resources expose
an opaque `version` for optimistic concurrency.

Task admission may include an immutable `storage_estimate` derived from the
same canonical input snapshot as the task spec. `scratch_bytes` is the peak
additional temporary space needed while the task runs; `output_bytes` is the
maximum final output written before temporary data is released. The runtime
checks their sum against current free space at admission and again at claim.
When the field is absent, the registered capability estimates remain the
backward-compatible fallback.

## Astrid binding

Astrid binds a typed task family, project identity, ordered CAS/input
references, and idempotency key to a Runtime-owned workspace task and run.
Workers claim and settle that work through the Runtime contract. Settlement,
output provenance, receipts, and event history remain Runtime-owned and are
the canonical readback surface for Astrid App's gallery and timeline consumers.
Product clients must not bypass this boundary with a direct database client or
legacy task-table fallback.

## Output locations

Runtime owns durable output bytes in the realm CAS at
`cas/sha256/<first-two>/<remaining-digest>`. Attempt scratch and settlement
staging are temporary and are not public result paths. Managed-output rows are
the portable readback identity. An explicit export materializes bytes under
the separately configured export root; the returned `destination.filename` is
the authoritative local filename. If a requested export filename already
exists or is too long for the host's temporary-name byte budget, Runtime keeps
the same root and chooses a deterministic association-scoped direct filename
rather than overwriting it or failing on the private staging sibling.


## Project object generation filters

`GET /v1/projects/{project_id}/objects` accepts optional `kind`, `model`, `target`
and `tag` query strings. The service equivalent is
`RuntimeService.list_project_objects(project, *, cursor=None, limit=50,
kind=None, model=None, target=None, tag=None)`. For example,
`?model=X&target=runpod` selects the RunPod object from managed/RunPod/fal
objects whose associated generations carry those values.

An object qualifies if it is already associated with the selected project and
**one generation in that same project** both references it through
`generation_variants.object_id` and satisfies **all** supplied filters. Different
generations cannot contribute different parts of the conjunction. Any variant
type and generation status qualifies; a generation without an object variant
selects no objects. Thumbnail references, media relations, output associations,
variant metadata, generation `type` and object MIME type do not supply matches.

Matching reuses the generation-list contract: `kind`, `model` and `target` are
exact, case-sensitive string comparisons against `generations.metadata.gen`;
`tag` is exact, case-sensitive membership among string elements of its `tags`
array. Missing or wrongly typed queried fields and malformed generation metadata
JSON do not match. Unrelated optional fields do not affect a match. Filters are
combined with AND, with no aliases, substring matching or wildcard expansion.
An omitted/`None` service filter is absent; an empty or non-string filter is an
`InvalidRequestError` (HTTP 400), including an explicitly blank query parameter.

Filtering returns existing `ManagedObject` resources with `relation` in the
unchanged `{items, next_cursor}` page envelope. Matching variants or generations
never duplicate an object. If several project reference relations exist for a
filtered object, its row uses the lexicographically first relation (`managed`
before `promoted`). Object order remains `objects.created_at ASC, digest ASC`,
independent of generation/variant order. Filtering and deduplication happen
before object pagination; limits remain 1–200, default 50. The unfiltered path
and its existing relation rows are unchanged.

Cursors belong to the object collection, canonical project ID and complete
non-absent filter set. Adding, removing or changing any filter, changing project,
or using a generation/variant cursor raises HTTP 400. Query argument order and
page size may change. Existing unfiltered object cursors remain compatible when
no filters are supplied. Cursors retain the existing live keyset behavior;
they do not freeze associations or metadata between requests. Clients forward
all filters unchanged on every page and consume object rows directly.
