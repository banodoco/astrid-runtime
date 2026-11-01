# Timeline commit contract v2 (C0 + C0b + C0c)

Normative contract for PLAN v2.1 §2, 22 October 2026. Runtime is the only writer;
the Python Agent provider computes semantics, validation, rebase and inverses.
App, CLI, Python, scripts and sheets submit the same commit operation. There is
no TypeScript executor, document overwrite route or force-conflict option.
Changes to this contract require the orchestrator. C0 is approved for dependents;
C0b is approved independently. C0c supplies the closure-root addressing amendment
for Astra/orchestrator review; it does not approve itself or claim implementation.
R2 may proceed against C0b and the adopted addressing principle, but merges only
after C0c approval.

This extends the existing `commitTimeline` engine, not a second store or journal.
The document version is v2; request `api_version: 1`, command `schema_version: 1`
and canonical-document `schema_version: 1` remain the existing ABI versions.
The generated request/reply schemas must explicitly adopt the fields and enums
below before consumers send them. In particular, v2 uses success `merged` where
the existing implementation says `rebased`; retain `rebased_onto` as the existing
head-pin field. An old provider must reject unsupported input rather than
silently ignoring merge policy, reads or steps. This is a coordinated schema
and client change, not a promise that the frozen R4 provider accepts v2 input.
Runtime's coordinator/port outcome validation must adopt `invalid` failures and
`merged` successes along with the generated DTOs; its present failure check only
admits `conflict`/`refused`. This document does not change those checks by itself.
Historical accepted receipts whose disjoint-head success is spelled `rebased`
remain authentic and replay unchanged, including their result, request hash,
event chain, records digest and `rebased_onto`. Extend `_verify_accepted()` to
recognize both historical `rebased` and new `merged` for a non-base landing;
`accepted` still requires the base landing. Keep every other authentication
check. Do not rewrite stored results/events, rehash old requests, synthesize
missing v2 step evidence or normalize a replay to `merged`. New v2 acceptances
and previews use `merged`; exact retries of historical keys return the original
`rebased` envelope without execution or an extra history entry.

Read against Runtime `cc7410a1f` (`timeline_commit_store.py`,
`timeline_commit_execution.py`) and Agent hub integration
`a086cc6db7928dc4a3516d304dd9a472b050f1cf` (`commands.py`, `commit.py`, including
its preview/accept branch at line 1061). Frozen R4 `commands.py`/`commit.py` were
also inspected; the line-1061 reference belongs to integration, not frozen R4.
Runtime's existing acceptance transaction, publisher-bound request hashing,
per-scope idempotency, verified closure, CAS and history chain remain authoritative.
C0b also rechecked Runtime hub integration `0d4c71a3c` and the same Agent hub
ref, including native occurrence creation and root restoration/allocation paths.
C0c rechecked those integration heads, Runtime closure validation and inherited
allocation authentication, and Agent `commands.py`, `_recording.py`, `inverse.py`,
`native_occurrence_create.py` and `authoring_bundle.py`: materialized children
can share the parent timeline ID while having distinct revision IDs. No product
implementation is changed here.

Examples are finite JSON: complete HTTP bodies/envelopes where stated, otherwise
named fixture fragments or input/expected-output scenarios. A fragment is not an
HTTP body. Revision/publication/principal IDs are fixture identities. Receipt
request hashes are illustrative 64-digit values; a live Runtime calculates them
from the authenticated invocation. Content and document digests in the complete
reply examples are calculated from their actual JSON values using Runtime's
canonical JSON spelling (sorted keys, compact separators, UTF-8). The examples
are executable test inputs for implementation tasks; parsing them does not prove
that those tasks have implemented the specified behavior.

## 1. Request: base, commands, label, steps, merge, reads and idempotency

Use the existing `commitTimeline` route, scoped by `project_id`/`timeline_id`.
Its HTTP `Idempotency-Key` is required for a mutation. The base is the exact pair
`base_revision_id`/`base_publication_id` in that scope, not a content digest or
local revision counter. Equal document bytes at a later publication are a new
base. Runtime verifies membership, authorization, the base pair and ancestry.

Required body fields remain `api_version`, both scope IDs, both base IDs and a
nonempty `commands` array. New App/Agent producers supply a nonempty `label` and
nonempty `steps` array. For compatibility with existing ABI-1 callers, omission
of `label` normalizes to `Timeline edit`; omission of `steps` synthesizes one
step (`id: "edit"`, the commit label, empty intent/tags, all command ordinals)
whose complete patch the provider derives. Explicit empty/null label or steps
is invalid. Thus every accepted commit has a label and step patches, including
requests from existing semantic callers. `source`, `rationale` and `group_id`
retain their existing meanings as caller-supplied annotations. `dry_run` defaults
to false. `merge` accepts only `fields` or `atomic` and defaults to `fields`,
preserving existing native semantic rebase with captured dependencies. The
conservative patch-read rule below can make its effective mode `atomic`.
Unknown control fields/enums are invalid; open document fields stay preserved.

Commands execute in array order as one transaction. They may mix native semantic
commands (including move, trim, set, split, ripple and per-occurrence fork when
registered by the provider) and the single generic operation type `doc.patch`.
Multiple instances of `doc.patch` are allowed, for example one for each of ten
notes. This contract does not invent semantic op names for unregistered recipes.
Native commands retain their existing `op`/`version`/`select`/`args` envelope.
The provider records all authored and derived effects and checks the final
candidate's timing, structure, parameter schemas, references and media inputs.
Temporary intermediate states may violate final document constraints; guards
and path resolution must still hold at each change. Any failure rejects the
whole batch, including its steps; `fields` never means partial acceptance.

Each step contains a stable unique `id` within the commit, `label`, `intent`
(string), `tags` (unique strings), `command_ordinals` (zero-based command indices)
and `patch` (an array of submitted changes using §2), plus optional `reads`
using §3's dependency variants. Steps partition the command array
into nonempty contiguous runs in execution order. Each command belongs to
exactly one step. A helper that needs independent undo of ten notes emits ten
commands/steps in one request. All changes of a command share its step.

For `doc.patch`, the submitted step patch must equal its commands' ordered
changes. For semantic commands, it contains any caller-asserted expected effects
and may be empty; assertions must match authoritative execution. The provider
fills the accepted step patch with complete authoritative effect records,
including compiler consequences and the provider-only forms in §2. Submitted
patches and these effect records have different permissions. Step patches are
checked claims, never instructions to apply a second edit. Semantic commands
need not predict compiler output in order to be submitted. Replies, previews
and history always contain complete provider-derived step patches with actual before values at the landing head.

`reads` is an optional array of the field/collection/scope dependencies defined
in §3, additional to all reads the provider captures for semantic commands.
Request `reads` are evaluated once at batch entry and apply conservatively to
every step, including when undo selects only one step. Explicit request
`reads: []` declares no additional batch-entry reads besides guarded operands;
it does not erase step-local or captured semantic dependencies. Step `reads`
are evaluated immediately before that step's first command, after preceding
steps' executed changes, at both original-base validation and landing-head
replay. They can therefore consume a value or root produced by an earlier step.
An incorrect step read on the sequential base is invalid
(`previous_value_mismatch`); a changed dependency during rebase is conflict
(`dependency_changed`, or `selection_changed` for collection shape).
Request-level reads are not re-evaluated at each step against values changed by
the batch itself. Omitted step `reads` adds no declarations; it does not assert
that native captures or inherited request reads are empty. A free-transform
producer must declare every additional step-local dependency it knows.

Omitting request `reads` is different: Runtime cannot infer what a script
consulted. A request containing `doc.patch` with omitted `reads` has effective
mode `atomic`, even if it asked for `fields`, and
guards the complete touched document scopes. The result reports `merge_mode`.
For each free-transform step in this fallback, persist scope dependencies for
the batch's complete touched scopes at that step's sequential input, including
scopes of derived effects. Do not limit this to scopes that the step wrote: it
may have consumed another step's output. Optional step reads cannot waive this
fallback. If scope
capture cannot bound the consulted closure, persist a `timeline` scope read.
These dependencies remain undo guards after acceptance; reporting `atomic`
alone is insufficient. A script consulting another scope must declare it; use
a closure-scope read when the consulted set cannot be bounded. The SDK must
choose this conservative form when it cannot capture reads, not invent `reads: []` after diffing bytes.

Accepted step `dependencies` is a provider-only array of §3 dependency variants:
the normalized union of inherited request reads, verified step reads, captured
semantic reads/selections/bindings, and generated conservative scope reads.
Empty `dependencies` may be omitted; supplied `steps[].dependencies` is invalid.
A scope dependency may conservatively subsume narrower captures in this array;
the original exact captures remain in `records.commands`. Preserve evaluation
boundaries and observed states in the authenticated request/step/command records;
this union is an undo dependency index, not a new batch-entry guard array.
`records.steps` stores the authoritative patches and dependencies, linked to
command captures by `command_ordinals`. Preview, result and history expose the
same authoritative steps. Never regenerate step dependencies from the final
patch or accept caller-authored recorder facts as authority.

Compiler attribution is causal and deterministic, even if compilation physically
runs only after the final command. For each derived effect, track the semantic
inputs it actually consumed and their last changing command ordinals. Assign
the effect to the step of the greatest such ordinal (ties use execution order),
and persist dependencies on all contributing steps' input changes. Compiler
outputs that depend on earlier compiler outputs inherit those causes. Preserve
actual before/after states and execution order in command captures; attribution
does not make a deferred effect observable earlier. A shared derived effect
requires contributing steps to be undone together whenever a surviving consumer
would be invalidated. If the compiler cannot bound causes, assign the effect to
the final step and persist conservative closure dependencies for all potential
contributors; per-step undo must refuse an unsafe subset. Do not silently assign
all effects to the final recorder. For example, step one changes a word anchor
and step two changes an unrelated note: derived clip `at`/`hold` belong to step
one, with its transcript dependency; undoing step two preserves that timing,
and undoing step one restores anchor and timing while preserving the note when
no later consumer exists. Rebase and preview use this same attribution rule.

Complete request body (`Idempotency-Key: edit-7`):

```json
{
  "api_version": 1,
  "project_id": "project-1",
  "timeline_id": "film-1",
  "base_revision_id": "rev-0",
  "base_publication_id": "pub-0",
  "commands": [
    {
      "schema_version": 1,
      "op": "doc.patch",
      "version": "1",
      "select": null,
      "args": {
        "changes": [
          {
            "op": "set",
            "ref": "parent",
            "path": [
              "clips",
              "id:clip-1",
              "meta",
              "org.example.notes",
              "note"
            ],
            "before": {
              "state": "present",
              "value": "A"
            },
            "value": "B"
          }
        ]
      }
    }
  ],
  "label": "Clarify opening note",
  "steps": [
    {
      "id": "note-1",
      "label": "Revise the first note",
      "intent": "Clarify the opening",
      "tags": [
        "notes"
      ],
      "command_ordinals": [
        0
      ],
      "patch": [
        {
          "op": "set",
          "ref": "parent",
          "path": [
            "clips",
            "id:clip-1",
            "meta",
            "org.example.notes",
            "note"
          ],
          "before": {
            "state": "present",
            "value": "A"
          },
          "value": "B"
        }
      ]
    }
  ],
  "merge": "fields",
  "reads": [],
  "dry_run": false,
  "source": {
    "via": "python",
    "detail": "notes.py"
  }
}
```

Runtime authorizes before returning a replay. The idempotency scope remains
(project, timeline); the canonical request identity includes the operation,
route, authenticated publisher and the entire body, including base, label,
steps, reads, merge and dry-run. The first durable accepted result for a key is
the winner. An exact retry, including after lost acknowledgement or restart,
returns that same `{data, receipt}` without rerunning effects or adding history.
The same key with a changed body or principal is `idempotency_mismatch` (409),
never a second edit. Concurrent identical requests serialize through the
existing execution coordinator and acceptance lookup. Authorization is still
required on retries. A transport failure or 503 `not_ready` is an unknown
outcome: retry the exact request/key before deciding to roll back or resubmit.

Rebase retries keep the original request/key and are bounded (the existing
provider tries at most three head-CAS attempts). A `tl.commit(fn)` conflict
re-run reads the returned head and reruns the function, at most three total
function evaluations by default; each changed request gets a fresh key. Do not
rerun a function merely because its previous request's outcome is unknown.
Outbox dependents retain stable created IDs and chain from the predecessor's
canonical landed document/pair; a refused predecessor requires revalidation
against the actual head or rollback with a message. A preview cannot be an
outbox predecessor's accepted base.

## 2. `doc.patch`: closure addressing and previous-value semantics

`doc.patch` has `select: null`, `version: "1"` and `args: {"changes": [...]}`.
A change has `op`, `ref`, `path`, and tagged `before`. `set` additionally has
`value`; `remove` does not. Paths are arrays of string tokens, never dotted
expressions, JSON Pointer escapes or numeric array indices. Object tokens are
literal keys, so dots and colons in an object key have no special meaning.
An empty path identifies the addressed payload root, subject to the ownership
restrictions below. Missing ancestors are not implicitly made: first set the
missing object, then set its child, or set the complete new object in one change.

**Closure-root identity (C0c).** Every root address resolves to exactly one
physical closure image at its evaluation boundary. Entity IDs are shorthand
aliases, not physical identities. Reachability is determined by verified pins,
not by payload equality, array order, the first match or the latest revision.
Two occurrences pointing to one image count as one match; two revisions with
identical payloads still count as two. Project/scope authorization applies to
all forms, including explicit revision refs.

| `ref` | Authored value addressed | Atomic touched scope |
| --- | --- | --- |
| `parent` | The evaluated parent composition payload | Parent payload |
| `shot:<shot_id>` | Exactly one reachable revision of that shot ID | That shot payload |
| `shot-revision:<revision_id>` | The reachable shot image with this revision ID | That shot payload |
| `internal:<timeline_id>` | Exactly one reachable child revision with that timeline ID | That child payload |
| `internal-revision:<revision_id>` | The reachable internal image with this revision ID | That child payload |

Revision ID suffixes are literal strings (split at the first colon); they do not
contain an entity-ID lookup or imply permission to read an arbitrary stored
revision. No match is `outside_closure`; multiple matches are `ambiguous_ref`.
Never select one or broadcast. This rule applies to submitted changes, declared
reads, semantic selections and authoritative effects. `timeline` is the existing
read-only whole-closure scope, not a payload root. Parent and existing
unambiguous native addresses retain their spelling and behavior. In particular,
an occurrence address follows its exact shot revision pin, even when the shot-ID
alias is ambiguous. A shared *revision* edit affects every occurrence of that
image, not every revision carrying the same shot ID.

Resolve request reads at batch input, step reads at step input, and each command
operand/change at its sequential input, including preceding creations/removals.
A future creation cannot satisfy an earlier lookup; a detached image cannot
satisfy a later lookup. Resolve and normalize to the physical image and logical
path before previous-value, overlap, collection, scope, dependency or undo
checks. Different spellings for one image overlap; identical entity IDs on
different images do not by themselves overlap. Preserve C0b's deferred compiler
visibility and causal attribution: only a materialized/verified intermediate
image is addressable, never a guessed future compiler revision ID.

Persist the resolved bindings in the existing authenticated command/step records,
not just the alias text. A binding identifies the submitted ref, physical ref,
image revision ID (including for `parent`), content digest, evaluation boundary
(base/landing head pair and step/command/change ordinal or batch-read boundary),
and the verified edge path when one was used. A `timeline` scope captures the
complete set of these image bindings, not a fictitious single physical root. Bind
scope/dependency captures too; step dependencies retain their original boundary
rather than being re-resolved at final output. The C0c fixture below shows binding
projections; they are provider facts, not caller instructions.
Existing native `records.commands[].bindings`, materialization captures and
`records.steps` carry these facts with their association to reads/effects. The
schema adoption must preserve that association and reject forged caller facts;
this document does not add a client-controlled binding override.

During landing-head replay a submitted alias must still have exactly one match,
and that match must be the recorded image or its unique authenticated successor.
A newly ambiguous alias conflicts with `ambiguous_ref`; a unique but unrelated
replacement conflicts with `binding_changed`, even if its value/digest matches.
Never silently retarget. Explicit revision refs identify the original image;
rebase/undo may follow successors only through authenticated materialization
records and verified managed-edge provenance connecting that image to its
successor in the same ownership context. A still-reachable original binding
stays on that image; another owner materializing a branch does not move it.
Entity IDs, matching bytes or a search for the newest revision are not
provenance. A fork/edge replacement is not an automatic continuation; no unique
authenticated continuation means `binding_changed` (missing required history means
`history_unavailable`). Reapply
field/collection guards and scan intervening history after this mapping. A
revision change alone need not conflict with a disjoint field edit; it cannot
conceal an intervening write, changed binding or A→B→A. Authenticated inverse
restoration/redo may return to an earlier image using the same provenance rules.

These roots address payloads of the verified sequential closure; commands never
write `CanonicalDocument` image wrappers, project/timeline identity, revision IDs,
content digests, dependency manifests, receipts, history or authorization.
Root `set` is a guarded replacement of an existing payload, validated with all
other changes, not a publication overwrite. Root `remove` is invalid. A missing
shot/internal root cannot be invented by choosing a ref. Closure creation,
attachment, detachment and per-occurrence fork use provider semantic commands;
subsequent patches in the same batch can address roots those commands created.
Patching entity membership inside an existing root is supported generically.
New media/documents must already be Runtime-verified inputs, not caller-forged
manifest pins or CAS identities. Ordinary asset registration metadata can be
patched only when its references verify against those inputs.

Occurrence rows are addressed under `parent` at
`["occurrences", "occurrence_id:<id>", ...]`. Their shot identity/revision links
and shot-to-internal revision links are provider-managed closure edges, not
ordinary patchable properties; use semantic creation/fork/attachment operations.
Existing edges are preserved verbatim until the provider regenerates their
revision pins for a changed child. A changed shared shot revision affects every
occurrence of that image; clients wanting occurrence-local ownership must fork
first. No implicit fork is performed by a field patch.

Existing native entity addresses (`parent/clip:<id>`,
`parent/track:<id>`, `occurrence:<id>/clip:<id>`,
`occurrence:<id>/track:<id>`, `occurrence:<id>/shot`, and occurrence source
addresses) normalize to the same uniquely bound physical roots/paths for guards,
conflicts, history and undo. Parent `clips`/`config.clips` and registry mirrors
likewise have one logical identity. The provider updates required mirrors; a client may
not write contradictory copies. Alias normalization must happen before overlap
checks: editing the same shared child through two occurrences is not disjoint.
A ref outside the authenticated closure is `outside_closure`.

**Provider-generated effect records.** Accepted `steps[].patch` and
`records.steps[].patch` describe the verified before/after closure union at the
relevant execution boundary, rather than only submitted-patch addresses.
Resolve effect refs against the verified before/after **union**, deduplicated by
physical image identity, not entity ID. `parent` remains the boundary anchor:
bind its unique before image and unique after image separately. A child alias
is usable in an effect only when unique in that union; otherwise use the
revision-qualified form. This
includes one entity's old/new revisions even if each side alone was unambiguous.
Root creation binds the after image; removal binds the before image. Materialized
successors are separate immutable images: record each entered/left root and its
managed-edge changes with their distinct physical refs, plus the authenticated
source→successor relation. An unchanged shared old image stays present and is
not removed. A field-level authored capture retains its before/after binding
and path even when the authoritative effect patch must represent revision
turnover as root remove/create. Those structural effects cannot erase its causal
step or turn unrelated fields into authored overlaps. Root membership/edge
consumers and explicit scope reads still guard the complete affected images.
For a grouped inverse/redo, retain each reversed/replayed target-step boundary
in the authenticated command recorder and associate its ordered effect range
with that boundary. Intermediate roots may occur in neither the whole command
input nor output. Use that segment's verified union, not the final union or all
historical images. The exposed step patch is the ordered concatenation; it does
not erase segment bindings. Effect ordering must preserve guards; final
reachability and pins must verify.
Intermediate detached/allocated images are authenticated staging values, never
additional roots a caller may submit.
Alongside ordinary changes, they may contain root creation (`set`, `path: []`,
`before: {"state": "absent"}` with the complete new payload), root removal
(`remove`, `path: []`, complete present `before`), and managed closure-edge
changes, including the links embedded in newly created roots/occurrence rows.
Root absence means absence from this boundary's reachable closure; immutable
historical images remain stored. Record every entered/left root and changed
managed link; links inside a complete root/item value are already recorded and
must not be duplicated as a second mutation. Use dependency-order effects:
create child before attaching its owner, detach owner before removing child.
A fork records the new roots and reattachment, and any old roots that leave the
closure; a still-shared old root is retained. Materialized revision-pin changes
are complete recorded effects even though §3 distinguishes them from authored
parent conflicts. Image wrappers, manifests, receipt identity and publication
pins remain Runtime-generated, never writable effect targets.

This permission is only for authenticated provider output, including an inverse's
output. Submitting the same root-create/root-remove or managed-edge form in
`doc.patch`, even inside a whole-root/item replacement or a step assertion,
remains invalid (`managed_closure_write`); reject these forbidden submitted
forms before address lookup. Otherwise a ref absent from the verified union
fails `outside_closure`; clients cannot enlarge that union by naming refs.
Only semantic execution and verified allocations establish new union members.
Effect records do not replace native `records.commands` allocation, restoration,
compiler-cause or dependency provenance; retain it for authentication and undo.

For an array whose schema gives items a unique string `id`, an element token is
`id:<literal-id>`. For the occurrence array it is
`occurrence_id:<literal-occurrence-id>`. Split a token at its first colon only.
The identity key comes from the schema, never from a caller-chosen heuristic.
Duplicate/missing identity keys in an identity collection are invalid. A token
which looks like an index remains an ordinary key in an object, but is invalid
as array traversal. IDs themselves cannot be changed by setting an `id` field:
remove and create a different item with appropriate guards instead.
`set` at an existing item token may replace that complete item only with the same
ID. Inserting an absent item with `set`, or removing an item with plain `remove`,
is invalid: use the corresponding `list.*` operation and its order guard.
Whole-array/ancestor replacement is allowed with a complete tagged `before`;
its authoritative diff still records membership/order effects and checks all
introduced IDs and references. It cannot bypass allocation or closure rules.

Tagged values have exactly one of these forms (fixture fragment):

```json
{
  "missing": {"state": "absent"},
  "explicit_null": {"state": "present", "value": null},
  "empty_object": {"state": "present", "value": {}},
  "empty_list": {"state": "present", "value": []}
}
```

`set` with `value: null` writes explicit JSON null, permitted only where the
schema allows it. `remove` is the explicit clear: it removes an optional key,
not sets it to null. Clearing required keys is invalid. A missing `value` in
`set` is invalid. `remove` requires present `before`; clearing an already absent
key is invalid (`previous_value_mismatch`), so redundant clears are not silently
accepted. No unspecified key is cleared or default-filled. Unknown keys are
preserved when another key changes.

Every `before` must exactly match the authored input at that position in the
sequential base execution (including earlier commands/changes). Object key order
is irrelevant; arrays are ordered; numbers compare numerically but booleans do
not equal numbers. All JSON must be finite. Object replacement guards all its
descendants, not only keys that differ; an item/ancestor replacement overlaps a
descendant edit. A wrong `before` on the original base is invalid; a correct base
guard that fails on a later head is a conflict. Schema/timing validation runs
against the completed candidate; acceptance must not silently drop an effect.

Absent → null → absent, with an existing namespace object (patch fragment):

```json
{
  "changes": [
    {
      "op": "set", "ref": "parent",
      "path": ["meta", "org.example.notes", "reviewed"],
      "before": {"state": "absent"}, "value": null
    },
    {
      "op": "remove", "ref": "parent",
      "path": ["meta", "org.example.notes", "reviewed"],
      "before": {"state": "present", "value": null}
    }
  ]
}
```

All intermediate effects are recorded even if the final value equals its input;
that equality does not erase read/write history or create undo authority.

Ordered identity arrays have three structural operations in addition to field
edits: `list.insert`, `list.remove`, `list.move`. Their `ref`/`path` identify the
array; `id` identifies the item. `before` is absent for insertion, or the complete
present item for removal/move. All three include `order_before`, the exact array
of IDs immediately before the operation. `list.insert` includes the new complete
`value` (whose identity equals `id`). Insert/move include `after_id`: null means
start, otherwise immediately after an existing item (never after itself).
For a move, locate the anchor after removing the moved item. `order_before`
implies an ordered collection read (§3). No last-writer-wins insertion tie rule
exists: concurrent membership/order edits conflict. Removing one item guards its
whole value, so a concurrent edit inside that item also conflicts. Other items'
fields remain mergeable when no field/value read covers them.

Structural patch fragments and expected final order:

```json
{
  "initial": [{"id": "a", "kind": "visual"}, {"id": "b", "kind": "visual"}],
  "changes": [
    {
      "op": "list.insert", "ref": "parent", "path": ["config", "tracks"],
      "id": "c", "before": {"state": "absent"},
      "order_before": ["a", "b"], "after_id": "a",
      "value": {"id": "c", "kind": "visual"}
    },
    {
      "op": "list.move", "ref": "parent", "path": ["config", "tracks"],
      "id": "b", "before": {"state": "present", "value": {"id": "b", "kind": "visual"}},
      "order_before": ["a", "c", "b"], "after_id": null
    },
    {
      "op": "list.remove", "ref": "parent", "path": ["config", "tracks"],
      "id": "c", "before": {"state": "present", "value": {"id": "c", "kind": "visual"}},
      "order_before": ["b", "a", "c"]
    }
  ],
  "expected_ids": ["b", "a"]
}
```

An id-less array (scalars, tuples, mixed rows, or rows without a schema-defined
stable key) is a single atomic field. Replace/remove that whole field with a
complete `before`; element traversal and `list.*` are refused
(`idless_list_address`). Never infer IDs from names or values. Whole-array
replacement remains available, including for unknown extension arrays.

Id-less-list scenario (the valid changes and invalid change are separate cases):

```json
{
  "initial": {"meta": {"org.example.notes": {"tags": ["rough", "review"]}}},
  "valid": {
    "op": "set", "ref": "parent", "path": ["meta", "org.example.notes", "tags"],
    "before": {"state": "present", "value": ["rough", "review"]},
    "value": ["approved"]
  },
  "invalid": {
    "op": "set", "ref": "parent", "path": ["meta", "org.example.notes", "tags", "0"],
    "before": {"state": "present", "value": "rough"}, "value": "approved"
  },
  "expected_invalid_code": "idless_list_address"
}
```

Creation uses caller-generated stable IDs (also across outbox retries). Native
`created` claims list the canonical entity refs; a `doc.patch` introducing a known
entity must declare its created refs in the same command envelope. The provider
verifies claims and records allocation ownership. The existing reservation
checks apply across the timeline's full allocation history, not merely live
membership: deleting an entity does not free its ID for another creation.
A collision at the original base is invalid; a concurrent allocation is conflict.
Only a verified inverse of that entity's deletion may restore its reserved ID.
No implicit renaming/remapping occurs; `id_map` contains only identity pairs (or
is empty). Arbitrary strings/keys inside `meta` are not reserved entity IDs.

Created-ID command fragment:

```json
{
  "schema_version": 1, "op": "doc.patch", "version": "1", "select": null,
  "created": ["parent/track:track-2"],
  "args": {"changes": [{
    "op": "list.insert", "ref": "parent", "path": ["config", "tracks"],
    "id": "track-2", "before": {"state": "absent"},
    "order_before": ["track-1"], "after_id": "track-1",
    "value": {"id": "track-2", "kind": "visual"}
  }]}
}
```

## 3. Conflicts: fields, collection reads and atomic scopes

The provider first verifies/executes the request at its base, then obtains the
verified contiguous ancestry from that publication through the current head.
Missing ancestry or unrecorded/legacy effects cannot be assumed empty:
`history_unavailable` (409) requires a fresh read/decision. Every retry repeats
head-sensitive guards. Runtime accepts only against the exact evaluated head
pair with CAS; it never updates an obsolete candidate unconditionally.

For effective `fields`, conflict if a later publication wrote a guarded field
or item, or an ancestor/descendant of it. This includes deletes/replacements,
identity rebinding and equal-value A→B→A changes; comparisons of final bytes alone
are insufficient. Reapplying the request against the head must also pass all
previous-value checks. Disjoint fields in the same object/item can merge.
An item field write guards existence and identity of that item, but does not
implicitly read all sibling fields or sibling ordering. Ordered `list.*` does
read collection shape, as specified above. Provider semantic reads and derived
writes participate in exactly the same conflict checks as patch effects.

Declared read variants (fixture fragments). Request reads are evaluated at the
original base before commands; step reads use the sequential input immediately
before that step. Replay uses the corresponding landing-head boundaries:

```json
{
  "field": {
    "kind": "field", "ref": "parent", "path": ["config", "fps"],
    "state": {"state": "present", "value": 30}
  },
  "ordered_collection": {
    "kind": "collection", "ref": "parent", "path": ["clips"],
    "members": ["clip-1", "clip-2"], "order": ["clip-1", "clip-2"]
  },
  "membership_only": {
    "kind": "collection", "ref": "parent", "path": ["clips"],
    "members": ["clip-1", "clip-2"], "order": null
  },
  "whole_child": {"kind": "scope", "ref": "internal:child-1", "path": []},
  "whole_closure": {"kind": "scope", "ref": "timeline", "path": []}
}
```

A field read is a tagged exact-value guard. Collection `members` is the complete
set of IDs in that collection, represented as a unique sorted string array;
non-null `order` is their complete ordered sequence. Membership changes always
conflict for a collection read; order changes also conflict if `order` is
non-null. It guards the full collection, not just selected items; declare field
reads too if a filter consulted item properties. A collection read does not
by itself guard item contents. For an id-less array use a field read of the
entire array. Scope reads guard the complete addressed payload; `timeline`
means the whole closure and is read-only. Verified image pins at the actual
evaluation boundary supply scope state (including earlier semantic allocations
for step reads); clients do not manufacture digests for scope reads. Any
overlapping intervening change conflicts even if the current state/order equals the base.
Incorrect declared reads at their original sequential evaluation boundary are
invalid. Earlier steps in this same transaction are not intervening publications;
their outputs are available to later step reads and retained as dependencies.

For effective `atomic`, derive touched scopes from every read, write and created
entity (including semantic consequences), normalized to parent, shot and child
payloads. Any intervening change anywhere in those complete scopes conflicts;
the batch can merge only across untouched scopes. Parent changes to a child
revision pin solely caused by materializing an otherwise untouched child are
not authored parent changes; the actual child scope carries that write. A scope
read of `timeline`, explicit parent root replacement or unknown legacy scope
requires conservative guarding of the whole affected closure. No caller can
shrink a touched scope by claiming narrower reads than the generated effects.

Conflict scenarios (each starts independently at its specified base):

```json
[
  {
    "case": "disjoint_fields", "merge": "fields", "reads": [],
    "ours": "parent clip-1 note A -> B",
    "theirs": "parent track-1 label Picture -> Opening",
    "expected": "merged", "preserve_theirs": true
  },
  {
    "case": "same_field", "merge": "fields", "reads": [],
    "ours": "parent clip-1 note A -> B",
    "theirs": "parent clip-1 note A -> C",
    "expected": "conflict", "reason": "value_conflict"
  },
  {
    "case": "collection_membership", "merge": "fields",
    "read": {"kind": "collection", "ref": "parent", "path": ["clips"], "members": ["clip-1"], "order": ["clip-1"]},
    "theirs": "insert clip-2", "expected": "conflict", "reason": "selection_changed"
  },
  {
    "case": "collection_order", "merge": "fields",
    "read": {"kind": "collection", "ref": "parent", "path": ["clips"], "members": ["clip-1", "clip-2"], "order": ["clip-1", "clip-2"]},
    "theirs_order": ["clip-2", "clip-1"],
    "expected": "conflict", "reason": "selection_changed"
  },
  {
    "case": "undeclared_transform", "requested_merge": "fields", "reads_omitted": true,
    "ours": "parent clip-1 note A -> B", "theirs": "parent track-1 label Picture -> Opening",
    "effective_merge": "atomic", "expected": "conflict", "reason": "atomic_scope_changed"
  },
  {
    "case": "explicit_atomic", "merge": "atomic", "reads": [],
    "ours": "parent clip-1 note A -> B", "theirs": "parent track-1 label Picture -> Opening",
    "expected": "conflict", "reason": "atomic_scope_changed"
  }
]
```

## 4. Replies: accepted, merged, conflict, invalid and dry-run

Success keeps the existing `{data, receipt}` envelope. A non-null durable receipt
is the acceptance authority. `data.status` is `accepted` when the landed previous
head equals the requested base, or `merged` when a disjoint later head was used.
Both include the complete canonical closure, digest, normalized commands,
identity map, provider/compiler versions, complete steps, effective `merge_mode`,
base IDs, previous head IDs, accepted revision and authoritative `publisher`.
The resulting publication ID is `receipt.receipt_id`; receipt `result` is the same
accepted data. `rebased_onto` is null for accepted, the landing head for merged.
Source/label/rationale/group annotations are echoed when supplied. Merged replies
contain the other party's changes in `canonical_document`; clients adopt that
whole result before replaying still-pending local edits.

Complete accepted envelope for §1's request at pub-0:

```json
{
  "data": {
    "status": "accepted",
    "base_revision_id": "rev-0",
    "base_publication_id": "pub-0",
    "previous_revision_id": "rev-0",
    "previous_publication_id": "pub-0",
    "accepted_revision_id": "rev-1",
    "rebased_onto": null,
    "canonical_document": {
      "schema_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "parent_revision": {
        "revision_id": "rev-1",
        "content_digest": "sha256:4506f79a8b9deebb8d0f0c0d260016c2c67027aaaccd1abf3fe89361903f5772",
        "payload": {
          "config": {
            "fps": 30,
            "tracks": [
              {
                "id": "track-1",
                "kind": "visual",
                "label": "Picture"
              }
            ]
          },
          "registry": {},
          "clips": [
            {
              "id": "clip-1",
              "clipType": "video",
              "track": "track-1",
              "at": 0,
              "hold": 2,
              "meta": {
                "org.example.notes": {
                  "note": "B"
                }
              }
            }
          ],
          "occurrences": []
        }
      },
      "shot_revisions": [],
      "internal_timeline_revisions": [],
      "dependency_manifest": {
        "shots": [],
        "internal_timelines": [],
        "media": [],
        "documents": []
      }
    },
    "document_digest": "sha256:f2c8b08d4d8cbdf2bf68fc90043b6be2a6930e22db945979f20e4b0150d94d3d",
    "commands": [
      {
        "schema_version": 1,
        "op": "doc.patch",
        "version": "1",
        "select": null,
        "args": {
          "changes": [
            {
              "op": "set",
              "ref": "parent",
              "path": [
                "clips",
                "id:clip-1",
                "meta",
                "org.example.notes",
                "note"
              ],
              "before": {
                "state": "present",
                "value": "A"
              },
              "value": "B"
            }
          ]
        }
      }
    ],
    "id_map": {},
    "provider_version": "provider-v2",
    "compiler_version": "compiler-v2",
    "merge_mode": "fields",
    "steps": [
      {
        "id": "note-1",
        "label": "Revise the first note",
        "intent": "Clarify the opening",
        "tags": [
          "notes"
        ],
        "command_ordinals": [
          0
        ],
        "patch": [
          {
            "op": "set",
            "ref": "parent",
            "path": [
              "clips",
              "id:clip-1",
              "meta",
              "org.example.notes",
              "note"
            ],
            "before": {
              "state": "present",
              "value": "A"
            },
            "value": "B"
          }
        ]
      }
    ],
    "publisher": "principal-7",
    "label": "Clarify opening note",
    "source": {
      "via": "python",
      "detail": "notes.py"
    }
  },
  "receipt": {
    "receipt_id": "pub-1",
    "command_kind": "timeline.commit",
    "idempotency_key": "edit-7",
    "request_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "project_id": "project-1",
    "project_seq": [
      2,
      2
    ],
    "event_ids": [
      "event-pub-1"
    ],
    "result": {
      "status": "accepted",
      "base_revision_id": "rev-0",
      "base_publication_id": "pub-0",
      "previous_revision_id": "rev-0",
      "previous_publication_id": "pub-0",
      "accepted_revision_id": "rev-1",
      "rebased_onto": null,
      "canonical_document": {
        "schema_version": 1,
        "project_id": "project-1",
        "timeline_id": "film-1",
        "parent_revision": {
          "revision_id": "rev-1",
          "content_digest": "sha256:4506f79a8b9deebb8d0f0c0d260016c2c67027aaaccd1abf3fe89361903f5772",
          "payload": {
            "config": {
              "fps": 30,
              "tracks": [
                {
                  "id": "track-1",
                  "kind": "visual",
                  "label": "Picture"
                }
              ]
            },
            "registry": {},
            "clips": [
              {
                "id": "clip-1",
                "clipType": "video",
                "track": "track-1",
                "at": 0,
                "hold": 2,
                "meta": {
                  "org.example.notes": {
                    "note": "B"
                  }
                }
              }
            ],
            "occurrences": []
          }
        },
        "shot_revisions": [],
        "internal_timeline_revisions": [],
        "dependency_manifest": {
          "shots": [],
          "internal_timelines": [],
          "media": [],
          "documents": []
        }
      },
      "document_digest": "sha256:f2c8b08d4d8cbdf2bf68fc90043b6be2a6930e22db945979f20e4b0150d94d3d",
      "commands": [
        {
          "schema_version": 1,
          "op": "doc.patch",
          "version": "1",
          "select": null,
          "args": {
            "changes": [
              {
                "op": "set",
                "ref": "parent",
                "path": [
                  "clips",
                  "id:clip-1",
                  "meta",
                  "org.example.notes",
                  "note"
                ],
                "before": {
                  "state": "present",
                  "value": "A"
                },
                "value": "B"
              }
            ]
          }
        }
      ],
      "id_map": {},
      "provider_version": "provider-v2",
      "compiler_version": "compiler-v2",
      "merge_mode": "fields",
      "steps": [
        {
          "id": "note-1",
          "label": "Revise the first note",
          "intent": "Clarify the opening",
          "tags": [
            "notes"
          ],
          "command_ordinals": [
            0
          ],
          "patch": [
            {
              "op": "set",
              "ref": "parent",
              "path": [
                "clips",
                "id:clip-1",
                "meta",
                "org.example.notes",
                "note"
              ],
              "before": {
                "state": "present",
                "value": "A"
              },
              "value": "B"
            }
          ]
        }
      ],
      "publisher": "principal-7",
      "label": "Clarify opening note",
      "source": {
        "via": "python",
        "detail": "notes.py"
      }
    },
    "created_at": "2026-10-22T10:00:00Z"
  }
}
```

Complete merged envelope for that same request if pub-1 independently changed
track-1's label to `Opening`. The note becomes B and the other party's label
survives; the original base stays pub-0 and the actual predecessor is pub-1:

```json
{
  "data": {
    "status": "merged",
    "base_revision_id": "rev-0",
    "base_publication_id": "pub-0",
    "previous_revision_id": "rev-1",
    "previous_publication_id": "pub-1",
    "accepted_revision_id": "rev-2",
    "rebased_onto": {
      "revision_id": "rev-1",
      "publication_id": "pub-1"
    },
    "canonical_document": {
      "schema_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "parent_revision": {
        "revision_id": "rev-2",
        "content_digest": "sha256:b2d872fa7524bb6e963d49a858bc0f178b1de35d50b503145d853cd2f092385a",
        "payload": {
          "config": {
            "fps": 30,
            "tracks": [
              {
                "id": "track-1",
                "kind": "visual",
                "label": "Opening"
              }
            ]
          },
          "registry": {},
          "clips": [
            {
              "id": "clip-1",
              "clipType": "video",
              "track": "track-1",
              "at": 0,
              "hold": 2,
              "meta": {
                "org.example.notes": {
                  "note": "B"
                }
              }
            }
          ],
          "occurrences": []
        }
      },
      "shot_revisions": [],
      "internal_timeline_revisions": [],
      "dependency_manifest": {
        "shots": [],
        "internal_timelines": [],
        "media": [],
        "documents": []
      }
    },
    "document_digest": "sha256:e5e0ad4e9ad7674a72fbf5d931ceb5812ac4464a6b4dacd46927b181382f6d10",
    "commands": [
      {
        "schema_version": 1,
        "op": "doc.patch",
        "version": "1",
        "select": null,
        "args": {
          "changes": [
            {
              "op": "set",
              "ref": "parent",
              "path": [
                "clips",
                "id:clip-1",
                "meta",
                "org.example.notes",
                "note"
              ],
              "before": {
                "state": "present",
                "value": "A"
              },
              "value": "B"
            }
          ]
        }
      }
    ],
    "id_map": {},
    "provider_version": "provider-v2",
    "compiler_version": "compiler-v2",
    "merge_mode": "fields",
    "steps": [
      {
        "id": "note-1",
        "label": "Revise the first note",
        "intent": "Clarify the opening",
        "tags": [
          "notes"
        ],
        "command_ordinals": [
          0
        ],
        "patch": [
          {
            "op": "set",
            "ref": "parent",
            "path": [
              "clips",
              "id:clip-1",
              "meta",
              "org.example.notes",
              "note"
            ],
            "before": {
              "state": "present",
              "value": "A"
            },
            "value": "B"
          }
        ]
      }
    ],
    "publisher": "principal-7",
    "label": "Clarify opening note",
    "source": {
      "via": "python",
      "detail": "notes.py"
    }
  },
  "receipt": {
    "receipt_id": "pub-2",
    "command_kind": "timeline.commit",
    "idempotency_key": "edit-7",
    "request_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "project_id": "project-1",
    "project_seq": [
      3,
      3
    ],
    "event_ids": [
      "event-pub-2"
    ],
    "result": {
      "status": "merged",
      "base_revision_id": "rev-0",
      "base_publication_id": "pub-0",
      "previous_revision_id": "rev-1",
      "previous_publication_id": "pub-1",
      "accepted_revision_id": "rev-2",
      "rebased_onto": {
        "revision_id": "rev-1",
        "publication_id": "pub-1"
      },
      "canonical_document": {
        "schema_version": 1,
        "project_id": "project-1",
        "timeline_id": "film-1",
        "parent_revision": {
          "revision_id": "rev-2",
          "content_digest": "sha256:b2d872fa7524bb6e963d49a858bc0f178b1de35d50b503145d853cd2f092385a",
          "payload": {
            "config": {
              "fps": 30,
              "tracks": [
                {
                  "id": "track-1",
                  "kind": "visual",
                  "label": "Opening"
                }
              ]
            },
            "registry": {},
            "clips": [
              {
                "id": "clip-1",
                "clipType": "video",
                "track": "track-1",
                "at": 0,
                "hold": 2,
                "meta": {
                  "org.example.notes": {
                    "note": "B"
                  }
                }
              }
            ],
            "occurrences": []
          }
        },
        "shot_revisions": [],
        "internal_timeline_revisions": [],
        "dependency_manifest": {
          "shots": [],
          "internal_timelines": [],
          "media": [],
          "documents": []
        }
      },
      "document_digest": "sha256:e5e0ad4e9ad7674a72fbf5d931ceb5812ac4464a6b4dacd46927b181382f6d10",
      "commands": [
        {
          "schema_version": 1,
          "op": "doc.patch",
          "version": "1",
          "select": null,
          "args": {
            "changes": [
              {
                "op": "set",
                "ref": "parent",
                "path": [
                  "clips",
                  "id:clip-1",
                  "meta",
                  "org.example.notes",
                  "note"
                ],
                "before": {
                  "state": "present",
                  "value": "A"
                },
                "value": "B"
              }
            ]
          }
        }
      ],
      "id_map": {},
      "provider_version": "provider-v2",
      "compiler_version": "compiler-v2",
      "merge_mode": "fields",
      "steps": [
        {
          "id": "note-1",
          "label": "Revise the first note",
          "intent": "Clarify the opening",
          "tags": [
            "notes"
          ],
          "command_ordinals": [
            0
          ],
          "patch": [
            {
              "op": "set",
              "ref": "parent",
              "path": [
                "clips",
                "id:clip-1",
                "meta",
                "org.example.notes",
                "note"
              ],
              "before": {
                "state": "present",
                "value": "A"
              },
              "value": "B"
            }
          ]
        }
      ],
      "publisher": "principal-7",
      "label": "Clarify opening note",
      "source": {
        "via": "python",
        "detail": "notes.py"
      }
    },
    "created_at": "2026-10-22T10:00:00Z"
  }
}
```

Failures keep the existing `http_status`/`code`/`message`/`details` error shape
and have no acceptance receipt. The structured semantic `code`, `path` (JSON
tokens), `hint` and `suggested_command` live in `details`, with `status`, `reason`,
`base`, `current` and `conflicts`. The outer `code` stays the transport category
(`conflict` or `validation_error`). A conflict entry has normalized `ref`/`path`,
`kind`, tagged `base`/`theirs`/`ours`, and `choices` (empty when reauthoring is
required). For array-operation/collection conflicts those states describe the
full collection shape. A conflict always includes the actual head pair in
`details.current`; clients load that canonical closure using the existing read
operation before revalidation. No force/overwrite choice is offered.

Complete conflict envelope (409; no writes):

```json
{
  "http_status": 409, "code": "conflict", "message": "The note changed after your base",
  "details": {
    "status": "conflict", "reason": "value_conflict", "code": "value_conflict",
    "path": ["clips", "id:clip-1", "meta", "org.example.notes", "note"],
    "hint": "Read the current note and reapply the intended change",
    "suggested_command": "timeline show",
    "base": {"revision_id": "rev-0", "publication_id": "pub-0"},
    "current": {"revision_id": "rev-1", "publication_id": "pub-1"},
    "conflicts": [{
      "kind": "value_conflict", "ref": "parent",
      "path": ["clips", "id:clip-1", "meta", "org.example.notes", "note"],
      "base": {"state": "present", "value": "A"},
      "theirs": {"state": "present", "value": "C"},
      "ours": {"state": "present", "value": "B"}, "choices": []
    }]
  }
}
```

Invalid means the request cannot be valid at its claimed base, including malformed
patches, incorrect previous values, unsupported operations or a final-validation
failure under the rule below. It is 422 with `details.status: "invalid"`. Include
the failing document path when known; for envelope errors use the request field
path. `current` is null only if validation happened before the authorized head
could be loaded.
Do not turn a later-head guard failure into an invalid-base diagnosis.

The existing mounted Agent provider performs final validation on the completed
candidate: return 422 `invalid` when a commit creates or modifies an unresolvable
timing/reference declaration, or makes a previously resolvable declaration
unresolvable (including by removing or moving its referenced target). An
unresolvable legacy declaration already in the base is preserved byte-for-byte
and cannot block an unrelated edit when the declaration and its referenced
targets are unchanged; `dry_run`/validate may report it only as a non-blocking
diagnostic. Guards still apply to every value written or invalidated: no binding
is invented and no declaration is stripped.

Normative fixture (executable assertions; this models the contract, not provider
implementation proof):

```python
import copy
import json

fixture = json.loads(r'''
{
  "base": {
    "config": {
      "tracks": [{"id": "track-1", "kind": "visual", "label": "Picture"}],
      "clips": [
        {
          "id": "clip-1", "clipType": "video", "track": "track-1", "at": 0, "hold": 2,
          "app": {"astrid": {"on": "old-anchor", "until": "end"}},
          "params": {"note": "A"}
        },
        {
          "id": "clip-2", "clipType": "video", "track": "track-1", "at": 2, "hold": 1,
          "app": {"astrid": {"on": "clip-1", "until": "end"}},
          "params": {"note": "B"}
        },
        {
          "id": "clip-3", "clipType": "video", "track": "track-1", "at": 3, "hold": 1,
          "app": {}, "params": {"note": "C"}
        }
      ]
    }
  },
  "cases": {
    "unrelated_edit": {
      "change": {"op": "set", "ref": "parent", "path": ["clips", "id:clip-1", "params", "note"], "before": {"state": "present", "value": "A"}, "value": "B"},
      "expected_status": "accepted"
    },
    "create_unresolved": {
      "change": {"op": "set", "ref": "parent", "path": ["clips", "id:clip-3", "app", "astrid"], "before": {"state": "absent"}, "value": {"on": "new-anchor", "until": "end"}},
      "expected": {"http_status": 422, "code": "validation_error", "details": {"status": "invalid", "code": "invalid_document", "path": ["clips", "id:clip-3", "app", "astrid"], "hint": "Bind the timing declaration to an existing target", "suggested_command": "timeline edit"}}
    },
    "modify_unresolved": {
      "change": {"op": "set", "ref": "parent", "path": ["clips", "id:clip-2", "app", "astrid", "on"], "before": {"state": "present", "value": "clip-1"}, "value": "missing-anchor"},
      "expected": {"http_status": 422, "code": "validation_error", "details": {"status": "invalid", "code": "invalid_document", "path": ["clips", "id:clip-2", "app", "astrid", "on"], "hint": "Bind the timing declaration to an existing target", "suggested_command": "timeline edit"}}
    },
    "remove_referenced_target": {
      "change": {"op": "list.remove", "ref": "parent", "path": ["clips"], "id": "clip-1", "before": {"state": "present", "value": {"id": "clip-1", "clipType": "video", "track": "track-1", "at": 0, "hold": 2, "app": {"astrid": {"on": "old-anchor", "until": "end"}}, "params": {"note": "A"}}}, "order_before": ["clip-1", "clip-2", "clip-3"]},
      "expected": {"http_status": 422, "code": "validation_error", "details": {"status": "invalid", "code": "invalid_document", "path": ["clips", "id:clip-2", "app", "astrid", "on"], "hint": "Keep the referenced target or update the declaration", "suggested_command": "timeline edit"}}
    }
  }
}
''')

base = fixture["base"]
clips = base["config"]["clips"]
target_ids = {clip["id"] for clip in clips}
assert "old-anchor" not in target_ids
legacy = clips[0]["app"]["astrid"]
legacy_bytes = json.dumps(legacy, separators=(",", ":"), ensure_ascii=False)

candidate = copy.deepcopy(base)
candidate["config"]["clips"][0]["params"]["note"] = "B"
assert fixture["cases"]["unrelated_edit"]["change"]["path"] == ["clips", "id:clip-1", "params", "note"]
assert json.dumps(candidate["config"]["clips"][0]["app"]["astrid"], separators=(",", ":"), ensure_ascii=False) == legacy_bytes
assert candidate["config"]["clips"][0]["params"]["note"] == "B"
assert fixture["cases"]["unrelated_edit"]["expected_status"] == "accepted"

for case in ("create_unresolved", "modify_unresolved", "remove_referenced_target"):
    expected = fixture["cases"][case]["expected"]
    assert expected["http_status"] == 422
    assert expected["code"] == "validation_error"
    assert expected["details"]["code"] == "invalid_document"
    assert expected["details"]["status"] == "invalid"
    assert expected["details"]["path"]
    assert expected["details"]["hint"] and expected["details"]["suggested_command"]

print("PASS: unrelated edit preserves unresolved legacy bytes; new, modified, and target-invalidating declarations are 422 invalid")
```

Complete invalid envelope for the id-less-list case:

```json
{
  "http_status": 422, "code": "validation_error", "message": "Array items have no stable identity",
  "details": {
    "status": "invalid", "reason": "idless_list_address", "code": "idless_list_address",
    "path": ["meta", "org.example.notes", "tags", "0"],
    "hint": "Replace the whole tags array with its complete previous value",
    "suggested_command": "timeline edit",
    "base": {"revision_id": "rev-0", "publication_id": "pub-0"},
    "current": {"revision_id": "rev-0", "publication_id": "pub-0"},
    "conflicts": []
  }
}
```

Other stable reasons include `previous_value_mismatch`, `invalid_path`,
`invalid_document`, `invalid_steps`, `identity_collision`, `outside_closure`,
`managed_field`, `unsupported_operation`, `selection_changed`, `ambiguous_ref`,
`binding_changed`,
`atomic_scope_changed`, `inverse_conflict`, `intervening_write`,
`surviving_dependents`, `history_unavailable`, `head_busy` and
`idempotency_mismatch`. Classification follows origin: a malformed base request
is invalid, an intervening change is conflict. Legacy refusal reasons such as
`history_unavailable`, `head_busy` and `idempotency_mismatch` retain 409 with
`details.status: "refused"`, plus the structured code/path/hint/command. Auth and
availability errors retain existing HTTP semantics and cannot claim acceptance.

Dry-run extends the existing `port.preview(prepared)` path in Agent
`commit.py:1061`, not a client-only simulation. Send the same body with
`dry_run: true` and a separate key. Run the same authorization, base/ancestry,
read/previous-value, identity, schema and head checks; return the same conflict
or invalid forms if they fail. On success return `data.status: "preview"`,
`would_status: "accepted" | "merged"`, `evaluated_head`, candidate document/digest,
normalized commands, `id_map`, complete steps and `merge_mode`, with
`receipt: null`. Candidate revision IDs are provisional and cannot be used as
published base IDs. A preview persists no closure revisions, allocations,
events, history, receipt or durable idempotency winner, and moves no head.
An exact repeated preview may evaluate a newer head. Committing after preview
uses a new key and `dry_run: false`; it repeats validation and may conflict.

Complete successful merged-preview envelope:

```json
{
  "data": {
    "status": "preview",
    "would_status": "merged",
    "base_revision_id": "rev-0",
    "base_publication_id": "pub-0",
    "evaluated_head": {
      "revision_id": "rev-1",
      "publication_id": "pub-1"
    },
    "canonical_document": {
      "schema_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "parent_revision": {
        "revision_id": "preview-rev-2",
        "content_digest": "sha256:b2d872fa7524bb6e963d49a858bc0f178b1de35d50b503145d853cd2f092385a",
        "payload": {
          "config": {
            "fps": 30,
            "tracks": [
              {
                "id": "track-1",
                "kind": "visual",
                "label": "Opening"
              }
            ]
          },
          "registry": {},
          "clips": [
            {
              "id": "clip-1",
              "clipType": "video",
              "track": "track-1",
              "at": 0,
              "hold": 2,
              "meta": {
                "org.example.notes": {
                  "note": "B"
                }
              }
            }
          ],
          "occurrences": []
        }
      },
      "shot_revisions": [],
      "internal_timeline_revisions": [],
      "dependency_manifest": {
        "shots": [],
        "internal_timelines": [],
        "media": [],
        "documents": []
      }
    },
    "document_digest": "sha256:211e4c7bb6c33fb38316e9c3e488e9b9b4525fa51d101464cbe27e17379c4663",
    "commands": [
      {
        "schema_version": 1,
        "op": "doc.patch",
        "version": "1",
        "select": null,
        "args": {
          "changes": [
            {
              "op": "set",
              "ref": "parent",
              "path": [
                "clips",
                "id:clip-1",
                "meta",
                "org.example.notes",
                "note"
              ],
              "before": {
                "state": "present",
                "value": "A"
              },
              "value": "B"
            }
          ]
        }
      }
    ],
    "id_map": {},
    "provider_version": "provider-v2",
    "compiler_version": "compiler-v2",
    "merge_mode": "fields",
    "steps": [
      {
        "id": "note-1",
        "label": "Revise the first note",
        "intent": "Clarify the opening",
        "tags": [
          "notes"
        ],
        "command_ordinals": [
          0
        ],
        "patch": [
          {
            "op": "set",
            "ref": "parent",
            "path": [
              "clips",
              "id:clip-1",
              "meta",
              "org.example.notes",
              "note"
            ],
            "before": {
              "state": "present",
              "value": "A"
            },
            "value": "B"
          }
        ]
      }
    ]
  },
  "receipt": null
}
```

## 5. Undo: whole commit, per-step guards and later-history scan

Undo is a new ordinary commit through the same engine, never a mutable history
entry or raw snapshot overwrite. Keep `timeline.inverse`, `select: null`, and
`args.publications` (unique target publication IDs in acceptance order). Extend
args with optional `steps`, a map from each target publication ID to a nonempty
array of unique step IDs. If `steps` is absent, undo every step of every target.
If present, it must specify every target; unknown step/publication IDs are
invalid. Selected steps are inverted in reverse execution order, newest selected
publication first. Nonselected steps in those publications remain intervening
work for dependency checks. The request still has its own label and steps; the
inverse step's submitted patch can be empty and is completed by the provider.
Store `records.undo_of` and `records.undo_steps` (the latter null for whole-commit
undo); retain original history entries unchanged.

Command fragments for a whole undo and a per-step undo (separate requests):

```json
{
  "whole": {
    "schema_version": 1, "op": "timeline.inverse", "version": "1", "select": null,
    "args": {"publications": ["pub-notes"]}
  },
  "one_step": {
    "schema_version": 1, "op": "timeline.inverse", "version": "1", "select": null,
    "args": {"publications": ["pub-notes"], "steps": {"pub-notes": ["note-3"]}}
  }
}
```

Runtime/provider load the target's authenticated complete step patches and the
actual previous landing head, never inverse writes supplied by the caller.
Reverse `set`/`remove` using their tagged before/after states; insertion becomes
removal, removal becomes insertion at its recorded position, and move restores
its previous position. A step's inverse uses its own sequential boundary states,
not the whole commit's final coalesced field values. Preserve all effects,
including derived writes and collection-shape changes. Validate the completed
inverse candidate before acceptance. Root create/remove and managed-edge effects
are inverted through the existing semantic restoration machinery, never by
turning the effect log into a client `doc.patch`. Load authenticated before/after
closures and native allocation facts, order restoration/reattachment correctly,
and recompile managed pins from that verified source. Restore reserved IDs only
with their original authenticated allocation provenance (including inherited
materialization sources); redo inherits it from the accepted inverse. No fresh
allocation, caller-supplied closure image or inferred provenance may authorize
restoration. Corrupt provenance is rejected, and unavailable boundary/history
is `history_unavailable`. Removing a root from the live closure does not erase
its immutable image or free its reserved ID.

Use the target's persisted physical bindings for inverse/redo and every later
history scan; do not resolve its historical alias text anew at the current head.
A formerly unique alias may now name several images. That does not authorize
choosing another image, nor does it invalidate a proven bound continuation by
itself. Normalize later reads/writes/edges through the same authenticated lineage
before checking overlap and surviving references. This differs from replaying a
new submitted alias, which must pass uniqueness at its replay boundary. Undo of
creation removes only the bound created roots and edges (and their authenticated
successors); unrelated children with the same timeline ID survive. Inverse
restoration effects use explicit refs wherever the before/after union is
ambiguous, and redo inherits bindings/allocation sources from its accepted undo.

Two guards are required: (1) current values/identities/collection shape match the
selected effects' recorded after states, adjusted only for other selected
inverses; (2) scan every later accepted publication and every later nonselected
step through the current evaluated head for overlapping writes, reads and
reference dependencies. Include every authoritative step dependency from §1,
with inherited request reads applying to every step and conservative scope reads
remaining active after the commit landed. A later write to a target field or
guarded read refuses undo even if it restored equal bytes; later consumers of a created entity or a
value the inverse would invalidate also refuse undo. Selected steps with shared
fields/dependencies must be undone together when a remaining step would be
invalidated. Unknown/legacy history is `history_unavailable`, never permission
to undo. A surviving reference blocks deletion of a created entity. Independent
later steps/commits remain intact. There is no automatic cascading undo.

A merged commit's inverse is computed against the head it actually landed on:
its `previous_*`/`rebased_onto`, not the stale requested base. Thus undoing §4's
merged note B→A preserves the other party's track label `Opening`. Later work is
still subject to both guards. Redo is guarded undo of the accepted undo commit,
with a fresh key; it is subject to the same history/dependency checks.

Undo scenarios, including a value-equal A→B→A tail:

```json
[
  {
    "case": "whole_notes",
    "target_steps": ["note-1", "note-2", "note-3"],
    "later": [], "undo_steps": null,
    "expected": "accepted", "reverted_steps": ["note-3", "note-2", "note-1"]
  },
  {
    "case": "independent_note_step",
    "target_steps": ["note-1", "note-2", "note-3"],
    "distinct_paths": true, "later": [], "undo_steps": ["note-2"],
    "expected": "accepted", "preserved_steps": ["note-1", "note-3"]
  },
  {
    "case": "later_dependent_step_in_same_commit",
    "target_step": {"id": "first", "change": "note X -> A"},
    "later_step": {"id": "second", "read": "note A", "writes": "derived_summary"},
    "undo_steps": ["first"], "expected": "conflict", "reason": "inverse_conflict"
  },
  {
    "case": "A_to_B_to_A",
    "target": {"publication_id": "p1", "before": "X", "after": "A"},
    "later": [
      {"publication_id": "p2", "before": "A", "after": "B"},
      {"publication_id": "p3", "before": "B", "after": "A"}
    ],
    "current": "A", "value_guard_matches": true,
    "undo": "p1", "expected": "conflict", "reason": "intervening_write"
  },
  {
    "case": "undo_first_leg_of_A_to_B_to_A",
    "target": {"publication_id": "p1", "before": "A", "after": "B"},
    "later": [{"publication_id": "p2", "before": "B", "after": "A"}],
    "undo": "p1", "expected": "conflict", "current": "A"
  },
  {
    "case": "merged_inverse",
    "requested_base": {"note": "A", "track_label": "Picture"},
    "landing_head": {"note": "A", "track_label": "Opening"},
    "accepted_result": {"note": "B", "track_label": "Opening"},
    "later": [], "expected_after_undo": {"note": "A", "track_label": "Opening"}
  }
]
```

Two-patch executable scenario. Bootstrap `base_document` as the authenticated
`pub-reads-0` fixture (its parent meta namespace already exists). Submit `request`
with key `step-reads`, then, with no other publications, submit
`undo_first_request` with key `undo-first`. Step two's read of B is valid only
after step one has run; evaluating it at batch entry would incorrectly reject
the commit. The first undo returns the exact refusal below, has no receipt and
adds no history. From that unchanged head submit `undo_both_request` with key
`undo-both`; it reverses second then first and restores the original payload.
`expected_commit`/`expected_undo` are outcome projections, not HTTP envelopes.
In independent resets, replace request `reads` with `request_read_variant.reads`
(the A read is checked only at entry), or remove it as instructed by
`uncaptured_variant`. Both still refuse undo of first alone and accept undo of
both; the latter persists parent-scope dependencies on both steps and reports
`atomic`. Later independent parent work would therefore also guard this undo.
These are required R1/R2 behavioral assertions, not results from JSON parsing.

```json
{
  "case": "sequential_step_reads",
  "base_document": {
    "schema_version": 1,
    "project_id": "project-1",
    "timeline_id": "film-1",
    "parent_revision": {
      "revision_id": "rev-reads-0",
      "content_digest": "sha256:2474d93db3e5bdd0f35e1fd2dd489b1d8b5eb154b1ee29ae7e1863074cbcf812",
      "payload": {
        "config": {"output": {"fps": 30}, "tracks": []},
        "registry": {},
        "clips": [],
        "occurrences": [],
        "meta": {"org.example.notes": {"note": "A"}}
      }
    },
    "shot_revisions": [],
    "internal_timeline_revisions": [],
    "dependency_manifest": {"shots": [], "internal_timelines": [], "media": [], "documents": []}
  },
  "request": {
    "api_version": 1,
    "project_id": "project-1",
    "timeline_id": "film-1",
    "base_revision_id": "rev-reads-0",
    "base_publication_id": "pub-reads-0",
    "commands": [
      {
        "schema_version": 1,
        "op": "doc.patch",
        "version": "1",
        "select": null,
        "args": {
          "changes": [
            {
              "op": "set",
              "ref": "parent",
              "path": ["meta", "org.example.notes", "note"],
              "before": {"state": "present", "value": "A"},
              "value": "B"
            }
          ]
        }
      },
      {
        "schema_version": 1,
        "op": "doc.patch",
        "version": "1",
        "select": null,
        "args": {
          "changes": [
            {
              "op": "set",
              "ref": "parent",
              "path": ["meta", "org.example.notes", "summary"],
              "before": {"state": "absent"},
              "value": "Note: B"
            }
          ]
        }
      }
    ],
    "label": "Revise note and summarize",
    "steps": [
      {
        "id": "first",
        "label": "Revise note",
        "intent": "",
        "tags": [],
        "command_ordinals": [0],
        "patch": [
          {
            "op": "set",
            "ref": "parent",
            "path": ["meta", "org.example.notes", "note"],
            "before": {"state": "present", "value": "A"},
            "value": "B"
          }
        ],
        "reads": []
      },
      {
        "id": "second",
        "label": "Summarize revised note",
        "intent": "",
        "tags": [],
        "command_ordinals": [1],
        "patch": [
          {
            "op": "set",
            "ref": "parent",
            "path": ["meta", "org.example.notes", "summary"],
            "before": {"state": "absent"},
            "value": "Note: B"
          }
        ],
        "reads": [
          {
            "kind": "field",
            "ref": "parent",
            "path": ["meta", "org.example.notes", "note"],
            "state": {"state": "present", "value": "B"}
          }
        ]
      }
    ],
    "merge": "fields",
    "reads": []
  },
  "expected_commit": {
    "status": "accepted",
    "accepted_revision_id": "rev-reads-1",
    "publication_id": "pub-reads-1",
    "merge_mode": "fields",
    "steps": [
      {
        "id": "first",
        "label": "Revise note",
        "intent": "",
        "tags": [],
        "command_ordinals": [0],
        "patch": [
          {
            "op": "set",
            "ref": "parent",
            "path": ["meta", "org.example.notes", "note"],
            "before": {"state": "present", "value": "A"},
            "value": "B"
          }
        ],
        "reads": []
      },
      {
        "id": "second",
        "label": "Summarize revised note",
        "intent": "",
        "tags": [],
        "command_ordinals": [1],
        "patch": [
          {
            "op": "set",
            "ref": "parent",
            "path": ["meta", "org.example.notes", "summary"],
            "before": {"state": "absent"},
            "value": "Note: B"
          }
        ],
        "reads": [
          {
            "kind": "field",
            "ref": "parent",
            "path": ["meta", "org.example.notes", "note"],
            "state": {"state": "present", "value": "B"}
          }
        ],
        "dependencies": [
          {
            "kind": "field",
            "ref": "parent",
            "path": ["meta", "org.example.notes", "note"],
            "state": {"state": "present", "value": "B"}
          }
        ]
      }
    ],
    "parent_payload": {
      "config": {"output": {"fps": 30}, "tracks": []},
      "registry": {},
      "clips": [],
      "occurrences": [],
      "meta": {"org.example.notes": {"note": "B", "summary": "Note: B"}}
    }
  },
  "undo_first_request": {
    "api_version": 1,
    "project_id": "project-1",
    "timeline_id": "film-1",
    "base_revision_id": "rev-reads-1",
    "base_publication_id": "pub-reads-1",
    "commands": [
      {
        "schema_version": 1,
        "op": "timeline.inverse",
        "version": "1",
        "select": null,
        "args": {"publications": ["pub-reads-1"], "steps": {"pub-reads-1": ["first"]}}
      }
    ],
    "label": "Undo notes",
    "steps": [
      {
        "id": "undo",
        "label": "Undo notes",
        "intent": "",
        "tags": [],
        "command_ordinals": [0],
        "patch": []
      }
    ],
    "merge": "fields",
    "reads": []
  },
  "expected_refusal": {
    "http_status": 409,
    "code": "conflict",
    "message": "A surviving step consumed the selected output",
    "details": {
      "status": "conflict",
      "reason": "inverse_conflict",
      "code": "inverse_conflict",
      "path": ["meta", "org.example.notes", "note"],
      "hint": "Undo first and second together",
      "suggested_command": "timeline history",
      "base": {"revision_id": "rev-reads-1", "publication_id": "pub-reads-1"},
      "current": {"revision_id": "rev-reads-1", "publication_id": "pub-reads-1"},
      "conflicts": [
        {
          "kind": "inverse_conflict",
          "ref": "parent",
          "path": ["meta", "org.example.notes", "note"],
          "base": {"state": "present", "value": "B"},
          "theirs": {"state": "present", "value": "B"},
          "ours": {"state": "present", "value": "A"},
          "choices": []
        }
      ]
    }
  },
  "expected_after_refusal": {
    "head": {"revision_id": "rev-reads-1", "publication_id": "pub-reads-1"},
    "parent_payload": {
      "config": {"output": {"fps": 30}, "tracks": []},
      "registry": {},
      "clips": [],
      "occurrences": [],
      "meta": {"org.example.notes": {"note": "B", "summary": "Note: B"}}
    },
    "added_history_entries": 0
  },
  "undo_both_request": {
    "api_version": 1,
    "project_id": "project-1",
    "timeline_id": "film-1",
    "base_revision_id": "rev-reads-1",
    "base_publication_id": "pub-reads-1",
    "commands": [
      {
        "schema_version": 1,
        "op": "timeline.inverse",
        "version": "1",
        "select": null,
        "args": {"publications": ["pub-reads-1"], "steps": {"pub-reads-1": ["first", "second"]}}
      }
    ],
    "label": "Undo notes",
    "steps": [
      {
        "id": "undo",
        "label": "Undo notes",
        "intent": "",
        "tags": [],
        "command_ordinals": [0],
        "patch": []
      }
    ],
    "merge": "fields",
    "reads": []
  },
  "expected_undo": {
    "status": "accepted",
    "accepted_revision_id": "rev-reads-2",
    "publication_id": "pub-reads-2",
    "reversed_steps": ["second", "first"],
    "patch": [
      {
        "op": "remove",
        "ref": "parent",
        "path": ["meta", "org.example.notes", "summary"],
        "before": {"state": "present", "value": "Note: B"}
      },
      {
        "op": "set",
        "ref": "parent",
        "path": ["meta", "org.example.notes", "note"],
        "before": {"state": "present", "value": "B"},
        "value": "A"
      }
    ],
    "parent_payload": {
      "config": {"output": {"fps": 30}, "tracks": []},
      "registry": {},
      "clips": [],
      "occurrences": [],
      "meta": {"org.example.notes": {"note": "A"}}
    },
    "undo_of": ["pub-reads-1"],
    "undo_steps": {"pub-reads-1": ["first", "second"]}
  },
  "request_read_variant": {
    "reads": [
      {
        "kind": "field",
        "ref": "parent",
        "path": ["meta", "org.example.notes", "note"],
        "state": {"state": "present", "value": "A"}
      }
    ],
    "expected_dependencies": [
      [
        {
          "kind": "field",
          "ref": "parent",
          "path": ["meta", "org.example.notes", "note"],
          "state": {"state": "present", "value": "A"}
        }
      ],
      [
        {
          "kind": "field",
          "ref": "parent",
          "path": ["meta", "org.example.notes", "note"],
          "state": {"state": "present", "value": "A"}
        },
        {
          "kind": "field",
          "ref": "parent",
          "path": ["meta", "org.example.notes", "note"],
          "state": {"state": "present", "value": "B"}
        }
      ]
    ],
    "expected_status": "accepted"
  },
  "uncaptured_variant": {
    "omit_request_fields": ["reads"],
    "expected_merge_mode": "atomic",
    "required_dependencies_per_step": [{"kind": "scope", "ref": "parent", "path": []}],
    "undo_first_status": "conflict",
    "undo_first_reason": "inverse_conflict",
    "undo_both_status": "accepted"
  }
}
```

Semantic creation and undo executable scenario. This uses the existing
`occurrence.create`, avoiding an invented fork recipe. Bootstrap the empty
closure below at `pub-create-0` with `picture` an active visual output track,
no reserved `shot-new`/`occ-new`, no legacy pinned groups and no intervening work.
Submit `request` with key `create-opening`, reload its canonical closure, then
submit `undo_request` with key `undo-opening`. `reply` and `undo_reply` are
complete success envelopes, including every root payload, manifest pin, effect
and receipt result; fixture revision/event identities stand for provider-produced
pins as in §4. The internal image's `timeline_id` is `film-1`, as the current
compiler assigns for a new shot. This case has exactly one child at that ref.
The new shot-to-internal link is inside the root `set`; the occurrence-to-shot
links are inside `list.insert`. All belong to the creation step although the
compiler emits the pins after command execution. Undo removes the occurrence,
then the shot and internal roots from the reachable closure. It preserves the
empty base payload and adds a new publication, retaining historical images and
ID reservations. `expected_history` is a recorder projection: native typed
allocations remain authenticated alongside the displayed effect records.

From the undo head, `redo_request` with fresh key `redo-opening` must restore the
same entities and child images via the accepted inverse's inherited allocation
provenance; its parent revision/publication is newly accepted. Ordinary creation
reusing these retired IDs at that base must be invalid (`identity_collision`). In
independent resets, wrap each `forbidden_patch_commands` command in an otherwise
valid commit with its matching step patch and `reads: []`: test root creation at
the empty base, and root removal/managed-edge set at the creation head. Each
returns 422 `invalid`/`managed_closure_write`, without receipt or history. A
same-value edge set is forbidden too; this is an ownership check, not a missing
reference check. A fork uses the same effect permissions and inverse machinery,
with surviving shared roots retained as specified in §2. R1/R2 must execute
these scenarios against the provider; fixture checks alone do not qualify them.

```json
{
  "case": "semantic_creation_and_inverse",
  "base_document": {
    "schema_version": 1,
    "project_id": "project-1",
    "timeline_id": "film-1",
    "parent_revision": {
      "revision_id": "rev-create-0",
      "content_digest": "sha256:7db6941424344f29682efe9425283892d2f45c9fc96bd20cf21faaa8256eb16a",
      "payload": {
        "config": {
          "output": {"fps": 30},
          "tracks": [{"id": "picture", "kind": "visual", "role": "output", "label": "Picture"}]
        },
        "registry": {},
        "clips": [],
        "occurrences": []
      }
    },
    "shot_revisions": [],
    "internal_timeline_revisions": [],
    "dependency_manifest": {"shots": [], "internal_timelines": [], "media": [], "documents": []}
  },
  "request": {
    "api_version": 1,
    "project_id": "project-1",
    "timeline_id": "film-1",
    "base_revision_id": "rev-create-0",
    "base_publication_id": "pub-create-0",
    "commands": [
      {
        "schema_version": 1,
        "op": "occurrence.create",
        "version": "1",
        "select": "parent",
        "args": {
          "occurrence_id": "occ-new",
          "shot_id": "shot-new",
          "name": "Opening",
          "track": "picture",
          "on": 0,
          "duration": 2
        },
        "created": ["shot:shot-new", "occurrence:occ-new"]
      }
    ],
    "label": "Create opening shot",
    "steps": [
      {
        "id": "create",
        "label": "Create opening shot",
        "intent": "",
        "tags": [],
        "command_ordinals": [0],
        "patch": [],
        "reads": [{"kind": "scope", "ref": "timeline", "path": []}]
      }
    ],
    "merge": "fields",
    "reads": []
  },
  "reply": {
    "data": {
      "status": "accepted",
      "base_revision_id": "rev-create-0",
      "base_publication_id": "pub-create-0",
      "previous_revision_id": "rev-create-0",
      "previous_publication_id": "pub-create-0",
      "accepted_revision_id": "rev-create-1",
      "rebased_onto": null,
      "canonical_document": {
        "schema_version": 1,
        "project_id": "project-1",
        "timeline_id": "film-1",
        "parent_revision": {
          "revision_id": "rev-create-1",
          "content_digest": "sha256:d3546764a26b60a2e6b6d0a91bbd39b7564c9cd58d9fbd89b901c0540ba108ee",
          "payload": {
            "config": {
              "output": {"fps": 30},
              "tracks": [{"id": "picture", "kind": "visual", "role": "output", "label": "Picture"}]
            },
            "registry": {},
            "clips": [],
            "occurrences": [
              {
                "occurrence_id": "occ-new",
                "shot_id": "shot-new",
                "shot_revision_id": "shot-new-1",
                "track": "picture",
                "placement": {"start_ms": 0, "track": "picture"},
                "duration_ms": 2000,
                "source_offset": 0,
                "speed": 1,
                "gain": 1
              }
            ]
          }
        },
        "shot_revisions": [
          {
            "shot_id": "shot-new",
            "revision_id": "shot-new-1",
            "internal_timeline_revision_id": "internal-new-1",
            "content_digest": "sha256:d6f9b8b3d85ccafca5c675759f43c6987433a57e34708a3848635a0b357f2306",
            "payload": {"name": "Opening", "items": [], "internal_timeline_revision_id": "internal-new-1"}
          }
        ],
        "internal_timeline_revisions": [
          {
            "timeline_id": "film-1",
            "revision_id": "internal-new-1",
            "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18",
            "payload": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
          }
        ],
        "dependency_manifest": {
          "shots": [
            {
              "shot_id": "shot-new",
              "revision_id": "shot-new-1",
              "internal_timeline_revision_id": "internal-new-1",
              "content_digest": "sha256:d6f9b8b3d85ccafca5c675759f43c6987433a57e34708a3848635a0b357f2306"
            }
          ],
          "internal_timelines": [
            {
              "timeline_id": "film-1",
              "revision_id": "internal-new-1",
              "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18"
            }
          ],
          "media": [],
          "documents": []
        }
      },
      "document_digest": "sha256:da282a5a1240e00d2e4516951ac1ed7a54b5e8d32171a4cefed83a4514b05508",
      "commands": [
        {
          "schema_version": 1,
          "op": "occurrence.create",
          "version": "1",
          "select": "parent",
          "args": {
            "occurrence_id": "occ-new",
            "shot_id": "shot-new",
            "name": "Opening",
            "track": "picture",
            "on": 0,
            "duration": 2
          },
          "created": ["shot:shot-new", "occurrence:occ-new"]
        }
      ],
      "id_map": {},
      "provider_version": "provider-v2",
      "compiler_version": "compiler-v2",
      "merge_mode": "fields",
      "steps": [
        {
          "id": "create",
          "label": "Create opening shot",
          "intent": "",
          "tags": [],
          "command_ordinals": [0],
          "patch": [
            {
              "op": "set",
              "ref": "internal:film-1",
              "path": [],
              "before": {"state": "absent"},
              "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
            },
            {
              "op": "set",
              "ref": "shot:shot-new",
              "path": [],
              "before": {"state": "absent"},
              "value": {"name": "Opening", "items": [], "internal_timeline_revision_id": "internal-new-1"}
            },
            {
              "op": "list.insert",
              "ref": "parent",
              "path": ["occurrences"],
              "id": "occ-new",
              "before": {"state": "absent"},
              "order_before": [],
              "after_id": null,
              "value": {
                "occurrence_id": "occ-new",
                "shot_id": "shot-new",
                "shot_revision_id": "shot-new-1",
                "track": "picture",
                "placement": {"start_ms": 0, "track": "picture"},
                "duration_ms": 2000,
                "source_offset": 0,
                "speed": 1,
                "gain": 1
              }
            }
          ],
          "reads": [{"kind": "scope", "ref": "timeline", "path": []}],
          "dependencies": [{"kind": "scope", "ref": "timeline", "path": []}]
        }
      ],
      "publisher": "principal-7",
      "label": "Create opening shot"
    },
    "receipt": {
      "receipt_id": "pub-create-1",
      "command_kind": "timeline.commit",
      "idempotency_key": "create-opening",
      "request_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "project_id": "project-1",
      "project_seq": [2, 2],
      "event_ids": ["event-pub-create-1"],
      "result": {
        "status": "accepted",
        "base_revision_id": "rev-create-0",
        "base_publication_id": "pub-create-0",
        "previous_revision_id": "rev-create-0",
        "previous_publication_id": "pub-create-0",
        "accepted_revision_id": "rev-create-1",
        "rebased_onto": null,
        "canonical_document": {
          "schema_version": 1,
          "project_id": "project-1",
          "timeline_id": "film-1",
          "parent_revision": {
            "revision_id": "rev-create-1",
            "content_digest": "sha256:d3546764a26b60a2e6b6d0a91bbd39b7564c9cd58d9fbd89b901c0540ba108ee",
            "payload": {
              "config": {
                "output": {"fps": 30},
                "tracks": [{"id": "picture", "kind": "visual", "role": "output", "label": "Picture"}]
              },
              "registry": {},
              "clips": [],
              "occurrences": [
                {
                  "occurrence_id": "occ-new",
                  "shot_id": "shot-new",
                  "shot_revision_id": "shot-new-1",
                  "track": "picture",
                  "placement": {"start_ms": 0, "track": "picture"},
                  "duration_ms": 2000,
                  "source_offset": 0,
                  "speed": 1,
                  "gain": 1
                }
              ]
            }
          },
          "shot_revisions": [
            {
              "shot_id": "shot-new",
              "revision_id": "shot-new-1",
              "internal_timeline_revision_id": "internal-new-1",
              "content_digest": "sha256:d6f9b8b3d85ccafca5c675759f43c6987433a57e34708a3848635a0b357f2306",
              "payload": {"name": "Opening", "items": [], "internal_timeline_revision_id": "internal-new-1"}
            }
          ],
          "internal_timeline_revisions": [
            {
              "timeline_id": "film-1",
              "revision_id": "internal-new-1",
              "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18",
              "payload": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
            }
          ],
          "dependency_manifest": {
            "shots": [
              {
                "shot_id": "shot-new",
                "revision_id": "shot-new-1",
                "internal_timeline_revision_id": "internal-new-1",
                "content_digest": "sha256:d6f9b8b3d85ccafca5c675759f43c6987433a57e34708a3848635a0b357f2306"
              }
            ],
            "internal_timelines": [
              {
                "timeline_id": "film-1",
                "revision_id": "internal-new-1",
                "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18"
              }
            ],
            "media": [],
            "documents": []
          }
        },
        "document_digest": "sha256:da282a5a1240e00d2e4516951ac1ed7a54b5e8d32171a4cefed83a4514b05508",
        "commands": [
          {
            "schema_version": 1,
            "op": "occurrence.create",
            "version": "1",
            "select": "parent",
            "args": {
              "occurrence_id": "occ-new",
              "shot_id": "shot-new",
              "name": "Opening",
              "track": "picture",
              "on": 0,
              "duration": 2
            },
            "created": ["shot:shot-new", "occurrence:occ-new"]
          }
        ],
        "id_map": {},
        "provider_version": "provider-v2",
        "compiler_version": "compiler-v2",
        "merge_mode": "fields",
        "steps": [
          {
            "id": "create",
            "label": "Create opening shot",
            "intent": "",
            "tags": [],
            "command_ordinals": [0],
            "patch": [
              {
                "op": "set",
                "ref": "internal:film-1",
                "path": [],
                "before": {"state": "absent"},
                "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
              },
              {
                "op": "set",
                "ref": "shot:shot-new",
                "path": [],
                "before": {"state": "absent"},
                "value": {"name": "Opening", "items": [], "internal_timeline_revision_id": "internal-new-1"}
              },
              {
                "op": "list.insert",
                "ref": "parent",
                "path": ["occurrences"],
                "id": "occ-new",
                "before": {"state": "absent"},
                "order_before": [],
                "after_id": null,
                "value": {
                  "occurrence_id": "occ-new",
                  "shot_id": "shot-new",
                  "shot_revision_id": "shot-new-1",
                  "track": "picture",
                  "placement": {"start_ms": 0, "track": "picture"},
                  "duration_ms": 2000,
                  "source_offset": 0,
                  "speed": 1,
                  "gain": 1
                }
              }
            ],
            "reads": [{"kind": "scope", "ref": "timeline", "path": []}],
            "dependencies": [{"kind": "scope", "ref": "timeline", "path": []}]
          }
        ],
        "publisher": "principal-7",
        "label": "Create opening shot"
      },
      "created_at": "2026-10-22T22:20:00Z"
    }
  },
  "undo_request": {
    "api_version": 1,
    "project_id": "project-1",
    "timeline_id": "film-1",
    "base_revision_id": "rev-create-1",
    "base_publication_id": "pub-create-1",
    "commands": [
      {
        "schema_version": 1,
        "op": "timeline.inverse",
        "version": "1",
        "select": null,
        "args": {"publications": ["pub-create-1"]}
      }
    ],
    "label": "Undo opening shot creation",
    "steps": [
      {
        "id": "undo",
        "label": "Undo opening shot creation",
        "intent": "",
        "tags": [],
        "command_ordinals": [0],
        "patch": []
      }
    ],
    "merge": "fields",
    "reads": []
  },
  "undo_reply": {
    "data": {
      "status": "accepted",
      "base_revision_id": "rev-create-1",
      "base_publication_id": "pub-create-1",
      "previous_revision_id": "rev-create-1",
      "previous_publication_id": "pub-create-1",
      "accepted_revision_id": "rev-create-2",
      "rebased_onto": null,
      "canonical_document": {
        "schema_version": 1,
        "project_id": "project-1",
        "timeline_id": "film-1",
        "parent_revision": {
          "revision_id": "rev-create-2",
          "content_digest": "sha256:7db6941424344f29682efe9425283892d2f45c9fc96bd20cf21faaa8256eb16a",
          "payload": {
            "config": {
              "output": {"fps": 30},
              "tracks": [{"id": "picture", "kind": "visual", "role": "output", "label": "Picture"}]
            },
            "registry": {},
            "clips": [],
            "occurrences": []
          }
        },
        "shot_revisions": [],
        "internal_timeline_revisions": [],
        "dependency_manifest": {"shots": [], "internal_timelines": [], "media": [], "documents": []}
      },
      "document_digest": "sha256:ecdacf571218d4cc951583296e5f75e1593cbcc72d64fa4f062597d38bd57689",
      "commands": [
        {
          "schema_version": 1,
          "op": "timeline.inverse",
          "version": "1",
          "select": null,
          "args": {"publications": ["pub-create-1"]}
        }
      ],
      "id_map": {},
      "provider_version": "provider-v2",
      "compiler_version": "compiler-v2",
      "merge_mode": "fields",
      "steps": [
        {
          "id": "undo",
          "label": "Undo opening shot creation",
          "intent": "",
          "tags": [],
          "command_ordinals": [0],
          "patch": [
            {
              "op": "list.remove",
              "ref": "parent",
              "path": ["occurrences"],
              "id": "occ-new",
              "before": {
                "state": "present",
                "value": {
                  "occurrence_id": "occ-new",
                  "shot_id": "shot-new",
                  "shot_revision_id": "shot-new-1",
                  "track": "picture",
                  "placement": {"start_ms": 0, "track": "picture"},
                  "duration_ms": 2000,
                  "source_offset": 0,
                  "speed": 1,
                  "gain": 1
                }
              },
              "order_before": ["occ-new"]
            },
            {
              "op": "remove",
              "ref": "shot:shot-new",
              "path": [],
              "before": {
                "state": "present",
                "value": {"name": "Opening", "items": [], "internal_timeline_revision_id": "internal-new-1"}
              }
            },
            {
              "op": "remove",
              "ref": "internal:film-1",
              "path": [],
              "before": {
                "state": "present",
                "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
              }
            }
          ],
          "dependencies": [{"kind": "scope", "ref": "timeline", "path": []}]
        }
      ],
      "publisher": "principal-7",
      "label": "Undo opening shot creation"
    },
    "receipt": {
      "receipt_id": "pub-create-2",
      "command_kind": "timeline.commit",
      "idempotency_key": "undo-opening",
      "request_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "project_id": "project-1",
      "project_seq": [3, 3],
      "event_ids": ["event-pub-create-2"],
      "result": {
        "status": "accepted",
        "base_revision_id": "rev-create-1",
        "base_publication_id": "pub-create-1",
        "previous_revision_id": "rev-create-1",
        "previous_publication_id": "pub-create-1",
        "accepted_revision_id": "rev-create-2",
        "rebased_onto": null,
        "canonical_document": {
          "schema_version": 1,
          "project_id": "project-1",
          "timeline_id": "film-1",
          "parent_revision": {
            "revision_id": "rev-create-2",
            "content_digest": "sha256:7db6941424344f29682efe9425283892d2f45c9fc96bd20cf21faaa8256eb16a",
            "payload": {
              "config": {
                "output": {"fps": 30},
                "tracks": [{"id": "picture", "kind": "visual", "role": "output", "label": "Picture"}]
              },
              "registry": {},
              "clips": [],
              "occurrences": []
            }
          },
          "shot_revisions": [],
          "internal_timeline_revisions": [],
          "dependency_manifest": {"shots": [], "internal_timelines": [], "media": [], "documents": []}
        },
        "document_digest": "sha256:ecdacf571218d4cc951583296e5f75e1593cbcc72d64fa4f062597d38bd57689",
        "commands": [
          {
            "schema_version": 1,
            "op": "timeline.inverse",
            "version": "1",
            "select": null,
            "args": {"publications": ["pub-create-1"]}
          }
        ],
        "id_map": {},
        "provider_version": "provider-v2",
        "compiler_version": "compiler-v2",
        "merge_mode": "fields",
        "steps": [
          {
            "id": "undo",
            "label": "Undo opening shot creation",
            "intent": "",
            "tags": [],
            "command_ordinals": [0],
            "patch": [
              {
                "op": "list.remove",
                "ref": "parent",
                "path": ["occurrences"],
                "id": "occ-new",
                "before": {
                  "state": "present",
                  "value": {
                    "occurrence_id": "occ-new",
                    "shot_id": "shot-new",
                    "shot_revision_id": "shot-new-1",
                    "track": "picture",
                    "placement": {"start_ms": 0, "track": "picture"},
                    "duration_ms": 2000,
                    "source_offset": 0,
                    "speed": 1,
                    "gain": 1
                  }
                },
                "order_before": ["occ-new"]
              },
              {
                "op": "remove",
                "ref": "shot:shot-new",
                "path": [],
                "before": {
                  "state": "present",
                  "value": {"name": "Opening", "items": [], "internal_timeline_revision_id": "internal-new-1"}
                }
              },
              {
                "op": "remove",
                "ref": "internal:film-1",
                "path": [],
                "before": {
                  "state": "present",
                  "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
                }
              }
            ],
            "dependencies": [{"kind": "scope", "ref": "timeline", "path": []}]
          }
        ],
        "publisher": "principal-7",
        "label": "Undo opening shot creation"
      },
      "created_at": "2026-10-22T22:20:00Z"
    }
  },
  "expected_history": {
    "created": [
      {"ref": "shot:shot-new", "kind": "shot", "owner": null},
      {"ref": "occurrence:occ-new", "kind": "occurrence", "owner": "parent"}
    ],
    "undo_of": ["pub-create-1"],
    "undo_steps": null
  },
  "redo_request": {
    "api_version": 1,
    "project_id": "project-1",
    "timeline_id": "film-1",
    "base_revision_id": "rev-create-2",
    "base_publication_id": "pub-create-2",
    "commands": [
      {
        "schema_version": 1,
        "op": "timeline.inverse",
        "version": "1",
        "select": null,
        "args": {"publications": ["pub-create-2"]}
      }
    ],
    "label": "Redo opening shot creation",
    "steps": [
      {
        "id": "undo",
        "label": "Redo opening shot creation",
        "intent": "",
        "tags": [],
        "command_ordinals": [0],
        "patch": []
      }
    ],
    "merge": "fields",
    "reads": []
  },
  "expected_redo": {
    "status": "accepted",
    "parent_payload": {
      "config": {
        "output": {"fps": 30},
        "tracks": [{"id": "picture", "kind": "visual", "role": "output", "label": "Picture"}]
      },
      "registry": {},
      "clips": [],
      "occurrences": [
        {
          "occurrence_id": "occ-new",
          "shot_id": "shot-new",
          "shot_revision_id": "shot-new-1",
          "track": "picture",
          "placement": {"start_ms": 0, "track": "picture"},
          "duration_ms": 2000,
          "source_offset": 0,
          "speed": 1,
          "gain": 1
        }
      ]
    },
    "shot_revisions": [
      {
        "shot_id": "shot-new",
        "revision_id": "shot-new-1",
        "internal_timeline_revision_id": "internal-new-1",
        "content_digest": "sha256:d6f9b8b3d85ccafca5c675759f43c6987433a57e34708a3848635a0b357f2306",
        "payload": {"name": "Opening", "items": [], "internal_timeline_revision_id": "internal-new-1"}
      }
    ],
    "internal_timeline_revisions": [
      {
        "timeline_id": "film-1",
        "revision_id": "internal-new-1",
        "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18",
        "payload": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
      }
    ],
    "created": ["shot:shot-new", "occurrence:occ-new"],
    "allocation_provenance": "inherit authenticated original allocation via pub-create-2"
  },
  "forbidden_patch_commands": [
    {
      "schema_version": 1,
      "op": "doc.patch",
      "version": "1",
      "select": null,
      "args": {
        "changes": [
          {
            "op": "set",
            "ref": "internal:film-1",
            "path": [],
            "before": {"state": "absent"},
            "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
          }
        ]
      }
    },
    {
      "schema_version": 1,
      "op": "doc.patch",
      "version": "1",
      "select": null,
      "args": {
        "changes": [
          {
            "op": "remove",
            "ref": "shot:shot-new",
            "path": [],
            "before": {
              "state": "present",
              "value": {"name": "Opening", "items": [], "internal_timeline_revision_id": "internal-new-1"}
            }
          }
        ]
      }
    },
    {
      "schema_version": 1,
      "op": "doc.patch",
      "version": "1",
      "select": null,
      "args": {
        "changes": [
          {
            "op": "set",
            "ref": "parent",
            "path": ["occurrences", "occurrence_id:occ-new", "shot_id"],
            "before": {"state": "present", "value": "shot-new"},
            "value": "shot-new"
          }
        ]
      }
    }
  ],
  "expected_forbidden": {"http_status": 422, "status": "invalid", "code": "managed_closure_write", "added_history_entries": 0}
}
```

### C0c: two created children, physical bindings and revision turnover

The following executable scenario is a fixture object, not one HTTP body.
`request` and each nested `request`/`ambiguous_request` are complete bodies with
fresh Idempotency-Keys named by their scenario keys. `reply_projection` omits the
already-specified full receipt/result envelope; `documents` and
`document_digests` supply complete expected closure states. `a` and `ab` are
verified sequential materialization boundaries inside the batch, not separately
published heads. Only `edited` is the batch's accepted state. Providers must
expose these intermediate images before a subsequent qualified operand uses
them, or refuse unsupported input; a producer must not guess their IDs. The
literal revision IDs stand for the verified IDs supplied by semantic
materialization, just as the existing single-child fixture uses fixture IDs.
Both children inherit `film-1`, even though ia1 and ib1 have equal payload bytes.
The patch edits only ia1. Its immutable successor ia2 changes the managed shot
and occurrence pins; ib1/sb1 stay unchanged. No alias in the effect union can
collapse ia1/ia2/ib1 or sa1/sa2 into an entity-ID dictionary.

`bindings_projection` and `materialization_projection` display required facts
from the authenticated recorder, not new request fields or proof that strings
are authenticated. Input-boundary digests may differ within one batch. Effect
bindings also retain side and physical revision/digest from the verified union:
creations bind after, removals before, and parent edge writes bind both parent
boundary images. The checker derives those bindings from the complete states.
Grouped inverse/redo `effect_boundaries` give half-open ranges in the flat effect
patch; each segment has its own verified before/after union. They retain transient restored roots
that appear in neither the command-entry nor command-exit closure.
The field-level input capture for edit-a remains ia1/output.fps 30→24 with
successor ia2; the expanded effect patch is not a submitted patch and cannot
bypass ownership.
The checks exercise the recorded transitions and binding rules, using Runtime's
canonical schema/digest validation. They do not authenticate real provider
materialization records, prove compiler visibility/attribution, or execute v2
rebase/undo. R1/R2/R2r must qualify those behaviors against these same requests.

Undo/redo branches start independently: undo-edit then redo-edit; or undo-all
then redo-all. Their expected payload states reuse `documents` but get fresh
parent revision/publication IDs in the reply projections. Undo edit restores ia1
and sa1 through authenticated source provenance; undo all reverses edit-a,
create-b, create-a. Redo all replays those boundaries in forward order with
inherited allocation provenance, not fresh allocations. Partial undo of create-a
alone refuses because edit-a survives; every refusal leaves its evaluated head
and history unchanged. The ambiguous-internal request reaches the two-child
boundary, refuses, and rolls back *both* creations. A lookup after the removal
of its last reachable owner likewise fails `outside_closure`.

`multi` is a separate authenticated base with two reachable shot-a revisions,
sa1 and sa2. An occurrence holds each pin. `shot:shot-a` refuses; the qualified
sa1 edit produces sa3 and changes only occ-a-old's edge. sa2/ia2 and shared ia1
stay intact. The final replay cases are binding probes: they test uniqueness
and authenticated continuation only; a full replay still applies read/write
and later-history guards. In particular an overlapping fps edit cannot merge
merely because a successor exists. Matching bytes on an unrelated child never
authorize retargeting.

```json
{
  "case": "C0c_two_children_and_shot_revisions",
  "documents": {
    "empty": {
      "schema_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "parent_revision": {
        "revision_id": "rev-c0",
        "content_digest": "sha256:7db6941424344f29682efe9425283892d2f45c9fc96bd20cf21faaa8256eb16a",
        "payload": {
          "config": {
            "output": {"fps": 30},
            "tracks": [{"id": "picture", "kind": "visual", "role": "output", "label": "Picture"}]
          },
          "registry": {},
          "clips": [],
          "occurrences": []
        }
      },
      "shot_revisions": [],
      "internal_timeline_revisions": [],
      "dependency_manifest": {"shots": [], "internal_timelines": [], "media": [], "documents": []}
    },
    "a": {
      "schema_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "parent_revision": {
        "revision_id": "rev-c1",
        "content_digest": "sha256:e346204627c0863213d52daaa81945a2fc55c8e1a748865f3ad346867976cb4d",
        "payload": {
          "config": {
            "output": {"fps": 30},
            "tracks": [{"id": "picture", "kind": "visual", "role": "output", "label": "Picture"}]
          },
          "registry": {},
          "clips": [],
          "occurrences": [
            {
              "occurrence_id": "occ-a",
              "shot_id": "shot-a",
              "shot_revision_id": "sa1",
              "track": "picture",
              "placement": {"start_ms": 0, "track": "picture"},
              "duration_ms": 2000,
              "source_offset": 0,
              "speed": 1,
              "gain": 1
            }
          ]
        }
      },
      "shot_revisions": [
        {
          "shot_id": "shot-a",
          "internal_timeline_revision_id": "ia1",
          "revision_id": "sa1",
          "content_digest": "sha256:117d90b8103422352f805cfab292feb3be00a4a08c21e1fc17d18113d7b05288",
          "payload": {"name": "A", "items": [], "internal_timeline_revision_id": "ia1"}
        }
      ],
      "internal_timeline_revisions": [
        {
          "timeline_id": "film-1",
          "revision_id": "ia1",
          "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18",
          "payload": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
        }
      ],
      "dependency_manifest": {
        "shots": [
          {
            "shot_id": "shot-a",
            "revision_id": "sa1",
            "internal_timeline_revision_id": "ia1",
            "content_digest": "sha256:117d90b8103422352f805cfab292feb3be00a4a08c21e1fc17d18113d7b05288"
          }
        ],
        "internal_timelines": [
          {
            "timeline_id": "film-1",
            "revision_id": "ia1",
            "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18"
          }
        ],
        "media": [],
        "documents": []
      }
    },
    "ab": {
      "schema_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "parent_revision": {
        "revision_id": "rev-c2",
        "content_digest": "sha256:83568c2f6c5fc93ac50909d7e0b812b9865cb17380b7d19968eb4f05b7818e78",
        "payload": {
          "config": {
            "output": {"fps": 30},
            "tracks": [{"id": "picture", "kind": "visual", "role": "output", "label": "Picture"}]
          },
          "registry": {},
          "clips": [],
          "occurrences": [
            {
              "occurrence_id": "occ-a",
              "shot_id": "shot-a",
              "shot_revision_id": "sa1",
              "track": "picture",
              "placement": {"start_ms": 0, "track": "picture"},
              "duration_ms": 2000,
              "source_offset": 0,
              "speed": 1,
              "gain": 1
            },
            {
              "occurrence_id": "occ-b",
              "shot_id": "shot-b",
              "shot_revision_id": "sb1",
              "track": "picture",
              "placement": {"start_ms": 2000, "track": "picture"},
              "duration_ms": 2000,
              "source_offset": 0,
              "speed": 1,
              "gain": 1
            }
          ]
        }
      },
      "shot_revisions": [
        {
          "shot_id": "shot-a",
          "internal_timeline_revision_id": "ia1",
          "revision_id": "sa1",
          "content_digest": "sha256:117d90b8103422352f805cfab292feb3be00a4a08c21e1fc17d18113d7b05288",
          "payload": {"name": "A", "items": [], "internal_timeline_revision_id": "ia1"}
        },
        {
          "shot_id": "shot-b",
          "internal_timeline_revision_id": "ib1",
          "revision_id": "sb1",
          "content_digest": "sha256:f27e0d4c5a37301033fa89f23bbc180f800f5088ae74316e02a7f0541c78822b",
          "payload": {"name": "B", "items": [], "internal_timeline_revision_id": "ib1"}
        }
      ],
      "internal_timeline_revisions": [
        {
          "timeline_id": "film-1",
          "revision_id": "ia1",
          "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18",
          "payload": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
        },
        {
          "timeline_id": "film-1",
          "revision_id": "ib1",
          "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18",
          "payload": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
        }
      ],
      "dependency_manifest": {
        "shots": [
          {
            "shot_id": "shot-a",
            "revision_id": "sa1",
            "internal_timeline_revision_id": "ia1",
            "content_digest": "sha256:117d90b8103422352f805cfab292feb3be00a4a08c21e1fc17d18113d7b05288"
          },
          {
            "shot_id": "shot-b",
            "revision_id": "sb1",
            "internal_timeline_revision_id": "ib1",
            "content_digest": "sha256:f27e0d4c5a37301033fa89f23bbc180f800f5088ae74316e02a7f0541c78822b"
          }
        ],
        "internal_timelines": [
          {
            "timeline_id": "film-1",
            "revision_id": "ia1",
            "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18"
          },
          {
            "timeline_id": "film-1",
            "revision_id": "ib1",
            "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18"
          }
        ],
        "media": [],
        "documents": []
      }
    },
    "edited": {
      "schema_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "parent_revision": {
        "revision_id": "rev-c3",
        "content_digest": "sha256:15f8f3c435bc65104d0456b01b356d0ddd6af8a5f71ac8d62af299ff6127de77",
        "payload": {
          "config": {
            "output": {"fps": 30},
            "tracks": [{"id": "picture", "kind": "visual", "role": "output", "label": "Picture"}]
          },
          "registry": {},
          "clips": [],
          "occurrences": [
            {
              "occurrence_id": "occ-a",
              "shot_id": "shot-a",
              "shot_revision_id": "sa2",
              "track": "picture",
              "placement": {"start_ms": 0, "track": "picture"},
              "duration_ms": 2000,
              "source_offset": 0,
              "speed": 1,
              "gain": 1
            },
            {
              "occurrence_id": "occ-b",
              "shot_id": "shot-b",
              "shot_revision_id": "sb1",
              "track": "picture",
              "placement": {"start_ms": 2000, "track": "picture"},
              "duration_ms": 2000,
              "source_offset": 0,
              "speed": 1,
              "gain": 1
            }
          ]
        }
      },
      "shot_revisions": [
        {
          "shot_id": "shot-a",
          "internal_timeline_revision_id": "ia2",
          "revision_id": "sa2",
          "content_digest": "sha256:3d02b808627b9bc0d9348d558d4792cd2f848ac02e7fde42517e38205b20ee81",
          "payload": {"name": "A", "items": [], "internal_timeline_revision_id": "ia2"}
        },
        {
          "shot_id": "shot-b",
          "internal_timeline_revision_id": "ib1",
          "revision_id": "sb1",
          "content_digest": "sha256:f27e0d4c5a37301033fa89f23bbc180f800f5088ae74316e02a7f0541c78822b",
          "payload": {"name": "B", "items": [], "internal_timeline_revision_id": "ib1"}
        }
      ],
      "internal_timeline_revisions": [
        {
          "timeline_id": "film-1",
          "revision_id": "ia2",
          "content_digest": "sha256:e6fe0947443b4d861dcaaa7bc76caebb789cd42de4be88de54ce2c76d2f53f74",
          "payload": {"output": {"fps": 24}, "tracks": [], "clips": [], "registry": {"assets": {}}}
        },
        {
          "timeline_id": "film-1",
          "revision_id": "ib1",
          "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18",
          "payload": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
        }
      ],
      "dependency_manifest": {
        "shots": [
          {
            "shot_id": "shot-a",
            "revision_id": "sa2",
            "internal_timeline_revision_id": "ia2",
            "content_digest": "sha256:3d02b808627b9bc0d9348d558d4792cd2f848ac02e7fde42517e38205b20ee81"
          },
          {
            "shot_id": "shot-b",
            "revision_id": "sb1",
            "internal_timeline_revision_id": "ib1",
            "content_digest": "sha256:f27e0d4c5a37301033fa89f23bbc180f800f5088ae74316e02a7f0541c78822b"
          }
        ],
        "internal_timelines": [
          {
            "timeline_id": "film-1",
            "revision_id": "ia2",
            "content_digest": "sha256:e6fe0947443b4d861dcaaa7bc76caebb789cd42de4be88de54ce2c76d2f53f74"
          },
          {
            "timeline_id": "film-1",
            "revision_id": "ib1",
            "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18"
          }
        ],
        "media": [],
        "documents": []
      }
    },
    "multi": {
      "schema_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "parent_revision": {
        "revision_id": "rev-m0",
        "content_digest": "sha256:fd9d43b9ec0b70a631eb59568cbff597044a94b30d9b8fab2818d3e6816a2fa7",
        "payload": {
          "config": {
            "output": {"fps": 30},
            "tracks": [{"id": "picture", "kind": "visual", "role": "output", "label": "Picture"}]
          },
          "registry": {},
          "clips": [],
          "occurrences": [
            {
              "occurrence_id": "occ-a",
              "shot_id": "shot-a",
              "shot_revision_id": "sa2",
              "track": "picture",
              "placement": {"start_ms": 0, "track": "picture"},
              "duration_ms": 2000,
              "source_offset": 0,
              "speed": 1,
              "gain": 1
            },
            {
              "occurrence_id": "occ-b",
              "shot_id": "shot-b",
              "shot_revision_id": "sb1",
              "track": "picture",
              "placement": {"start_ms": 2000, "track": "picture"},
              "duration_ms": 2000,
              "source_offset": 0,
              "speed": 1,
              "gain": 1
            },
            {
              "occurrence_id": "occ-a-old",
              "shot_id": "shot-a",
              "shot_revision_id": "sa1",
              "track": "picture",
              "placement": {"start_ms": 4000, "track": "picture"},
              "duration_ms": 2000,
              "source_offset": 0,
              "speed": 1,
              "gain": 1
            }
          ]
        }
      },
      "shot_revisions": [
        {
          "shot_id": "shot-a",
          "internal_timeline_revision_id": "ia1",
          "revision_id": "sa1",
          "content_digest": "sha256:117d90b8103422352f805cfab292feb3be00a4a08c21e1fc17d18113d7b05288",
          "payload": {"name": "A", "items": [], "internal_timeline_revision_id": "ia1"}
        },
        {
          "shot_id": "shot-a",
          "internal_timeline_revision_id": "ia2",
          "revision_id": "sa2",
          "content_digest": "sha256:3d02b808627b9bc0d9348d558d4792cd2f848ac02e7fde42517e38205b20ee81",
          "payload": {"name": "A", "items": [], "internal_timeline_revision_id": "ia2"}
        },
        {
          "shot_id": "shot-b",
          "internal_timeline_revision_id": "ib1",
          "revision_id": "sb1",
          "content_digest": "sha256:f27e0d4c5a37301033fa89f23bbc180f800f5088ae74316e02a7f0541c78822b",
          "payload": {"name": "B", "items": [], "internal_timeline_revision_id": "ib1"}
        }
      ],
      "internal_timeline_revisions": [
        {
          "timeline_id": "film-1",
          "revision_id": "ia1",
          "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18",
          "payload": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
        },
        {
          "timeline_id": "film-1",
          "revision_id": "ia2",
          "content_digest": "sha256:e6fe0947443b4d861dcaaa7bc76caebb789cd42de4be88de54ce2c76d2f53f74",
          "payload": {"output": {"fps": 24}, "tracks": [], "clips": [], "registry": {"assets": {}}}
        },
        {
          "timeline_id": "film-1",
          "revision_id": "ib1",
          "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18",
          "payload": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
        }
      ],
      "dependency_manifest": {
        "shots": [
          {
            "shot_id": "shot-a",
            "revision_id": "sa1",
            "internal_timeline_revision_id": "ia1",
            "content_digest": "sha256:117d90b8103422352f805cfab292feb3be00a4a08c21e1fc17d18113d7b05288"
          },
          {
            "shot_id": "shot-a",
            "revision_id": "sa2",
            "internal_timeline_revision_id": "ia2",
            "content_digest": "sha256:3d02b808627b9bc0d9348d558d4792cd2f848ac02e7fde42517e38205b20ee81"
          },
          {
            "shot_id": "shot-b",
            "revision_id": "sb1",
            "internal_timeline_revision_id": "ib1",
            "content_digest": "sha256:f27e0d4c5a37301033fa89f23bbc180f800f5088ae74316e02a7f0541c78822b"
          }
        ],
        "internal_timelines": [
          {
            "timeline_id": "film-1",
            "revision_id": "ia1",
            "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18"
          },
          {
            "timeline_id": "film-1",
            "revision_id": "ia2",
            "content_digest": "sha256:e6fe0947443b4d861dcaaa7bc76caebb789cd42de4be88de54ce2c76d2f53f74"
          },
          {
            "timeline_id": "film-1",
            "revision_id": "ib1",
            "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18"
          }
        ],
        "media": [],
        "documents": []
      }
    },
    "multi_edited": {
      "schema_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "parent_revision": {
        "revision_id": "rev-m1",
        "content_digest": "sha256:7feda6f8114e093b74b1a0534800b8e3aa6b07319507c42db978121e626ad18d",
        "payload": {
          "config": {
            "output": {"fps": 30},
            "tracks": [{"id": "picture", "kind": "visual", "role": "output", "label": "Picture"}]
          },
          "registry": {},
          "clips": [],
          "occurrences": [
            {
              "occurrence_id": "occ-a",
              "shot_id": "shot-a",
              "shot_revision_id": "sa2",
              "track": "picture",
              "placement": {"start_ms": 0, "track": "picture"},
              "duration_ms": 2000,
              "source_offset": 0,
              "speed": 1,
              "gain": 1
            },
            {
              "occurrence_id": "occ-b",
              "shot_id": "shot-b",
              "shot_revision_id": "sb1",
              "track": "picture",
              "placement": {"start_ms": 2000, "track": "picture"},
              "duration_ms": 2000,
              "source_offset": 0,
              "speed": 1,
              "gain": 1
            },
            {
              "occurrence_id": "occ-a-old",
              "shot_id": "shot-a",
              "shot_revision_id": "sa3",
              "track": "picture",
              "placement": {"start_ms": 4000, "track": "picture"},
              "duration_ms": 2000,
              "source_offset": 0,
              "speed": 1,
              "gain": 1
            }
          ]
        }
      },
      "shot_revisions": [
        {
          "shot_id": "shot-a",
          "internal_timeline_revision_id": "ia2",
          "revision_id": "sa2",
          "content_digest": "sha256:3d02b808627b9bc0d9348d558d4792cd2f848ac02e7fde42517e38205b20ee81",
          "payload": {"name": "A", "items": [], "internal_timeline_revision_id": "ia2"}
        },
        {
          "shot_id": "shot-a",
          "internal_timeline_revision_id": "ia1",
          "revision_id": "sa3",
          "content_digest": "sha256:a50939a571dd41c3b744cf65ca14a84a90b25417d8865b5c2f7e2fd47bbe8105",
          "payload": {"name": "Old branch", "items": [], "internal_timeline_revision_id": "ia1"}
        },
        {
          "shot_id": "shot-b",
          "internal_timeline_revision_id": "ib1",
          "revision_id": "sb1",
          "content_digest": "sha256:f27e0d4c5a37301033fa89f23bbc180f800f5088ae74316e02a7f0541c78822b",
          "payload": {"name": "B", "items": [], "internal_timeline_revision_id": "ib1"}
        }
      ],
      "internal_timeline_revisions": [
        {
          "timeline_id": "film-1",
          "revision_id": "ia1",
          "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18",
          "payload": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
        },
        {
          "timeline_id": "film-1",
          "revision_id": "ia2",
          "content_digest": "sha256:e6fe0947443b4d861dcaaa7bc76caebb789cd42de4be88de54ce2c76d2f53f74",
          "payload": {"output": {"fps": 24}, "tracks": [], "clips": [], "registry": {"assets": {}}}
        },
        {
          "timeline_id": "film-1",
          "revision_id": "ib1",
          "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18",
          "payload": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
        }
      ],
      "dependency_manifest": {
        "shots": [
          {
            "shot_id": "shot-a",
            "revision_id": "sa2",
            "internal_timeline_revision_id": "ia2",
            "content_digest": "sha256:3d02b808627b9bc0d9348d558d4792cd2f848ac02e7fde42517e38205b20ee81"
          },
          {
            "shot_id": "shot-a",
            "revision_id": "sa3",
            "internal_timeline_revision_id": "ia1",
            "content_digest": "sha256:a50939a571dd41c3b744cf65ca14a84a90b25417d8865b5c2f7e2fd47bbe8105"
          },
          {
            "shot_id": "shot-b",
            "revision_id": "sb1",
            "internal_timeline_revision_id": "ib1",
            "content_digest": "sha256:f27e0d4c5a37301033fa89f23bbc180f800f5088ae74316e02a7f0541c78822b"
          }
        ],
        "internal_timelines": [
          {
            "timeline_id": "film-1",
            "revision_id": "ia1",
            "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18"
          },
          {
            "timeline_id": "film-1",
            "revision_id": "ia2",
            "content_digest": "sha256:e6fe0947443b4d861dcaaa7bc76caebb789cd42de4be88de54ce2c76d2f53f74"
          },
          {
            "timeline_id": "film-1",
            "revision_id": "ib1",
            "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18"
          }
        ],
        "media": [],
        "documents": []
      }
    }
  },
  "document_digests": {
    "empty": "sha256:f8cc39f9ebed677fce15fdf5f4b13bb8ca6b034df3be8e339ab4f79cc4437b1e",
    "a": "sha256:80d16e39eea6c6395ee32d56b1476b82fbd0eb0fb0b07840db247ee05d0c9f4b",
    "ab": "sha256:e8ac1463f7a421f9a0f2f484eb59dc44ac1f495d37321717e60caa94f4308c2b",
    "edited": "sha256:40cb47bc1214194d7d9affb9e02c2da48173183afd7c33ab146ae0ae2e8d0623",
    "multi": "sha256:cf755404c00ec7c702533d256fd79d5b6d9a883f902904e05dabe90825facc2f",
    "multi_edited": "sha256:83f68f81759a41c7de2f71b270c6471531dd5dca9641ccb4870a9eebd96c44a5"
  },
  "request": {
    "api_version": 1,
    "project_id": "project-1",
    "timeline_id": "film-1",
    "base_revision_id": "rev-c0",
    "base_publication_id": "pub-c0",
    "commands": [
      {
        "schema_version": 1,
        "op": "occurrence.create",
        "version": "1",
        "select": "parent",
        "args": {"occurrence_id": "occ-a", "shot_id": "shot-a", "name": "A", "track": "picture", "on": 0, "duration": 2},
        "created": ["shot:shot-a", "occurrence:occ-a"]
      },
      {
        "schema_version": 1,
        "op": "occurrence.create",
        "version": "1",
        "select": "parent",
        "args": {"occurrence_id": "occ-b", "shot_id": "shot-b", "name": "B", "track": "picture", "on": 2, "duration": 2},
        "created": ["shot:shot-b", "occurrence:occ-b"]
      },
      {
        "schema_version": 1,
        "op": "doc.patch",
        "version": "1",
        "select": null,
        "args": {
          "changes": [
            {
              "op": "set",
              "ref": "internal-revision:ia1",
              "path": ["output", "fps"],
              "before": {"state": "present", "value": 30},
              "value": 24
            }
          ]
        }
      }
    ],
    "label": "Create two children and edit A",
    "steps": [
      {
        "id": "create-a",
        "label": "create-a",
        "intent": "",
        "tags": [],
        "command_ordinals": [0],
        "patch": [],
        "reads": [{"kind": "scope", "ref": "timeline", "path": []}]
      },
      {
        "id": "create-b",
        "label": "create-b",
        "intent": "",
        "tags": [],
        "command_ordinals": [1],
        "patch": [],
        "reads": [{"kind": "scope", "ref": "timeline", "path": []}]
      },
      {
        "id": "edit-a",
        "label": "edit-a",
        "intent": "",
        "tags": [],
        "command_ordinals": [2],
        "patch": [
          {
            "op": "set",
            "ref": "internal-revision:ia1",
            "path": ["output", "fps"],
            "before": {"state": "present", "value": 30},
            "value": 24
          }
        ],
        "reads": [
          {
            "kind": "field",
            "ref": "internal-revision:ia1",
            "path": ["output", "fps"],
            "state": {"state": "present", "value": 30}
          }
        ]
      }
    ],
    "merge": "fields",
    "reads": []
  },
  "reply_projection": {
    "data": {
      "status": "accepted",
      "base_revision_id": "rev-c0",
      "base_publication_id": "pub-c0",
      "accepted_revision_id": "rev-c3",
      "steps": [
        {
          "id": "create-a",
          "label": "create-a",
          "intent": "",
          "tags": [],
          "command_ordinals": [0],
          "patch": [
            {
              "op": "set",
              "ref": "internal-revision:ia1",
              "path": [],
              "before": {"state": "absent"},
              "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
            },
            {
              "op": "set",
              "ref": "shot-revision:sa1",
              "path": [],
              "before": {"state": "absent"},
              "value": {"name": "A", "items": [], "internal_timeline_revision_id": "ia1"}
            },
            {
              "op": "list.insert",
              "ref": "parent",
              "path": ["occurrences"],
              "id": "occ-a",
              "before": {"state": "absent"},
              "value": {
                "occurrence_id": "occ-a",
                "shot_id": "shot-a",
                "shot_revision_id": "sa1",
                "track": "picture",
                "placement": {"start_ms": 0, "track": "picture"},
                "duration_ms": 2000,
                "source_offset": 0,
                "speed": 1,
                "gain": 1
              },
              "order_before": [],
              "after_id": null
            }
          ],
          "dependencies": [{"kind": "scope", "ref": "timeline", "path": []}]
        },
        {
          "id": "create-b",
          "label": "create-b",
          "intent": "",
          "tags": [],
          "command_ordinals": [1],
          "patch": [
            {
              "op": "set",
              "ref": "internal-revision:ib1",
              "path": [],
              "before": {"state": "absent"},
              "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
            },
            {
              "op": "set",
              "ref": "shot-revision:sb1",
              "path": [],
              "before": {"state": "absent"},
              "value": {"name": "B", "items": [], "internal_timeline_revision_id": "ib1"}
            },
            {
              "op": "list.insert",
              "ref": "parent",
              "path": ["occurrences"],
              "id": "occ-b",
              "before": {"state": "absent"},
              "value": {
                "occurrence_id": "occ-b",
                "shot_id": "shot-b",
                "shot_revision_id": "sb1",
                "track": "picture",
                "placement": {"start_ms": 2000, "track": "picture"},
                "duration_ms": 2000,
                "source_offset": 0,
                "speed": 1,
                "gain": 1
              },
              "order_before": ["occ-a"],
              "after_id": "occ-a"
            }
          ],
          "dependencies": [{"kind": "scope", "ref": "timeline", "path": []}]
        },
        {
          "id": "edit-a",
          "label": "edit-a",
          "intent": "",
          "tags": [],
          "command_ordinals": [2],
          "patch": [
            {
              "op": "set",
              "ref": "internal-revision:ia2",
              "path": [],
              "before": {"state": "absent"},
              "value": {"output": {"fps": 24}, "tracks": [], "clips": [], "registry": {"assets": {}}}
            },
            {
              "op": "set",
              "ref": "shot-revision:sa2",
              "path": [],
              "before": {"state": "absent"},
              "value": {"name": "A", "items": [], "internal_timeline_revision_id": "ia2"}
            },
            {
              "op": "set",
              "ref": "parent",
              "path": ["occurrences", "occurrence_id:occ-a", "shot_revision_id"],
              "before": {"state": "present", "value": "sa1"},
              "value": "sa2"
            },
            {
              "op": "remove",
              "ref": "shot-revision:sa1",
              "path": [],
              "before": {"state": "present", "value": {"name": "A", "items": [], "internal_timeline_revision_id": "ia1"}}
            },
            {
              "op": "remove",
              "ref": "internal-revision:ia1",
              "path": [],
              "before": {
                "state": "present",
                "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
              }
            }
          ],
          "dependencies": [
            {
              "kind": "field",
              "ref": "internal-revision:ia1",
              "path": ["output", "fps"],
              "state": {"state": "present", "value": 30}
            }
          ]
        }
      ]
    },
    "receipt": {"receipt_id": "pub-c3"}
  },
  "step_states": ["a", "ab", "edited"],
  "bindings_projection": [
    {
      "ref": "parent",
      "physical_ref": "parent",
      "revision_id": "rev-c0",
      "content_digest": "sha256:7db6941424344f29682efe9425283892d2f45c9fc96bd20cf21faaa8256eb16a",
      "boundary": {
        "base_revision_id": "rev-c0",
        "base_publication_id": "pub-c0",
        "evaluated_head": {"revision_id": "rev-c0", "publication_id": "pub-c0"},
        "step_id": "create-a",
        "command_ordinal": 0,
        "phase": "input"
      }
    },
    {
      "ref": "parent",
      "physical_ref": "parent",
      "content_digest": "sha256:e346204627c0863213d52daaa81945a2fc55c8e1a748865f3ad346867976cb4d",
      "boundary": {
        "base_revision_id": "rev-c0",
        "base_publication_id": "pub-c0",
        "evaluated_head": {"revision_id": "rev-c0", "publication_id": "pub-c0"},
        "step_id": "create-b",
        "command_ordinal": 1,
        "phase": "input"
      },
      "revision_id": "rev-c1"
    },
    {
      "ref": "internal-revision:ia1",
      "physical_ref": "internal-revision:ia1",
      "content_digest": "sha256:44480cc6477dcc476f4a2b1c694dd95918b819ab0a98aec573cb360072201a18",
      "boundary": {
        "base_revision_id": "rev-c0",
        "base_publication_id": "pub-c0",
        "evaluated_head": {"revision_id": "rev-c0", "publication_id": "pub-c0"},
        "step_id": "edit-a",
        "command_ordinal": 2,
        "change_ordinal": 0,
        "phase": "input"
      },
      "revision_id": "ia1"
    }
  ],
  "materialization_projection": [
    {
      "step_id": "edit-a",
      "source": "internal-revision:ia1",
      "successor": "internal-revision:ia2",
      "owner": "occurrence:occ-a/shot",
      "edge_before": "shot-revision:sa1",
      "edge_after": "shot-revision:sa2"
    },
    {
      "step_id": "edit-a",
      "source": "shot-revision:sa1",
      "successor": "shot-revision:sa2",
      "owner": "occurrence:occ-a/shot",
      "edge_before": "internal-revision:ia1",
      "edge_after": "internal-revision:ia2"
    }
  ],
  "ambiguous_internal": {
    "request": {
      "api_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "base_revision_id": "rev-c0",
      "base_publication_id": "pub-c0",
      "commands": [
        {
          "schema_version": 1,
          "op": "occurrence.create",
          "version": "1",
          "select": "parent",
          "args": {"occurrence_id": "occ-a", "shot_id": "shot-a", "name": "A", "track": "picture", "on": 0, "duration": 2},
          "created": ["shot:shot-a", "occurrence:occ-a"]
        },
        {
          "schema_version": 1,
          "op": "occurrence.create",
          "version": "1",
          "select": "parent",
          "args": {"occurrence_id": "occ-b", "shot_id": "shot-b", "name": "B", "track": "picture", "on": 2, "duration": 2},
          "created": ["shot:shot-b", "occurrence:occ-b"]
        },
        {
          "schema_version": 1,
          "op": "doc.patch",
          "version": "1",
          "select": null,
          "args": {
            "changes": [
              {
                "op": "set",
                "ref": "internal:film-1",
                "path": ["output", "fps"],
                "before": {"state": "present", "value": 30},
                "value": 24
              }
            ]
          }
        }
      ],
      "label": "Create two children and edit A",
      "steps": [
        {
          "id": "create-a",
          "label": "create-a",
          "intent": "",
          "tags": [],
          "command_ordinals": [0],
          "patch": [],
          "reads": [{"kind": "scope", "ref": "timeline", "path": []}]
        },
        {
          "id": "create-b",
          "label": "create-b",
          "intent": "",
          "tags": [],
          "command_ordinals": [1],
          "patch": [],
          "reads": [{"kind": "scope", "ref": "timeline", "path": []}]
        },
        {
          "id": "edit-a",
          "label": "edit-a",
          "intent": "",
          "tags": [],
          "command_ordinals": [2],
          "patch": [
            {
              "op": "set",
              "ref": "internal:film-1",
              "path": ["output", "fps"],
              "before": {"state": "present", "value": 30},
              "value": 24
            }
          ],
          "reads": []
        }
      ],
      "merge": "fields",
      "reads": []
    },
    "http_status": 422,
    "reply": {
      "code": "invalid",
      "message": "Use internal-revision:ia1 or internal-revision:ib1.",
      "details": {
        "status": "invalid",
        "code": "ambiguous_ref",
        "reason": "ambiguous_ref",
        "path": ["commands", "2", "args", "changes", "0", "ref"],
        "hint": "Use internal-revision:ia1 or internal-revision:ib1.",
        "suggested_command": "timeline show --history"
      }
    },
    "expected_head": {"revision_id": "rev-c0", "publication_id": "pub-c0"},
    "added_history_entries": 0
  },
  "undo_edit": {
    "request": {
      "api_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "base_revision_id": "rev-c3",
      "base_publication_id": "pub-c3",
      "commands": [
        {
          "schema_version": 1,
          "op": "timeline.inverse",
          "version": "1",
          "select": null,
          "args": {"publications": ["pub-c3"], "steps": {"pub-c3": ["edit-a"]}}
        }
      ],
      "label": "Undo A edit",
      "steps": [{"id": "inverse", "label": "inverse", "intent": "", "tags": [], "command_ordinals": [0], "patch": []}],
      "merge": "fields",
      "reads": []
    },
    "reply_projection": {
      "data": {
        "status": "accepted",
        "accepted_revision_id": "rev-c4",
        "steps": [
          {
            "id": "inverse",
            "label": "inverse",
            "intent": "",
            "tags": [],
            "command_ordinals": [0],
            "patch": [
              {
                "op": "set",
                "ref": "internal-revision:ia1",
                "path": [],
                "before": {"state": "absent"},
                "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
              },
              {
                "op": "set",
                "ref": "shot-revision:sa1",
                "path": [],
                "before": {"state": "absent"},
                "value": {"name": "A", "items": [], "internal_timeline_revision_id": "ia1"}
              },
              {
                "op": "set",
                "ref": "parent",
                "path": ["occurrences", "occurrence_id:occ-a", "shot_revision_id"],
                "before": {"state": "present", "value": "sa2"},
                "value": "sa1"
              },
              {
                "op": "remove",
                "ref": "shot-revision:sa2",
                "path": [],
                "before": {"state": "present", "value": {"name": "A", "items": [], "internal_timeline_revision_id": "ia2"}}
              },
              {
                "op": "remove",
                "ref": "internal-revision:ia2",
                "path": [],
                "before": {
                  "state": "present",
                  "value": {"output": {"fps": 24}, "tracks": [], "clips": [], "registry": {"assets": {}}}
                }
              }
            ]
          }
        ]
      },
      "receipt": {"receipt_id": "pub-c4"}
    },
    "expected_payload_state": "ab",
    "restoration_sources": ["pub-c3:edit-a"]
  },
  "redo_edit": {
    "request": {
      "api_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "base_revision_id": "rev-c4",
      "base_publication_id": "pub-c4",
      "commands": [
        {
          "schema_version": 1,
          "op": "timeline.inverse",
          "version": "1",
          "select": null,
          "args": {"publications": ["pub-c4"]}
        }
      ],
      "label": "Redo A edit",
      "steps": [{"id": "inverse", "label": "inverse", "intent": "", "tags": [], "command_ordinals": [0], "patch": []}],
      "merge": "fields",
      "reads": []
    },
    "reply_projection": {
      "data": {
        "status": "accepted",
        "accepted_revision_id": "rev-c5",
        "steps": [
          {
            "id": "inverse",
            "label": "inverse",
            "intent": "",
            "tags": [],
            "command_ordinals": [0],
            "patch": [
              {
                "op": "set",
                "ref": "internal-revision:ia2",
                "path": [],
                "before": {"state": "absent"},
                "value": {"output": {"fps": 24}, "tracks": [], "clips": [], "registry": {"assets": {}}}
              },
              {
                "op": "set",
                "ref": "shot-revision:sa2",
                "path": [],
                "before": {"state": "absent"},
                "value": {"name": "A", "items": [], "internal_timeline_revision_id": "ia2"}
              },
              {
                "op": "set",
                "ref": "parent",
                "path": ["occurrences", "occurrence_id:occ-a", "shot_revision_id"],
                "before": {"state": "present", "value": "sa1"},
                "value": "sa2"
              },
              {
                "op": "remove",
                "ref": "shot-revision:sa1",
                "path": [],
                "before": {"state": "present", "value": {"name": "A", "items": [], "internal_timeline_revision_id": "ia1"}}
              },
              {
                "op": "remove",
                "ref": "internal-revision:ia1",
                "path": [],
                "before": {
                  "state": "present",
                  "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
                }
              }
            ]
          }
        ]
      },
      "receipt": {"receipt_id": "pub-c5"}
    },
    "expected_payload_state": "edited",
    "restoration_sources": ["pub-c4", "pub-c3:edit-a"]
  },
  "undo_all": {
    "request": {
      "api_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "base_revision_id": "rev-c3",
      "base_publication_id": "pub-c3",
      "commands": [
        {
          "schema_version": 1,
          "op": "timeline.inverse",
          "version": "1",
          "select": null,
          "args": {"publications": ["pub-c3"]}
        }
      ],
      "label": "Undo both creations and edit",
      "steps": [{"id": "inverse", "label": "inverse", "intent": "", "tags": [], "command_ordinals": [0], "patch": []}],
      "merge": "fields",
      "reads": []
    },
    "reply_projection": {
      "data": {
        "status": "accepted",
        "accepted_revision_id": "rev-c6",
        "steps": [
          {
            "id": "inverse",
            "label": "inverse",
            "intent": "",
            "tags": [],
            "command_ordinals": [0],
            "patch": [
              {
                "op": "set",
                "ref": "internal-revision:ia1",
                "path": [],
                "before": {"state": "absent"},
                "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
              },
              {
                "op": "set",
                "ref": "shot-revision:sa1",
                "path": [],
                "before": {"state": "absent"},
                "value": {"name": "A", "items": [], "internal_timeline_revision_id": "ia1"}
              },
              {
                "op": "set",
                "ref": "parent",
                "path": ["occurrences", "occurrence_id:occ-a", "shot_revision_id"],
                "before": {"state": "present", "value": "sa2"},
                "value": "sa1"
              },
              {
                "op": "remove",
                "ref": "shot-revision:sa2",
                "path": [],
                "before": {"state": "present", "value": {"name": "A", "items": [], "internal_timeline_revision_id": "ia2"}}
              },
              {
                "op": "remove",
                "ref": "internal-revision:ia2",
                "path": [],
                "before": {
                  "state": "present",
                  "value": {"output": {"fps": 24}, "tracks": [], "clips": [], "registry": {"assets": {}}}
                }
              },
              {
                "op": "list.remove",
                "ref": "parent",
                "path": ["occurrences"],
                "id": "occ-b",
                "before": {
                  "state": "present",
                  "value": {
                    "occurrence_id": "occ-b",
                    "shot_id": "shot-b",
                    "shot_revision_id": "sb1",
                    "track": "picture",
                    "placement": {"start_ms": 2000, "track": "picture"},
                    "duration_ms": 2000,
                    "source_offset": 0,
                    "speed": 1,
                    "gain": 1
                  }
                },
                "order_before": ["occ-a", "occ-b"]
              },
              {
                "op": "remove",
                "ref": "shot-revision:sb1",
                "path": [],
                "before": {"state": "present", "value": {"name": "B", "items": [], "internal_timeline_revision_id": "ib1"}}
              },
              {
                "op": "remove",
                "ref": "internal-revision:ib1",
                "path": [],
                "before": {
                  "state": "present",
                  "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
                }
              },
              {
                "op": "list.remove",
                "ref": "parent",
                "path": ["occurrences"],
                "id": "occ-a",
                "before": {
                  "state": "present",
                  "value": {
                    "occurrence_id": "occ-a",
                    "shot_id": "shot-a",
                    "shot_revision_id": "sa1",
                    "track": "picture",
                    "placement": {"start_ms": 0, "track": "picture"},
                    "duration_ms": 2000,
                    "source_offset": 0,
                    "speed": 1,
                    "gain": 1
                  }
                },
                "order_before": ["occ-a"]
              },
              {
                "op": "remove",
                "ref": "shot-revision:sa1",
                "path": [],
                "before": {"state": "present", "value": {"name": "A", "items": [], "internal_timeline_revision_id": "ia1"}}
              },
              {
                "op": "remove",
                "ref": "internal-revision:ia1",
                "path": [],
                "before": {
                  "state": "present",
                  "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
                }
              }
            ]
          }
        ]
      },
      "receipt": {"receipt_id": "pub-c6"}
    },
    "expected_payload_state": "empty",
    "restoration_sources": ["pub-c3"],
    "effect_boundaries": [
      {"before": "edited", "after": "ab", "range": [0, 5]},
      {"before": "ab", "after": "a", "range": [5, 8]},
      {"before": "a", "after": "empty", "range": [8, 11]}
    ]
  },
  "redo_all": {
    "request": {
      "api_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "base_revision_id": "rev-c6",
      "base_publication_id": "pub-c6",
      "commands": [
        {
          "schema_version": 1,
          "op": "timeline.inverse",
          "version": "1",
          "select": null,
          "args": {"publications": ["pub-c6"]}
        }
      ],
      "label": "Redo both creations and edit",
      "steps": [{"id": "inverse", "label": "inverse", "intent": "", "tags": [], "command_ordinals": [0], "patch": []}],
      "merge": "fields",
      "reads": []
    },
    "reply_projection": {
      "data": {
        "status": "accepted",
        "accepted_revision_id": "rev-c7",
        "steps": [
          {
            "id": "inverse",
            "label": "inverse",
            "intent": "",
            "tags": [],
            "command_ordinals": [0],
            "patch": [
              {
                "op": "set",
                "ref": "internal-revision:ia1",
                "path": [],
                "before": {"state": "absent"},
                "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
              },
              {
                "op": "set",
                "ref": "shot-revision:sa1",
                "path": [],
                "before": {"state": "absent"},
                "value": {"name": "A", "items": [], "internal_timeline_revision_id": "ia1"}
              },
              {
                "op": "list.insert",
                "ref": "parent",
                "path": ["occurrences"],
                "id": "occ-a",
                "before": {"state": "absent"},
                "value": {
                  "occurrence_id": "occ-a",
                  "shot_id": "shot-a",
                  "shot_revision_id": "sa1",
                  "track": "picture",
                  "placement": {"start_ms": 0, "track": "picture"},
                  "duration_ms": 2000,
                  "source_offset": 0,
                  "speed": 1,
                  "gain": 1
                },
                "order_before": [],
                "after_id": null
              },
              {
                "op": "set",
                "ref": "internal-revision:ib1",
                "path": [],
                "before": {"state": "absent"},
                "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
              },
              {
                "op": "set",
                "ref": "shot-revision:sb1",
                "path": [],
                "before": {"state": "absent"},
                "value": {"name": "B", "items": [], "internal_timeline_revision_id": "ib1"}
              },
              {
                "op": "list.insert",
                "ref": "parent",
                "path": ["occurrences"],
                "id": "occ-b",
                "before": {"state": "absent"},
                "value": {
                  "occurrence_id": "occ-b",
                  "shot_id": "shot-b",
                  "shot_revision_id": "sb1",
                  "track": "picture",
                  "placement": {"start_ms": 2000, "track": "picture"},
                  "duration_ms": 2000,
                  "source_offset": 0,
                  "speed": 1,
                  "gain": 1
                },
                "order_before": ["occ-a"],
                "after_id": "occ-a"
              },
              {
                "op": "set",
                "ref": "internal-revision:ia2",
                "path": [],
                "before": {"state": "absent"},
                "value": {"output": {"fps": 24}, "tracks": [], "clips": [], "registry": {"assets": {}}}
              },
              {
                "op": "set",
                "ref": "shot-revision:sa2",
                "path": [],
                "before": {"state": "absent"},
                "value": {"name": "A", "items": [], "internal_timeline_revision_id": "ia2"}
              },
              {
                "op": "set",
                "ref": "parent",
                "path": ["occurrences", "occurrence_id:occ-a", "shot_revision_id"],
                "before": {"state": "present", "value": "sa1"},
                "value": "sa2"
              },
              {
                "op": "remove",
                "ref": "shot-revision:sa1",
                "path": [],
                "before": {"state": "present", "value": {"name": "A", "items": [], "internal_timeline_revision_id": "ia1"}}
              },
              {
                "op": "remove",
                "ref": "internal-revision:ia1",
                "path": [],
                "before": {
                  "state": "present",
                  "value": {"output": {"fps": 30}, "tracks": [], "clips": [], "registry": {"assets": {}}}
                }
              }
            ]
          }
        ]
      },
      "receipt": {"receipt_id": "pub-c7"}
    },
    "expected_payload_state": "edited",
    "restoration_sources": ["pub-c6", "pub-c3"],
    "effect_boundaries": [
      {"before": "empty", "after": "a", "range": [0, 3]},
      {"before": "a", "after": "ab", "range": [3, 6]},
      {"before": "ab", "after": "edited", "range": [6, 11]}
    ]
  },
  "undo_creation_only": {
    "request": {
      "api_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "base_revision_id": "rev-c3",
      "base_publication_id": "pub-c3",
      "commands": [
        {
          "schema_version": 1,
          "op": "timeline.inverse",
          "version": "1",
          "select": null,
          "args": {"publications": ["pub-c3"], "steps": {"pub-c3": ["create-a"]}}
        }
      ],
      "label": "Undo A creation only",
      "steps": [{"id": "inverse", "label": "inverse", "intent": "", "tags": [], "command_ordinals": [0], "patch": []}],
      "merge": "fields",
      "reads": []
    },
    "http_status": 409,
    "reply": {
      "code": "conflict",
      "message": "Undo the whole creation batch, including dependent steps.",
      "details": {
        "status": "conflict",
        "code": "surviving_dependents",
        "reason": "surviving_dependents",
        "path": ["commands", "0"],
        "hint": "Undo the whole creation batch, including dependent steps.",
        "suggested_command": "timeline show --history",
        "current": {"revision_id": "rev-c3", "publication_id": "pub-c3"}
      }
    },
    "added_history_entries": 0
  },
  "multiple_shot_revisions": {
    "base_state": "multi",
    "request": {
      "api_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "base_revision_id": "rev-m0",
      "base_publication_id": "pub-m0",
      "commands": [
        {
          "schema_version": 1,
          "op": "doc.patch",
          "version": "1",
          "select": null,
          "args": {
            "changes": [
              {
                "op": "set",
                "ref": "shot-revision:sa1",
                "path": ["name"],
                "before": {"state": "present", "value": "A"},
                "value": "Old branch"
              }
            ]
          }
        }
      ],
      "label": "Edit only the old shot revision",
      "steps": [
        {
          "id": "old-shot",
          "label": "old-shot",
          "intent": "",
          "tags": [],
          "command_ordinals": [0],
          "patch": [
            {
              "op": "set",
              "ref": "shot-revision:sa1",
              "path": ["name"],
              "before": {"state": "present", "value": "A"},
              "value": "Old branch"
            }
          ]
        }
      ],
      "merge": "fields",
      "reads": []
    },
    "reply_projection": {
      "data": {
        "status": "accepted",
        "accepted_revision_id": "rev-m1",
        "steps": [
          {
            "id": "old-shot",
            "label": "old-shot",
            "intent": "",
            "tags": [],
            "command_ordinals": [0],
            "patch": [
              {
                "op": "set",
                "ref": "shot-revision:sa3",
                "path": [],
                "before": {"state": "absent"},
                "value": {"name": "Old branch", "items": [], "internal_timeline_revision_id": "ia1"}
              },
              {
                "op": "set",
                "ref": "parent",
                "path": ["occurrences", "occurrence_id:occ-a-old", "shot_revision_id"],
                "before": {"state": "present", "value": "sa1"},
                "value": "sa3"
              },
              {
                "op": "remove",
                "ref": "shot-revision:sa1",
                "path": [],
                "before": {"state": "present", "value": {"name": "A", "items": [], "internal_timeline_revision_id": "ia1"}}
              }
            ]
          }
        ]
      },
      "receipt": {"receipt_id": "pub-m1"}
    },
    "expected_state": "multi_edited",
    "ambiguous_request": {
      "api_version": 1,
      "project_id": "project-1",
      "timeline_id": "film-1",
      "base_revision_id": "rev-m0",
      "base_publication_id": "pub-m0",
      "commands": [
        {
          "schema_version": 1,
          "op": "doc.patch",
          "version": "1",
          "select": null,
          "args": {
            "changes": [
              {
                "op": "set",
                "ref": "shot:shot-a",
                "path": ["name"],
                "before": {"state": "present", "value": "A"},
                "value": "Old branch"
              }
            ]
          }
        }
      ],
      "label": "Edit only the old shot revision",
      "steps": [
        {
          "id": "old-shot",
          "label": "old-shot",
          "intent": "",
          "tags": [],
          "command_ordinals": [0],
          "patch": [
            {
              "op": "set",
              "ref": "shot:shot-a",
              "path": ["name"],
              "before": {"state": "present", "value": "A"},
              "value": "Old branch"
            }
          ]
        }
      ],
      "merge": "fields",
      "reads": []
    },
    "http_status": 422,
    "ambiguous_reply": {
      "code": "invalid",
      "message": "Use shot-revision:sa1 or shot-revision:sa2.",
      "details": {
        "status": "invalid",
        "code": "ambiguous_ref",
        "reason": "ambiguous_ref",
        "path": ["commands", "0", "args", "changes", "0", "ref"],
        "hint": "Use shot-revision:sa1 or shot-revision:sa2.",
        "suggested_command": "timeline show --history"
      }
    },
    "added_history_entries_on_refusal": 0
  },
  "replay_cases": [
    {
      "case": "new_second_match",
      "base_state": "a",
      "landing_state": "ab",
      "ref": "internal:film-1",
      "bound": "internal-revision:ia1",
      "expected": "ambiguous_ref"
    },
    {
      "case": "unique_unrelated_same_bytes",
      "base_state": "a",
      "landing_state": "only_b",
      "ref": "internal:film-1",
      "bound": "internal-revision:ia1",
      "expected": "binding_changed"
    },
    {
      "case": "authenticated_successor",
      "base_state": "a",
      "landing_state": "only_edited_a",
      "ref": "internal:film-1",
      "bound": "internal-revision:ia1",
      "expected": "internal-revision:ia2"
    },
    {
      "case": "qualified_without_provenance",
      "base_state": "a",
      "landing_state": "only_edited_a",
      "ref": "internal-revision:ia1",
      "bound": "internal-revision:ia1",
      "expected": "binding_changed"
    }
  ]
}
```

## 6. `meta` namespaces: placement, limits and preservation

`meta` is an optional JSON object on authored parent composition payloads,
TimelineConfig payloads (parent and internal), shot payloads, occurrence rows,
clip rows, track rows, and registry asset records. It does not belong on immutable
revision-image wrappers, manifests, commands or receipts. A parent payload's
`meta` and its config's `meta` are distinct locations; no mirroring or merging
between them is implied.

Each `meta` key is a namespace matching
`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`, 1–128 ASCII characters. Use reverse-domain
names for application/extension data (`org.example.notes`). Namespace values
are JSON objects; their descendants may be any finite JSON value including null
and arrays. No executable values, nonfinite numbers or implicit references.
`meta: null` and a namespace value of null are invalid; remove the namespace or
`meta` key explicitly to clear it. Empty objects are valid and stay empty.

Limits, measured independently at each `meta` occurrence in the final candidate:
at most 64 namespaces, at most 65,536 canonical UTF-8 bytes per namespace value,
at most 262,144 canonical UTF-8 bytes for the whole `meta` object, and at most
32 nested container levels below a namespace value (its root object is level
one). Canonical size uses the same compact sorted-key UTF-8 encoding as Runtime
digests. Exceeding a limit is invalid (`meta_limit_exceeded`) with the offending
path and a hint. These are schema/validation limits for V1/V2 to implement;
existing HTTP body limits may reject a larger request earlier.

Unknown namespaces and contents are preserved verbatim as JSON values through
load, patch, semantic edit, compile, acceptance, history read and undo. Do not
insert defaults, normalize strings, strip unknown keys or reorder arrays.
Verbatim means value preservation, not original whitespace/object key order.
Composition and renderers ignore unknown `meta`; it cannot alter timing or
structural validation. Namespace keys grant no write privilege. Normal field
and ancestor overlap rules apply: two leaf edits in different namespaces can
merge under `fields`; replacing the entire `meta` object guards all namespaces.
Strings in `meta` that look like IDs receive no reference integrity, remapping,
automatic deletion or dependency tracking; a script depending on them declares
reads. Core reference/asset discovery must not interpret opaque `meta` descendants
as schema-owned media references or append phantom manifest entries.

Preservation scenario (the set carries the entire previous namespace value):

```json
{
  "before": {
    "meta": {
      "org.example.notes": {"note": "A", "tags": ["rough"]},
      "com.other.tool": {"foreign_id": "missing-is-allowed", "nullable": null, "items": [2, 1]}
    }
  },
  "change": {
    "op": "set", "ref": "parent", "path": ["meta", "org.example.notes"],
    "before": {"state": "present", "value": {"note": "A", "tags": ["rough"]}},
    "value": {"note": "B", "tags": ["rough"]}
  },
  "expected": {
    "meta": {
      "org.example.notes": {"note": "B", "tags": ["rough"]},
      "com.other.tool": {"foreign_id": "missing-is-allowed", "nullable": null, "items": [2, 1]}
    }
  },
  "invalid_namespace_value": {"meta": {"org.example.notes": null}},
  "expected_invalid_code": "invalid_meta"
}
```

## 7. History: labels, steps and authoritative attribution

Store accepted label, steps (including complete provider effect patches,
verified step reads and authoritative dependencies), requested/effective
merge modes and declared request reads with the existing immutable acceptance/history
entry, including the resolved physical bindings and authenticated successor/edge
provenance from §2. `records.commands` remains the provider's authoritative command recorder;
add `records.steps` for authoritative step boundaries/patches/dependencies, and `undo_steps`
as in §5. No parallel evidence ledger is introduced. Keep source, rationale,
group ID, previous head pair, publication/revision IDs, receipt,
provider/compiler versions and `records.undo_of`.

The authenticated Runtime `publisher` is the authoritative actor, also stored
on the durable receipt-bound history entry and accepted event. `source.via`,
`source.detail`, labels, tags and prose intent describe the client request and
cannot override actor identity. Do not accept client `publisher`/`actor` fields
as attribution. History/read replay must agree with the accepted result, not
reconstruct authorship from an App user name or a script string.

The existing history operation lists entries in acceptance order with
`items`, `next_cursor`, and a pinned `head` pair. Read at a chosen `through` pair;
all pages share that pair and scope. Use the existing cursor/limit behavior
(1–200, default 100), contiguous ancestry verification and authenticated reads.
Do not mix a newly moved head into an existing pagination walk. List and
single-entry reads return labels, steps and authoritative publisher without
requiring a second metadata store. Legacy entries retain
`intent: "legacy_unknown"`, missing attribution as null and missing step records as
null/absent; never invent steps or guarded undo evidence for them. Preview,
invalid, conflict, refused and unknown outcomes add no accepted history entries.

History-entry projection for the accepted example (projection omits the already
shown receipt and full command recorder; actual entries include both):

```json
{
  "publication_id": "pub-1",
  "revision_id": "rev-1",
  "previous": {
    "revision_id": "rev-0",
    "publication_id": "pub-0"
  },
  "intent": "recorded",
  "publisher": "principal-7",
  "label": "Clarify opening note",
  "source": {
    "via": "python",
    "detail": "notes.py"
  },
  "merge": "fields",
  "merge_mode": "fields",
  "reads": [],
  "steps": [
    {
      "id": "note-1",
      "label": "Revise the first note",
      "intent": "Clarify the opening",
      "tags": [
        "notes"
      ],
      "command_ordinals": [
        0
      ],
      "patch": [
        {
          "op": "set",
          "ref": "parent",
          "path": [
            "clips",
            "id:clip-1",
            "meta",
            "org.example.notes",
            "note"
          ],
          "before": {
            "state": "present",
            "value": "A"
          },
          "value": "B"
        }
      ]
    }
  ],
  "records": {
    "steps": [
      {
        "id": "note-1",
        "label": "Revise the first note",
        "intent": "Clarify the opening",
        "tags": [
          "notes"
        ],
        "command_ordinals": [
          0
        ],
        "patch": [
          {
            "op": "set",
            "ref": "parent",
            "path": [
              "clips",
              "id:clip-1",
              "meta",
              "org.example.notes",
              "note"
            ],
            "before": {
              "state": "present",
              "value": "A"
            },
            "value": "B"
          }
        ]
      }
    ],
    "undo_of": [],
    "undo_steps": null,
    "restored_from": null
  },
  "provider_version": "provider-v2",
  "compiler_version": "compiler-v2"
}
```

Implementation responsibilities follow PLAN §3: R1 implements patch/guard/read
semantics and Runtime store integration; R2 implements guarded whole/per-step
undo; R2r persists/lists labels, steps and authoritative attribution; R3 extends
preview and structured errors; V1/V2 adopt metadata and validation; A2 consumes
canonical replies through the persisted outbox; G2 provides the bounded Python
function re-run. Existing passing behavior tests stay in place. C0 changes only
this contract and its identical orchestrator design copy. C0b amends those same
two files only; C0c amends their addressing rules and executable fixtures.
C0b corrected existing fixture track kinds from `video` to the schema enum
`visual`, with recomputed digests and canonical-schema checks; implementation
and behavioral qualification belong to R1/R2/R2r.
The Runtime Python project/CI configure pytest but no prose lint or typecheck
gate. The TypeScript client has a `tsc` build/test gate; it is N/A to these
Markdown-only edits. The targeted generator tests below still exercise its DTO
type fixtures. No full, browser or live-socket suite is required for C0b/C0c.

Example parsing and copy equality were checked from the runtime worktree with:

```bash
python - <<'PY'
import json
import re
from pathlib import Path

repo = Path('contract/commit-v2.md')
shared = Path('/tmp/claude-0/-home-user-repo/7dc61be1-7066-52e0-a5d0-94f90e61430a/scratchpad/orch/design/commit-v2.md')
assert repo.read_bytes() == shared.read_bytes()
def unique_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError('duplicate JSON object keys')
    return result

for path in (repo, shared):
    source = path.read_text()
    blocks = re.findall(r'^```json\n(.*?)^```$', source, re.M | re.S)
    assert len(blocks) == 20
    for index, block in enumerate(blocks, 1):
        json.loads(block, object_pairs_hook=unique_object, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    assert len(re.findall(r'^## [1-7]\. ', source, re.M)) == 7
    print(f'{path}: {len(blocks)} JSON blocks parsed; 7 required headings')
PY
```

The following fixture-consistency check also passed. It uses the existing
Runtime digest/schema validators and applies the displayed effect transitions to fixture
values; it does not run an unimplemented v2 provider or prove refusal, causal
compiler capture, allocation authentication, rebase or replay behavior:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. /home/user/work/venv-runtime/bin/python - <<'PY'
import copy
import json
import re
from pathlib import Path
from runtime_protocol.timeline_commit_validation import digest, validate_commit_value

source = Path('contract/commit-v2.md').read_text()
examples = [json.loads(block) for block in re.findall(r'^```json\n(.*?)^```$', source, re.M | re.S)]
request, shapes, clears, structural, idless, created, reads, conflicts, accepted, merged, conflict, invalid, preview, undo, undo_cases, sequential, creation, addressing, meta, history = examples
for outcome in (accepted, merged, preview):
    data = outcome['data']
    document = data['canonical_document']
    validate_commit_value(document, 'CanonicalDocument')
    assert digest(document) == data['document_digest']
    assert digest(document['parent_revision']['payload']) == document['parent_revision']['content_digest']
    assert data['commands'] == request['commands']
    assert data['steps'] == request['steps']
for outcome in (accepted, merged):
    assert outcome['receipt']['result'] == outcome['data']
    assert outcome['receipt']['receipt_id'] == outcome['data']['accepted_revision_id'].replace('rev-', 'pub-')
assert preview['receipt'] is None and preview['data']['would_status'] == 'merged'
assert merged['data']['previous_revision_id'] == merged['data']['rebased_onto']['revision_id']
assert merged['data']['previous_publication_id'] == merged['data']['rebased_onto']['publication_id']
assert merged['data']['canonical_document']['parent_revision']['payload']['config']['tracks'][0]['label'] == 'Opening'
assert accepted['data']['canonical_document']['parent_revision']['payload']['config']['tracks'][0]['label'] == 'Picture'
assert history['steps'] == history['records']['steps'] == request['steps']
assert [i for step in request['steps'] for i in step['command_ordinals']] == list(range(len(request['commands'])))
assert [change for step in request['steps'] for change in step['patch']] == [change for command in request['commands'] for change in command['args']['changes']]
rows = copy.deepcopy(structural['initial'])
for change in structural['changes']:
    assert [row['id'] for row in rows] == change['order_before']
    before = next((row for row in rows if row['id'] == change['id']), None)
    assert change['before'] == ({'state': 'present', 'value': before} if before else {'state': 'absent'})
    if change['op'] == 'list.insert':
        row = change['value']
    else:
        row = rows.pop(next(i for i, row in enumerate(rows) if row['id'] == change['id']))
    if change['op'] != 'list.remove':
        anchor = change['after_id']
        index = 0 if anchor is None else next(i for i, row in enumerate(rows) if row['id'] == anchor) + 1
        rows.insert(index, row)
assert [row['id'] for row in rows] == structural['expected_ids']
assert shapes['missing'] != shapes['explicit_null']
assert conflict['details']['current'] and invalid['details']['code'] == idless['expected_invalid_code']
assert all(key in failure['details'] for failure in (conflict, invalid) for key in ('code', 'path', 'hint', 'suggested_command'))
aba = next(case for case in undo_cases if case['case'] == 'A_to_B_to_A')
assert aba['target']['after'] == aba['current'] == aba['later'][-1]['after']
assert aba['expected'] == 'conflict' and aba['reason'] == 'intervening_write'
assert meta['before']['meta']['com.other.tool'] == meta['expected']['meta']['com.other.tool']
# C0b: consistency of complete closures/receipts and effect transitions. This
# checks fixture arithmetic and guards, not the provider's acceptance/undo path.
for outcome in (creation['reply'], creation['undo_reply']):
    data = outcome['data']
    document = data['canonical_document']
    validate_commit_value(document, 'CanonicalDocument')
    assert digest(document) == data['document_digest']
    for image in [document['parent_revision'], *document['shot_revisions'], *document['internal_timeline_revisions']]:
        assert digest(image['payload']) == image['content_digest']
    assert document['dependency_manifest']['shots'] == [
        {k: image[k] for k in ('shot_id', 'revision_id', 'internal_timeline_revision_id', 'content_digest')}
        for image in document['shot_revisions']]
    assert document['dependency_manifest']['internal_timelines'] == [
        {k: image[k] for k in ('timeline_id', 'revision_id', 'content_digest')}
        for image in document['internal_timeline_revisions']]
    shots = {image['shot_id']: image for image in document['shot_revisions']}
    internals = {image['revision_id']: image for image in document['internal_timeline_revisions']}
    assert {row['shot_id'] for row in document['parent_revision']['payload']['occurrences']} == set(shots)
    for row in document['parent_revision']['payload']['occurrences']:
        assert row['shot_revision_id'] == shots[row['shot_id']]['revision_id']
    for image in shots.values():
        assert image['payload']['internal_timeline_revision_id'] == image['internal_timeline_revision_id']
        assert image['internal_timeline_revision_id'] in internals
    assert outcome['receipt']['result'] == data
    assert outcome['receipt']['receipt_id'] == data['accepted_revision_id'].replace('rev-', 'pub-')
    assert data['steps'][0]['dependencies'] == [{'kind': 'scope', 'ref': 'timeline', 'path': []}]
for scenario in (sequential, creation):
    document = scenario['base_document']
    validate_commit_value(document, 'CanonicalDocument')
    assert digest(document['parent_revision']['payload']) == document['parent_revision']['content_digest']
    body = scenario['request']
    assert [i for step in body['steps'] for i in step['command_ordinals']] == list(range(len(body['commands'])))

def roots(document):
    pairs = [('parent', document['parent_revision']['payload'])]
    pairs += [('shot:' + image['shot_id'], image['payload']) for image in document['shot_revisions']]
    pairs += [('internal:' + image['timeline_id'], image['payload']) for image in document['internal_timeline_revisions']]
    assert len({ref for ref, value in pairs}) == len(pairs)
    return copy.deepcopy(dict(pairs))

def location(state, ref, path):
    if not path:
        return state, ref
    node = state[ref]
    for token in path[:-1]:
        if isinstance(node, list):
            key, value = token.split(':', 1)
            node = next(row for row in node if row['id' if key == 'id' else key] == value)
        else:
            node = node[token]
    return node, path[-1]

def tagged(node, key):
    return {'state': 'present', 'value': copy.deepcopy(node[key])} if key in node else {'state': 'absent'}

def apply_effects(state, effects):
    for effect in effects:
        node, key = location(state, effect['ref'], effect['path'])
        if effect['op'].startswith('list.'):
            rows = node[key]
            assert effect['path'] == ['occurrences']
            assert [row['occurrence_id'] for row in rows] == effect['order_before']
            index = next((i for i, row in enumerate(rows) if row['occurrence_id'] == effect['id']), None)
            actual = {'state': 'absent'} if index is None else {'state': 'present', 'value': rows[index]}
            assert actual == effect['before']
            if effect['op'] == 'list.insert':
                assert index is None
                anchor = effect['after_id']
                offset = 0 if anchor is None else next(i for i, row in enumerate(rows) if row['occurrence_id'] == anchor) + 1
                rows.insert(offset, copy.deepcopy(effect['value']))
            else:
                assert effect['op'] == 'list.remove'
                rows.pop(index)
        else:
            assert tagged(node, key) == effect['before']
            if effect['op'] == 'set':
                node[key] = copy.deepcopy(effect['value'])
            else:
                assert effect['op'] == 'remove'
                del node[key]

state = roots(sequential['base_document'])
for step in sequential['request']['steps']:
    for read in step['reads']:
        node, key = location(state, read['ref'], read['path'])
        assert tagged(node, key) == read['state']
    assert step['patch'] == [change for i in step['command_ordinals'] for change in sequential['request']['commands'][i]['args']['changes']]
    apply_effects(state, step['patch'])
assert state['parent'] == sequential['expected_commit']['parent_payload']
dependency = sequential['expected_commit']['steps'][1]['dependencies'][0]
first = sequential['request']['steps'][0]['patch'][0]
assert (dependency['ref'], dependency['path']) == (first['ref'], first['path'])
assert dependency['state'] == {'state': 'present', 'value': first['value']}
assert dependency['state'] != first['before']  # B is not the batch-entry A.
assert sequential['expected_refusal']['details']['reason'] == 'inverse_conflict'
assert sequential['expected_after_refusal']['added_history_entries'] == 0
assert sequential['undo_first_request']['commands'][0]['args']['steps'] == {'pub-reads-1': ['first']}
assert sequential['undo_both_request']['commands'][0]['args']['steps'] == {'pub-reads-1': ['first', 'second']}
apply_effects(state, sequential['expected_undo']['patch'])
assert state == roots(sequential['base_document'])
assert state['parent'] == sequential['expected_undo']['parent_payload']
assert sequential['expected_undo']['reversed_steps'] == ['second', 'first']
variant = sequential['request_read_variant']
assert variant['reads'][0]['state'] == first['before']
assert variant['expected_dependencies'] == [variant['reads'], variant['reads'] + [dependency]]
assert sequential['uncaptured_variant']['required_dependencies_per_step'] == [{'kind': 'scope', 'ref': 'parent', 'path': []}]
assert sequential['uncaptured_variant']['expected_merge_mode'] == 'atomic'
state = roots(creation['base_document'])
apply_effects(state, creation['reply']['data']['steps'][0]['patch'])
assert state == roots(creation['reply']['data']['canonical_document'])
apply_effects(state, creation['undo_reply']['data']['steps'][0]['patch'])
assert state == roots(creation['base_document']) == roots(creation['undo_reply']['data']['canonical_document'])
assert creation['request']['steps'][0]['patch'] == creation['undo_request']['steps'][0]['patch'] == []
assert creation['reply']['data']['commands'] == creation['request']['commands']
assert creation['undo_reply']['data']['commands'] == creation['undo_request']['commands']
assert creation['undo_request']['commands'][0]['args']['publications'] == [creation['reply']['receipt']['receipt_id']]
assert creation['redo_request']['commands'][0]['args']['publications'] == [creation['undo_reply']['receipt']['receipt_id']]
assert creation['request']['commands'][0]['created'] == [item['ref'] for item in creation['expected_history']['created']]
assert creation['expected_history']['undo_of'] == ['pub-create-1']
for key in ('shot_revisions', 'internal_timeline_revisions'):
    assert creation['expected_redo'][key] == creation['reply']['data']['canonical_document'][key]
assert creation['expected_redo']['parent_payload'] == creation['reply']['data']['canonical_document']['parent_revision']['payload']
assert creation['expected_forbidden']['code'] == 'managed_closure_write'
assert creation['forbidden_patch_commands'][0]['args']['changes'][0]['before'] == {'state': 'absent'}
assert creation['forbidden_patch_commands'][1]['args']['changes'][0]['op'] == 'remove'
assert creation['forbidden_patch_commands'][2]['args']['changes'][0]['path'][-1] == 'shot_id'
# C0c: bind physical images; execute all displayed creation/edit/inverse/redo
# effects and verify pins at every boundary. This is a contract model, not the
# provider implementation or cryptographic provenance verification.
class RefError(Exception):
    pass

def image_pairs(document):
    return [('parent', document['parent_revision'])] + [
        ('shot-revision:' + im['revision_id'], im) for im in document['shot_revisions']
    ] + [('internal-revision:' + im['revision_id'], im)
         for im in document['internal_timeline_revisions']]

def physical_roots(document):
    pairs = image_pairs(document)
    assert len(dict(pairs)) == len(pairs)
    return {ref: copy.deepcopy(im['payload']) for ref, im in pairs}

def resolve(document, ref):
    if ref == 'parent':
        return ref, document['parent_revision']
    if ref.startswith('occurrence:'):
        owner, suffix = ref.split('/', 1)
        assert suffix == 'shot'
        row = next(row for row in document['parent_revision']['payload']['occurrences']
                   if row['occurrence_id'] == owner.removeprefix('occurrence:'))
        return resolve(document, 'shot-revision:' + row['shot_revision_id'])
    kind, identity = ref.split(':', 1)
    family = 'shot_revisions' if kind.startswith('shot') else 'internal_timeline_revisions'
    key = 'revision_id' if kind.endswith('-revision') else 'shot_id' if kind == 'shot' else 'timeline_id'
    matches = [im for im in document[family] if im[key] == identity]
    if not matches:
        raise RefError('outside_closure')
    if len(matches) != 1:
        raise RefError('ambiguous_ref')
    physical = ('shot-revision:' if family == 'shot_revisions' else 'internal-revision:') + matches[0]['revision_id']
    return physical, matches[0]

def ref_error(document, ref):
    try:
        resolve(document, ref)
    except RefError as exc:
        return str(exc)
    raise AssertionError('expected a refused lookup: ' + ref)

def validate_document(document):
    validate_commit_value(document, 'CanonicalDocument')
    pairs = image_pairs(document)
    assert len(dict(pairs)) == len(pairs)
    for ref, im in pairs:
        assert digest(im['payload']) == im['content_digest']
    shots = document['shot_revisions']
    internals = document['internal_timeline_revisions']
    assert shots == sorted(shots, key=lambda im: (im['shot_id'], im['revision_id']))
    assert internals == sorted(internals, key=lambda im: (im['timeline_id'], im['revision_id']))
    manifest = document['dependency_manifest']
    assert manifest['shots'] == [{k: im[k] for k in ('shot_id', 'revision_id', 'internal_timeline_revision_id', 'content_digest')} for im in shots]
    assert manifest['internal_timelines'] == [{k: im[k] for k in ('timeline_id', 'revision_id', 'content_digest')} for im in internals]
    rows = document['parent_revision']['payload']['occurrences']
    assert len({row['occurrence_id'] for row in rows}) == len(rows)
    assert {(row['shot_id'], row['shot_revision_id']) for row in rows} == {(im['shot_id'], im['revision_id']) for im in shots}
    assert {im['internal_timeline_revision_id'] for im in shots} == {im['revision_id'] for im in internals}
    for im in shots:
        assert im['payload']['internal_timeline_revision_id'] == im['internal_timeline_revision_id']

def verify_effect_bindings(before, after, effects):
    # Only authenticated execution may supply this union. Alias ambiguity is
    # checked across both sides, even if each side separately has one match.
    union = copy.deepcopy(before)
    for family in ('shot_revisions', 'internal_timeline_revisions'):
        images = {im['revision_id']: im for im in before[family]}
        for im in after[family]:
            assert im['revision_id'] not in images or im == images[im['revision_id']]
            images[im['revision_id']] = im
        union[family] = list(images.values())
    for effect in effects:
        physical, im = resolve(union, effect['ref'])
        assert physical == effect['ref']  # This fixture uses normalized refs.
        if not effect['path']:
            side = after if effect['op'] == 'set' else before
            bound, side_image = resolve(side, physical)
            assert bound == physical and side_image['content_digest'] == im['content_digest']
            payload = effect['value'] if effect['op'] == 'set' else effect['before']['value']
            assert payload == im['payload']
    state = physical_roots(before)
    apply_effects(state, effects)
    assert state == physical_roots(after)
    return union

states = addressing['documents']
for name, document in states.items():
    validate_document(document)
    assert digest(document) == addressing['document_digests'][name]
assert states['ab']['internal_timeline_revisions'][0]['content_digest'] == states['ab']['internal_timeline_revisions'][1]['content_digest']
body = addressing['request']
steps = addressing['reply_projection']['data']['steps']
assert addressing['reply_projection']['data']['accepted_revision_id'] == states['edited']['parent_revision']['revision_id']
assert [i for st in body['steps'] for i in st['command_ordinals']] == list(range(len(body['commands'])))
state = states['empty']
for ordinal, (submitted, actual, name, binding) in enumerate(zip(body['steps'], steps, addressing['step_states'], addressing['bindings_projection'])):
    assert submitted['command_ordinals'] == actual['command_ordinals'] == [ordinal]
    assert submitted['id'] == actual['id'] == binding['boundary']['step_id']
    assert binding['boundary']['base_revision_id'] == body['base_revision_id']
    assert binding['boundary']['base_publication_id'] == body['base_publication_id']
    assert binding['boundary']['command_ordinal'] == ordinal and binding['boundary']['phase'] == 'input'
    physical, im = resolve(state, binding['ref'])
    assert physical == binding['physical_ref'] and im['content_digest'] == binding['content_digest']
    assert im['revision_id'] == binding['revision_id']
    assert binding['boundary']['evaluated_head'] == {'revision_id': body['base_revision_id'], 'publication_id': body['base_publication_id']}
    for dependency in submitted['reads']:
        if dependency['ref'] != 'timeline':
            bound, _ = resolve(state, dependency['ref'])
            node, key = location(physical_roots(state), bound, dependency['path'])
            assert tagged(node, key) == dependency['state']
    assert actual['dependencies'] == submitted['reads']
    if body['commands'][ordinal]['op'] == 'doc.patch':
        assert submitted['patch'] == body['commands'][ordinal]['args']['changes']
        authored = physical_roots(state)
        apply_effects(authored, submitted['patch'])
        assert authored['internal-revision:ia1'] == physical_roots(states[name])['internal-revision:ia2']
    if body['commands'][ordinal]['op'] == 'occurrence.create':
        cmd = body['commands'][ordinal]
        args = cmd['args']
        occurrence = actual['patch'][-1]['value']
        assert occurrence['occurrence_id'] == args['occurrence_id']
        assert occurrence['shot_id'] == args['shot_id']
        assert occurrence['placement']['start_ms'] == args['on'] * 1000
        assert occurrence['duration_ms'] == args['duration'] * 1000
        _, shot = resolve(states[name], 'shot-revision:' + occurrence['shot_revision_id'])
        assert shot['payload']['name'] == args['name']
        assert cmd['created'] == ['shot:' + args['shot_id'], 'occurrence:' + args['occurrence_id']]
    verify_effect_bindings(state, states[name], actual['patch'])
    state = states[name]
assert resolve(states['a'], 'internal:film-1')[0] == 'internal-revision:ia1'
assert resolve(states['a'], 'shot:shot-a')[0] == resolve(states['a'], 'occurrence:occ-a/shot')[0] == 'shot-revision:sa1'
assert ref_error(states['empty'], 'internal-revision:ia1') == 'outside_closure'
assert ref_error(states['ab'], 'internal:film-1') == 'ambiguous_ref'
assert ref_error(states['multi'], 'shot:shot-a') == 'ambiguous_ref'
union = verify_effect_bindings(states['ab'], states['edited'], steps[2]['patch'])
assert ref_error(union, 'shot:shot-a') == 'ambiguous_ref'  # Unique on each side.
assert ref_error(union, 'internal:film-1') == 'ambiguous_ref'
for fact in addressing['materialization_projection']:
    assert fact['source'] in physical_roots(states['ab'])
    assert fact['successor'] in physical_roots(states['edited'])
    assert fact['owner'] == 'occurrence:occ-a/shot'
assert 'internal-revision:ib1' in physical_roots(states['edited'])
assert physical_roots(states['ab'])['internal-revision:ib1'] == physical_roots(states['edited'])['internal-revision:ib1']

# A small transactional contract model uses supplied authoritative transitions;
# it checks operand bindings and rolls back staging when any lookup fails.
# It does not implement occurrence.create or prove provider transactionality.
def contract_transaction(initial, request, authoritative, outputs):
    staged = physical_roots(initial)
    boundary = initial
    visited = 0
    try:
        for submitted, recorded, output in zip(request['steps'], authoritative, outputs):
            for read in submitted.get('reads', []):
                if read['ref'] != 'timeline':
                    bound, _ = resolve(boundary, read['ref'])
                    node, key = location(staged, bound, read['path'])
                    assert tagged(node, key) == read['state']
            for ordinal in submitted['command_ordinals']:
                command = request['commands'][ordinal]
                if command['op'] == 'doc.patch':
                    for change in command['args']['changes']:
                        bound, _ = resolve(boundary, change['ref'])
                        node, key = location(staged, bound, change['path'])
                        assert tagged(node, key) == change['before']
            apply_effects(staged, recorded['patch'])
            assert staged == physical_roots(output)
            boundary, visited = output, visited + 1
        return 'accepted', staged, visited
    except RefError as exc:
        return str(exc), physical_roots(initial), visited

outcome, staged, visited = contract_transaction(states['empty'], body, steps,
                                               [states[name] for name in addressing['step_states']])
assert outcome == 'accepted' and staged == physical_roots(states['edited']) and visited == 3
bad = addressing['ambiguous_internal']
assert bad['request']['steps'][2]['patch'] == bad['request']['commands'][2]['args']['changes']
outcome, staged, visited = contract_transaction(states['empty'], bad['request'], steps,
                                               [states[name] for name in addressing['step_states']])
assert outcome == bad['reply']['details']['code'] == 'ambiguous_ref' and visited == 2
assert staged == physical_roots(states['empty'])
assert bad['http_status'] == 422 and bad['added_history_entries'] == 0
assert bad['expected_head'] == {'revision_id': body['base_revision_id'], 'publication_id': body['base_publication_id']}

for key, before in (('undo_edit', 'edited'), ('redo_edit', 'ab'), ('undo_all', 'edited'), ('redo_all', 'empty')):
    scenario = addressing[key]
    after = scenario['expected_payload_state']
    effects = scenario['reply_projection']['data']['steps'][0]['patch']
    boundaries = scenario.get('effect_boundaries', [{'before': before, 'after': after, 'range': [0, len(effects)]}])
    cursor = 0
    previous = before
    for boundary in boundaries:
        start, end = boundary['range']
        assert start == cursor and end > start and boundary['before'] == previous
        verify_effect_bindings(states[boundary['before']], states[boundary['after']], effects[start:end])
        cursor, previous = end, boundary['after']
    assert cursor == len(effects) and previous == after
    combined = physical_roots(states[before])
    apply_effects(combined, effects)
    assert combined == physical_roots(states[after])
    assert scenario['request']['steps'][0]['patch'] == []
    assert scenario['request']['commands'][0]['op'] == 'timeline.inverse'
    assert scenario['restoration_sources']
assert addressing['undo_edit']['request']['commands'][0]['args']['steps'] == {'pub-c3': ['edit-a']}
for redo, undo in (('redo_edit', 'undo_edit'), ('redo_all', 'undo_all')):
    assert addressing[redo]['request']['commands'][0]['args']['publications'] == [addressing[undo]['reply_projection']['receipt']['receipt_id']]
    assert addressing[redo]['request']['base_publication_id'] == addressing[undo]['reply_projection']['receipt']['receipt_id']
partial = addressing['undo_creation_only']
assert partial['request']['commands'][0]['args']['steps'] == {'pub-c3': ['create-a']}
created_refs = {effect['ref'] for effect in steps[0]['patch'] if effect['path'] == []}
consumed_refs = {dependency['ref'] for dependency in steps[2]['dependencies']}
assert created_refs & consumed_refs == {'internal-revision:ia1'}
assert partial['reply']['details']['code'] == 'surviving_dependents' and partial['added_history_entries'] == 0

multiple = addressing['multiple_shot_revisions']
change = multiple['request']['commands'][0]['args']['changes'][0]
assert multiple['request']['steps'][0]['patch'] == [change]
assert multiple['request']['base_revision_id'] == states['multi']['parent_revision']['revision_id']
assert resolve(states['multi'], change['ref'])[0] == 'shot-revision:sa1'
authored = physical_roots(states['multi'])
apply_effects(authored, [change])
assert authored['shot-revision:sa1'] == physical_roots(states['multi_edited'])['shot-revision:sa3']
verify_effect_bindings(states['multi'], states['multi_edited'], multiple['reply_projection']['data']['steps'][0]['patch'])
assert ref_error(states['multi'], multiple['ambiguous_request']['commands'][0]['args']['changes'][0]['ref']) == multiple['ambiguous_reply']['details']['code']
msteps = multiple['reply_projection']['data']['steps']
for key, expected in (('request', 'accepted'), ('ambiguous_request', 'ambiguous_ref')):
    outcome, staged, visited = contract_transaction(states['multi'], multiple[key], msteps, [states['multi_edited']])
    assert outcome == expected
    assert staged == physical_roots(states['multi_edited' if outcome == 'accepted' else 'multi'])
assert multiple['added_history_entries_on_refusal'] == 0
for ref in ('shot-revision:sa2', 'internal-revision:ia1', 'internal-revision:ia2', 'internal-revision:ib1'):
    assert physical_roots(states['multi'])[ref] == physical_roots(states['multi_edited'])[ref]

# Model only verified successor facts from the accepted edit fixture. An actual
# provider must authenticate the native records and edge path before using them.
successors = {fact['source']: fact['successor'] for fact in addressing['materialization_projection']}
def single_owner_probe(document, occurrence_id, revision):
    result = copy.deepcopy(document)
    parent = result['parent_revision']
    parent['revision_id'] = revision
    rows = parent['payload']['occurrences']
    rows[:] = [row for row in rows if row['occurrence_id'] == occurrence_id]
    shot_ids = {row['shot_revision_id'] for row in rows}
    result['shot_revisions'] = [im for im in result['shot_revisions'] if im['revision_id'] in shot_ids]
    internal_ids = {im['internal_timeline_revision_id'] for im in result['shot_revisions']}
    result['internal_timeline_revisions'] = [im for im in result['internal_timeline_revisions'] if im['revision_id'] in internal_ids]
    manifest = result['dependency_manifest']
    manifest['shots'] = [pin for pin in manifest['shots'] if pin['revision_id'] in shot_ids]
    manifest['internal_timelines'] = [pin for pin in manifest['internal_timelines'] if pin['revision_id'] in internal_ids]
    parent['content_digest'] = digest(parent['payload'])
    validate_document(result)
    return result
only_b = single_owner_probe(states['ab'], 'occ-b', 'rev-probe-b')
only_a2 = single_owner_probe(states['edited'], 'occ-a', 'rev-probe-a2')
probe_states = dict(states, only_b=only_b, only_edited_a=only_a2)
for case in addressing['replay_cases']:
    assert resolve(probe_states[case['base_state']], case['ref'])[0] == case['bound']
    landing = probe_states[case['landing_state']]
    proven = successors if case['case'] == 'authenticated_successor' else {}
    try:
        physical, _ = resolve(landing, case['ref'])
        result = physical if physical == case['bound'] or proven.get(case['bound']) == physical else 'binding_changed'
    except RefError as exc:
        continuation = proven.get(case['bound'])
        result = continuation if continuation in physical_roots(landing) else 'binding_changed' if str(exc) == 'outside_closure' else str(exc)
    assert result == case['expected']

# Guard normalization uses the bound image if it survives, and follows only
# the fixture's verified continuation for its exact owner when it has left.
def continue_binding(bound, document, owner, facts):
    if bound in physical_roots(document):
        return bound
    candidates = {fact['successor'] for fact in facts if fact['source'] == bound and fact['owner'] == owner}
    if len(candidates) != 1:
        raise RefError('binding_changed')
    successor = candidates.pop()
    if successor not in physical_roots(document):
        raise RefError('binding_changed')
    return successor

def overlapping(left, right):
    return left[:len(right)] == right or right[:len(left)] == left

def guard_overlap(bound, path, document, other_ref, other_path, owner):
    physical = continue_binding(bound, document, owner, addressing['materialization_projection'])
    other, _ = resolve(document, other_ref)
    return physical == other and overlapping(path, other_path)

path = steps[2]['dependencies'][0]['path']
bound = resolve(states['a'], 'internal:film-1')[0]
assert guard_overlap(bound, path, states['a'], 'internal-revision:ia1', path, 'occurrence:occ-a/shot')
assert not guard_overlap(bound, path, states['ab'], 'internal-revision:ib1', path, 'occurrence:occ-a/shot')
assert guard_overlap(bound, path, states['edited'], 'internal-revision:ia2', path, 'occurrence:occ-a/shot')
assert not guard_overlap(bound, path, states['edited'], 'internal-revision:ia2', ['registry'], 'occurrence:occ-a/shot')
# The old branch remains reachable: do not follow occ-a's successor for occ-a-old.
assert not guard_overlap('shot-revision:sa1', ['name'], states['multi'], 'occurrence:occ-a/shot', ['name'], 'occurrence:occ-a-old/shot')
assert guard_overlap('shot-revision:sa1', ['name'], states['multi'], 'occurrence:occ-a-old/shot', ['name'], 'occurrence:occ-a-old/shot')
# Scan writes, not only final bytes: the 30→24→30 tail still overlaps.
tail = [{'ref': 'internal-revision:ia2', 'path': path, 'before': 30, 'after': 24},
        {'ref': 'internal-revision:ia2', 'path': path, 'before': 24, 'after': 30}]
assert tail[-1]['after'] == 30
assert any(guard_overlap(bound, path, states['edited'], write['ref'], write['path'], 'occurrence:occ-a/shot') for write in tail)
print('PASS C0c: 6 schema/digest/pin states, 3 sequential steps, alias/union bindings, 4 inverse/redo transitions, rollback/dependency refusals, multi-shot edit, 4 replay binding probes and guard normalization; provider proof deferred')
assert not any(line.rstrip() != line for line in source.splitlines())
print('PASS: Runtime digests, receipt/result equality, step partition, ordered-list transitions, merged preservation, preview, structured errors, ABA, meta preservation, C0b sequential reads/effect reversals/closure pins and whitespace; provider behavior unverified')
PY
```

Required targeted contract controls (existing suites; no provider-v2 behavioral
qualification implied) and whitespace gate:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. /home/user/work/venv-runtime/bin/python -m pytest -q tests/test_timeline_commit_contract.py tests/test_timeline_commit_type_generator.py
git diff --check
```
