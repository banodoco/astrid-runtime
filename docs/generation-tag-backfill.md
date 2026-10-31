# Generation metadata backfill

`migrate-generation-tags` extends the existing offline Runtime migration family.
It acquires the stopped-runtime owner fence for previews and application. The
default is a read-only dry run. Application requires both `--apply` and the exact
realm confirmation. Neither mode reads or writes the idempotency ledger, reads
CAS/media bytes, upgrades the database, or creates a tag table.

```sh
python -m runtime_protocol.cli migrate-generation-tags --root /absolute/copied-realm \
  --project-id project-id --manifest-root /absolute/manifests \
  --receipt-root /absolute/receipts --template-model-map /absolute/models.json \
  --dry-run --skip-ledger
python -m runtime_protocol.cli migrate-generation-tags --root /absolute/copied-realm \
  --manifest-root /absolute/manifests --receipt-root /absolute/receipts \
  --template-model-map /absolute/models.json --apply \
  --confirm 'MIGRATE GENERATION TAGS realm-id' --skip-ledger
```

No external paths are discovered automatically. `--manifest-root` and
`--receipt-root` are repeatable absolute JSON files or directories. Only `.json`
files below selected directories are read, with a 4 MiB limit per file; symbolic
links are not followed. Paths embedded in documents are never traversed. The
template model map is one explicitly supplied JSON object (maximum 1 MiB), such
as `{"h3-template": "model-name", "fal-template": "another-model"}`. There is no
model-name guessing or built-in template registry dependency.

A JSON input can contain one row, an array of rows, or `{"generations": [...]}`.
Each row must bind to a Runtime `generation_id` or `task_id` (`kernel_task_id` is
also accepted). A receipt may put task/run identities in `locator`, as the SDK's
recovery receipt does. Supplied `project_id`, `realm_id`, and locator `run_id`
must match the Runtime row. Ambiguous or contradictory bindings skip the
generation. A row can carry contract fields in `gen`, `metadata.gen`, or named
legacy fields:

```json
{
  "generation_id": "generation-id",
  "project_id": "project-id",
  "modality": "video",
  "template_id": "h3-template",
  "target": "runpod",
  "mode_used": "t2v",
  "seed": 0,
  "tags": ["hero"]
}
```

Named fields `modality`/`content_type`, `execution`, and `mode_used` map to
`kind`, `backend`, and `mode`. A legacy execution backend such as `cloud` does
not establish a RunPod or fal target. Other `metadata.gen` contract names keep their
names. `template_id`/`template` map to a model only through the explicit map.
Receipts can also carry `admission.spec` generation intent or
`admission.settlement_effect.payload.metadata`. No ledger receipts are used.

Runtime SQL supplies generation metadata/params, source task/run intents,
publication effects, named generation inputs, explicit execution bindings, and
import provenance. An `h3_av` metadata object supplies its explicit fields and
generator identity; `h3_av.graph.profile` uses the template map and
`h3_av.graph.workflow.sha256` supplies the workflow digest. No media inspection
or filesystem-name inference occurs.

Existing generation metadata and `gen` values remain authoritative. Explicit
import provenance supplies `origin: imported` when absent and prevents historical
sources from reclassifying that import. Conflicting historical values for a
missing field, malformed evidence, ownership mismatches, and insufficient
evidence produce a skipped-row reason. Candidate reports include generation id,
the missing field names, and the complete proposed `gen` object. Unreadable,
malformed, and unbound external rows appear in `source_skipped`. Application
changes only generation metadata, row version, and update timestamp; a repeat
reports `already_current` and writes nothing.
