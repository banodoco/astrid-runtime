# OpCall / EditCommand candidate source increment

This is source implementation readiness, not freeze, review or acceptance. The
single editable schema is Astrid `schemas/change-contract/opcall.schema.json`.
`CommitCommand` references its exact `$id`; no new schema tree or request route
is introduced. Runtime and product consumers contain generated projections only.

From the Runtime source, regenerate/check with the existing generator seam:

```sh
python3 generators/generate.py --astrid-root "$ASTRID_ROOT" --app-root "$APP_ROOT"
python3 generators/generate.py --check --astrid-root "$ASTRID_ROOT" --app-root "$APP_ROOT"
```

`--opcall-schema PATH` (or `ASTRID_OPCALL_SCHEMA`) explicitly selects the source
when checking isolated consumer copies. `--astrid-root` also selects its schema.
The standalone TypeScript conformance generator accepts the same source flag/env.
The schema's logical `$id` and exact bytes participate in the framed contract
digest in both generators. No schema reference is fetched over the network.
The small generated envelope validators check the source's field requirements,
types, operation pattern, unknown-field policy and resolved string array. They
reject non-finite/non-JSON values; Runtime byte validation rejects duplicate JSON
keys and returns the original bytes, including whitespace, ordering and UTF-8.
They do not resolve selectors, run handlers, normalize args, rebase or compute time.

## Established mappings and open semantics

- WS-SAVE `command` maps by role to `op`; `target` maps to `select`. Executed
  selectors are canonical stable identities, matching D's actual producer.
- The runner fills `version` with its tool version (`0.1.0`), not WS-SAVE's
  literal `"1"`, and fills `resolved`. Optional output fields remain optional
  on input; validators never materialize defaults. SDK coercion intentionally
  discards caller output metadata before the runner recomputes it.
- Clear is the existing `clip.clear` operation with `args.keys`; absent arguments
  remain omitted, explicit JSON null stays a value. An object `{op:"clear"}`
  inside opaque arguments is not implicitly a clear. Handlers own null refusal.
- `expect` is request precondition state; D has no matching precondition evaluator.
  Its required gesture/revert/suffix behavior and ABSENT prior-value encoding
  remain open. `$absent` objects in synthetic opaque witnesses do not prove it.
- `bindings`, `created`, and `authorship` are runner/result provenance state.
  D's five-field executed calls have no compatible emitted representation;
  these remain open, not invented writer fields or a second envelope.
- D's resolved identities are local; a scoped identity mapping and its cross-scope
  provenance remain open. Strings are preserved exactly, never prefixed by Runtime.
- App's existing local `TimelineCommand` engine is not a wire format. Its shared
  OpCall boundary in `commands/types.ts` validates and preserves the same object.
  Mapping every internal gesture/handler to OpCall is not claimed by this increment.
- Commit preparation/acceptance hosting is an external unresolved semantic seam;
  this increment neither chooses nor implements a host. X0/App observed payload,
  rebase, acceptance and live commit proof remain owned by their existing cards.

Synthetic shared fixtures live only in `conformance/fixtures/`. Astrid owns
anchor parsing and moment flooring; App checks its existing document placement
conversion on the compiled clock. Backend render rounding has a positive
render-dimension domain; duration rounding additionally covers negative half ties.
The backend previously nested helper is exposed under `_js_round` without changing
its arithmetic or call site. The flag fixture covers the admitted parity inventory
and D's current additions; tests deliberately do not close the operation registry.
