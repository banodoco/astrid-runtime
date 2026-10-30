# GR03 owner composition contract

Source baseline: Runtime `b943c210b187374f15df8ab9f53223d9139b7bd9`, Agent
`1e0f21f438e7cb7a4b2dd56b980e62e44a4cc24b`. Citations below are paths and line
numbers **at those commits**. This contract precedes task136 source edits.

## Existing ownership and boundaries

The bounded retention implementation is already in the named Runtime base
(introduced by `ee0a2df`, task78). Reuse it; task136 adds explicit documentation
and regression coverage, with no new authority or admission behavior.

| Boundary | Existing owner and concrete contract |
| --- | --- |
| Profile selection | The operator's configured `worker_profile` is loaded by `load_local_worker_composition`, which validates supported fields/paths and constructs one `LocalWorkerProfile`, `CrossProcessWorkerPreparer`, and `OSProcessInspector`. A profile declaration requests verification; it does not certify itself. Runtime `runtime_protocol/local_worker_composition.py:1219-1330`, `runtime_protocol/local_worker.py:67-118`. |
| Detached startup | `LocalRuntimeBoundary._argv` carries the configured profile to `runtime_protocol start`; CLI loads it with owner-selected realm/support roots and passes the same composition and lifecycle actors privately to `RuntimeDaemon`. Runtime `astrid_runtime/runtime_boundary.py:245-287`, `runtime_protocol/cli.py:389-418`. |
| Foreground startup | `ForegroundRuntimeBoundary.start` loads the configured profile and passes the same private composition and actors to the same daemon. Runtime `astrid_runtime/runtime_boundary.py:1179-1197`. These are Runtime startup paths, distinct from the Agent's `pip_embedded`/`checkout_server` execution profiles. |
| Retention | Before daemon path/store effects, `_retain_local_worker_composition` snapshots the owner-selected profiles/config as immutable JSON bytes. Profile/actor agreement is checked; reads reconstruct detached copies; mutable preparer/inspector actors are excluded. Existing implementation references are captured lazily, never supplied by a task. Runtime `runtime_protocol/local_worker_composition.py:1186-1202,1394-1463`, `runtime_protocol/daemon.py:58-62`. |
| Service wiring | `RuntimeDaemon._start` forwards that immutable object to `RuntimeService`; the constructor retains the same private snapshot before opening `RealmStore`. Existing live actors still bind endpoints and own launch/cleanup independently. Runtime `runtime_protocol/daemon.py:273-289`, `runtime_protocol/service.py:515-519`, `runtime_protocol/local_worker_composition.py:181-186`. |

Retention preserves the selected declaration; it does **not** authenticate every
config value, establish a model root, invoke a producer, or grant task authority.
`required` only means a configured composition must exist and validate; it is not
a caller-supplied “verified” flag. Component-only daemon construction remains
supported and retains no composition authority (`runtime_protocol/daemon.py:108-121`).

## What the existing verifier authenticates

For host-only launch, the existing preparer obtains the installed record from
`_installed_host_release` and uses `TrustedLocalHostLaunchVerifier.verify/claim`
before spawning and binding the exact retained child. The installed-record owner
checks current distribution RECORD bytes, selected release digest, source closure,
launcher and import inventories. Runtime
`runtime_protocol/local_worker_composition.py:346-409,1346-1391`.

`TrustedLocalHostLaunchVerifier` explicitly operates under trusted single-user
installation selection; custody authenticates the actual process. It claims no
immutable source/native/OS or post-check tamper defense. `_SourceLoader` hashes
and compiles the selected bytes, avoiding an ordinary import reopen or bytecode
fallback. Runtime `runtime_protocol/verified_host_launch.py:475-492,521-546`.
Its authenticated object is a **host launch**, not a producer's returned recipe.
The retained loader reference is dormant implementation selection, not an executed
verified producer, a bound import root, or authenticated output.

## Concrete producer/result seam and remaining work

Agent already has a fixed private `prepare_image_recipe` operation on the retained
Runtime-relay/host control socket. `_prepare_image_recipe` accepts one managed
UTF-8 prompt plus bounded scalar controls, checks operation/channel/epoch/request
bindings, invokes `_prepare_verified_image_recipe`, and returns canonical recipe
bytes with request/recipe digests and the observed binding. The same existing
control loop returns the response frame; preparation failure returns `unresolved`
and preserves abort ownership. Agent
`astrid/core/execution/generic_host.py:12437-12518,13860-13865,13940-13960`.
The producer helper resolves the shipped catalog, validates the model inventory,
and freezes compiled members; it performs no task admission. Agent
`astrid/sdk/generation.py:218-225,275-348`.

The producer's `_producer_binding` requires the retained verified host protocol,
owner peer/epoch, exact process/session/config/argv evidence, a digest-bound model
root, disabled custom nodes and no extra model search paths. It rechecks the
binding after production. Agent
`astrid/core/execution/generic_host.py:12351-12435,12494-12504`.
`model_root_binding_from_profile(..., verify_files=True)` is the existing worker
readiness-profile root authority; filename availability alone is insufficient.
Agent `astrid/core/generation/model_root.py:1-9,639-654`,
`astrid/core/execution/generic_host.py:12369-12427`.

Runtime currently has **no** `prepare_image_recipe` sender or response consumer in
`local_worker_composition.py`, `local_worker.py`, or `service.py`. Its retained
snapshot is not connected to this Agent operation. Ordinary admission still treats
`generation_intent` as opaque transport and calls the existing `store.create_task`
once (`runtime_protocol/service.py:6537-6548`). Caller source/model identities,
hashes, signatures, or a “verified” boolean must never fill this missing seam.

The stronger first candidate is one local image via `checkout_server`: the consumer
requires a verified readiness profile and constructs its existing host-session
adapter. Agent `astrid/packs/vibecomfy/production_engine.py:862-880`. In contrast,
`pip_embedded` selects a Comfy tree and calls `run_embedded_sync` without an explicit
verified model-root argument; it lacks the VibeComfy session binding required by
the current private producer. Agent
`astrid/packs/vibecomfy/production_engine.py:791-828`,
`astrid/core/execution/generic_host.py:10276-10286,12369-12381`. Therefore this slice
does not qualify pip-embedded producer/model authority. Retaining a composition
on either Runtime startup path does not close that limitation.

A subsequent separately scoped slice must name and review Runtime
`runtime_protocol/local_worker_composition.py`/`local_worker.py` for exact retained
child/control invocation, `service.py`/`store.py` for managed-input association
validation and atomic evidence retention before one ordinary admission, plus Agent
`astrid/sdk/invocation.py`, `astrid/sdk/generation.py`,
`astrid/core/execution/generic_host.py` and
`astrid/packs/vibecomfy/production_engine.py` for request/execution binding as
required. It must reject before admission on any unresolved producer/source/root
binding and preserve evidence across spec retirement. These are requirements,
not guarantees delivered here; broader Agent/SDK/host implementation is outside
task136. No recipe format, callback, ledger, lifecycle, lease/fence, executor,
publication, H3, remote or pod semantics change in this slice.
