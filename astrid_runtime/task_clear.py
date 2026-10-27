"""Owner-authorized, exact-id task clearing orchestration for the CLI."""

from __future__ import annotations

import json
import hashlib
import urllib.error
import urllib.request
import uuid
from urllib.parse import quote, unquote
from typing import Any, Mapping

from .bootstrap import _read_support_json, _validate_loopback_endpoint, _validate_support_paths
from .loopback_http import urlopen_loopback
from runtime_protocol.daemon import WORKER_ACTOR


TERMINAL_STATES = {"succeeded", "completed", "failed", "cancelled"}


def _abandon_key(route, body):
    # Exact response-loss replay binds the observed incarnation and decision.
    return "tasks-clear-abandon-" + hashlib.sha256(json.dumps(
        [route, body], sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _lost_row(task_id, settlement):
    if (not isinstance(settlement, Mapping) or settlement.get("task_id") != task_id
            or settlement.get("settled") is not True or settlement.get("state") != "failed"):
        return None
    task = settlement.get("task")
    if (not isinstance(task, Mapping) or task.get("task_id") != task_id
            or task.get("state") != "failed"):
        return None
    lost = settlement.get("lost_disposition")
    result = task.get("result")
    if (not isinstance(lost, Mapping) or set(lost) != {"event_id", "attempt_id", "reason"}
            or not isinstance(result, Mapping)):
        return None
    run_id = task.get("run_id")
    event_id, attempt_id, reason = (lost.get(key) for key in ("event_id", "attempt_id", "reason"))
    # Enforce the closed signal shape and canonical abandoned identity here:
    # generated Python clients do not validate wire schemas.
    if (not isinstance(run_id, str) or not run_id.strip()
            or result.get("task_id") != task_id or result.get("run_id") != run_id
            or not isinstance(event_id, str) or not event_id.isdecimal()
            or not isinstance(attempt_id, str) or not attempt_id.strip()
            or not isinstance(reason, str) or not reason.strip() or len(reason) > 4096
            or result.get("disposition") != "lost" or result.get("attempt_id") != attempt_id
            or result.get("reason") != reason or result.get("remote_stop_confirmed") is not False
            or result.get("billing_stop_confirmed") is not False):
        return None
    return {"task_id": task_id, "outcome": "lost", "state": settlement["state"],
            "disposition": "lost", "reason": reason,
            "remote_stop_confirmed": False, "billing_stop_confirmed": False}


class ControlError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, details: Any = None):
        super().__init__(message)
        self.status = status
        self.details = details


def _control(paths, token: str, method: str, route: str, body: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    discovery = _read_support_json(paths.discovery_path)
    if not discovery or not discovery.get("endpoint"):
        raise ControlError("No live Runtime discovery is available; tasks clear will not start Runtime.")
    endpoint = _validate_loopback_endpoint(str(discovery["endpoint"])).rstrip("/")
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if method == "POST" and route.endswith("/abandon"):
        headers["Idempotency-Key"] = _abandon_key(route, body)
    request = urllib.request.Request(endpoint + route, data=payload, method=method, headers=headers)
    try:
        with urlopen_loopback(request, timeout=30) as response:
            result = json.loads(response.read(1024 * 1024).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            details = json.loads(exc.read(1024 * 1024).decode("utf-8"))
        except Exception:
            details = {"message": str(exc)}
        message = details.get("message") if isinstance(details, Mapping) else None
        raise ControlError(str(message or details), status=exc.code, details=details) from exc
    except (OSError, ValueError) as exc:
        raise ControlError(str(exc)) from exc
    if not isinstance(result, Mapping):
        raise ControlError("Runtime returned invalid owner-control metadata.")
    return result


def _error_row(task_id: str, outcome: str, error: str, **extra: Any) -> dict[str, Any]:
    return {"task_id": task_id, "outcome": outcome, "error": error, **extra}


def _control_details(value: Any) -> Mapping[str, Any]:
    """Normalize typed-client detail maps and raw HTTP error envelopes."""
    if not isinstance(value, Mapping):
        return {}
    details = value.get("details", value)
    if isinstance(details, Mapping) and isinstance(details.get("error"), Mapping):
        details = details["error"].get("details", details["error"])
    return details if isinstance(details, Mapping) else {}


def _typed_control(client):
    if not all(hasattr(client, name) for name in (
        "get_task_settlement", "get_local_worker_generation", "relinquish_local_worker", "abandon_task",
    )):
        return None

    def request(method: str, route: str, body: Mapping[str, Any] | None = None):
        try:
            if method == "GET" and route.endswith("/settlement"):
                task_id = unquote(route.rsplit("/tasks/", 1)[1].rsplit("/settlement", 1)[0])
                return client.get_task_settlement(task_id)
            if method == "GET" and route == "/v1/control/local-worker/generation":
                return client.get_local_worker_generation()
            if method == "POST" and route.endswith("/abandon"):
                task_id = unquote(route.rsplit("/tasks/", 1)[1].rsplit("/abandon", 1)[0])
                return client.abandon_task(task_id, body, idempotency_key=_abandon_key(route, body))
            if method == "POST" and route == "/v1/control/local-worker/relinquish":
                return client.relinquish_local_worker(
                    str(body["executor_incarnation"]), str(body["evidence_digest"]),
                    expected_task_ids=list(body["expected_task_ids"]),
                )
            raise ControlError("Unsupported owner-control operation.")
        except ControlError:
            raise
        except Exception as exc:
            raise ControlError(str(exc), status=getattr(exc, "status", None),
                               details=getattr(exc, "details", None)) from exc

    return request


def clear_tasks(paths, task_ids: list[str], *, credential_reader, client_factory, control_request=None) -> dict[str, Any]:
    """Clear only named tasks and report one stable result per input occurrence."""
    unique_ids = list(dict.fromkeys(task_ids))
    outcomes: dict[str, dict[str, Any]] = {}
    try:
        token = credential_reader(paths)
        if not isinstance(token, str) or not token.isascii() or any(ord(char) < 0x20 or ord(char) == 0x7f for char in token):
            raise ControlError("Runtime owner credential is malformed.")
        if control_request is None:
            _validate_support_paths(paths)
            discovery = _read_support_json(paths.discovery_path)
            if not discovery or not discovery.get("endpoint"):
                raise ControlError("No live Runtime owner is available; tasks clear will not start Runtime.")
        client = client_factory(paths)
        if control_request is None:
            control_request = _typed_control(client)
            if control_request is None:
                control_request = lambda method, route, body=None: _control(paths, token, method, route, body)
        # Complete owner authorization and settlement preflight for every id
        # before issuing any canonical cancellation mutation.
        observations: dict[str, Mapping[str, Any] | None] = {}
        for task_id in unique_ids:
            try:
                observations[task_id] = control_request(
                    "GET", f"/v1/control/tasks/{quote(task_id, safe='')}/settlement"
                )
            except ControlError as exc:
                if exc.status == 404:
                    observations[task_id] = None
                else:
                    raise
        tasks: dict[str, Mapping[str, Any]] = {}
        for task_id in unique_ids:
            if observations[task_id] is None:
                outcomes[task_id] = _error_row(task_id, "unknown", "task id is unknown")
                continue
            task = observations[task_id].get("task")
            if not isinstance(task, Mapping) or task.get("task_id") != task_id:
                outcomes[task_id] = _error_row(task_id, "failed", "owner settlement response omitted canonical task details")
                continue
            tasks[task_id] = task
            if observations[task_id].get("settled") is True:
                outcomes[task_id] = _lost_row(task_id, observations[task_id]) or {"task_id": task_id, "outcome": "already_settled",
                                     "state": observations[task_id].get("state")}
    except Exception as exc:
        for task_id in unique_ids:
            outcomes[task_id] = _error_row(task_id, "failed", str(exc))
        return _result(task_ids, outcomes)

    # Canonical cancel is the only task cancellation mechanism. A terminal
    # status alone is not settlement proof; preserve it for owner recheck.
    for task_id in unique_ids:
        if task_id in outcomes:
            continue
        task = tasks[task_id]
        state = str(task.get("state") or "")
        if state in TERMINAL_STATES:
            outcomes[task_id] = {"task_id": task_id, "outcome": "unresolved", "state": state}
            continue
        try:
            client.cancel_task(task_id, expected_version=int(task["version"]), idempotency_key=str(uuid.uuid4()))
            outcomes[task_id] = {"task_id": task_id, "outcome": "cancel_requested", "state": "cancel_requested"}
        except Exception as exc:
            outcomes[task_id] = _error_row(task_id, "failed", str(exc), state=state)

    # Re-observe each task through the owner lifecycle report.
    for task_id in unique_ids:
        if outcomes.get(task_id, {}).get("outcome") in {"unknown", "failed", "already_settled", "lost"}:
            continue
        try:
            current = control_request("GET", f"/v1/control/tasks/{quote(task_id, safe='')}/settlement")
            if current.get("settled") is True:
                outcomes[task_id] = _lost_row(task_id, current) or {"task_id": task_id, "outcome": "settled", "state": current.get("state")}
            else:
                outcomes[task_id] = {"task_id": task_id, "outcome": "unresolved", "state": current.get("state"),
                                     "blockers": current.get("blockers", [])}
        except Exception as exc:
            outcomes[task_id] = _error_row(task_id, "failed", str(exc), state=outcomes[task_id].get("state"))

    unresolved = [task_id for task_id in unique_ids if outcomes.get(task_id, {}).get("outcome") == "unresolved"]
    named_worker_tasks = [
        task_id for task_id in unique_ids
        if isinstance(tasks.get(task_id, {}).get("execution_binding"), Mapping)
        and tasks[task_id]["execution_binding"].get("executor_id") == WORKER_ACTOR
    ]
    # A stopped/fenced generation may represent an interrupted previous exact
    # relinquish. Replay it with the same full id set even if tasks settled.
    if named_worker_tasks:
        try:
            generation = control_request("GET", "/v1/control/local-worker/generation")
            state = str(generation.get("state") or "")
            incarnation = generation.get("executor_incarnation")
            evidence = generation.get("evidence_digest")
            pending_replay = state in {"fencing", "fenced", "stop_unknown", "stopped"}

            def matches_generation(task_id):
                binding = tasks.get(task_id, {}).get("execution_binding")
                verification = binding.get("verification") if isinstance(binding, Mapping) else None
                return (
                    isinstance(binding, Mapping)
                    and binding.get("executor_id") == WORKER_ACTOR
                    and binding.get("executor_incarnation") == incarnation
                    and isinstance(verification, Mapping)
                    and verification.get("evidence_digest") == evidence
                )

            matching_named = [task_id for task_id in named_worker_tasks if matches_generation(task_id)]
            unresolved_worker = [task_id for task_id in unresolved if task_id in named_worker_tasks]
            can_relinquish_active = state == "active" and any(
                task_id in matching_named for task_id in unresolved_worker
            )
            if unresolved_worker and not any(task_id in matching_named for task_id in unresolved_worker):
                for task_id in unresolved_worker:
                    outcomes[task_id]["worker_handoff_error"] = "named task execution binding does not match the current local Worker generation"
            if (pending_replay and matching_named) or can_relinquish_active:
                control_request("POST", "/v1/control/local-worker/relinquish", {
                    "executor_incarnation": incarnation,
                    "evidence_digest": evidence,
                    "expected_task_ids": unique_ids,
                })
                for task_id in unresolved:
                    if task_id not in matching_named:
                        continue
                    current = control_request("GET", f"/v1/control/tasks/{quote(task_id, safe='')}/settlement")
                    if current.get("settled") is True:
                        outcomes[task_id] = {"task_id": task_id, "outcome": "settled", "state": current.get("state"),
                                             "worker_relinquished": True}
                    else:
                        outcomes[task_id] = {"task_id": task_id, "outcome": "unresolved", "state": current.get("state"),
                                             "blockers": current.get("blockers", [])}
        except ControlError as exc:
            if exc.status != 404:
                affected = unresolved or named_worker_tasks
                details = _control_details(exc.details)
                for task_id in affected:
                    outcomes[task_id]["worker_handoff_error"] = str(exc)
                    if details:
                        outcomes[task_id]["worker_handoff_details"] = dict(details)
                    if outcomes[task_id]["outcome"] in {"settled", "already_settled"}:
                        outcomes[task_id]["outcome"] = "failed"
            elif unresolved:
                for task_id in unresolved:
                    outcomes[task_id]["worker_handoff_error"] = str(exc)
            else:
                for task_id in named_worker_tasks:
                    outcomes[task_id]["worker_handoff_warning"] = "settled, but local Worker cleanup state could not be observed"
        except Exception as exc:
            for task_id in (unresolved or named_worker_tasks):
                outcomes[task_id]["worker_handoff_error"] = str(exc)
                if outcomes[task_id]["outcome"] in {"settled", "already_settled"}:
                    outcomes[task_id]["outcome"] = "failed"

    # Explicit owner tasks clear alone may choose lost after canonical cancel.
    # Fresh exact observation prevents a raced/new attempt inheriting authority.
    for task_id in unique_ids:
        if outcomes.get(task_id, {}).get("outcome") != "unresolved":
            continue
        try:
            route = f"/v1/control/tasks/{quote(task_id, safe='')}"
            current = control_request("GET", route + "/settlement")
            task = current.get("task", {})
            binding = task.get("execution_binding")
            if (task.get("state") != "cancel_requested" or task.get("waiting_reason") != "provider_state_unknown"
                    or not isinstance(binding, Mapping) or binding.get("executor_id") == WORKER_ACTOR
                    or binding.get("status") not in {"claimed", "stale"}
                    or not binding.get("actual_target")
                    or (binding.get("verification") or {}).get("verified") is not True):
                continue
            initial = tasks[task_id]
            initial_binding = initial.get("execution_binding") or {}
            identity_fields = ("binding_id", "attempt_id", "lease_id", "fence", "executor_id", "runtime_epoch",
                               "actual_target", "verification", "executor_incarnation", "placement_version",
                               "recovery_decision_digest")
            if (any(task.get(field) != initial.get(field) for field in ("version", "attempt_id", "runtime_epoch"))
                    or any(binding.get(field) != initial_binding.get(field) for field in identity_fields)):
                outcomes[task_id]["abandon_error"] = "observed task attempt changed during clear; retry the named id"
                continue
            body = {"expected_task_version": task["version"], "attempt_id": task["attempt_id"],
                    "lease_id": binding["lease_id"], "fence": binding["fence"],
                    "runtime_epoch": task["runtime_epoch"], "execution_binding": dict(binding),
                    "reason": "Owner tasks clear abandoned unresolved external execution; remote execution and billing may continue."}
            control_request("POST", route + "/abandon", body)
            final = control_request("GET", route + "/settlement")
            lost = _lost_row(task_id, final)
            if final.get("settled") is True and lost:
                outcomes[task_id] = lost
            else:
                outcomes[task_id]["abandon_error"] = "owner abandon did not confirm a settled lost disposition"
        except Exception as exc:
            outcomes[task_id]["abandon_error"] = str(exc)
            details = _control_details(getattr(exc, "details", None))
            if details:
                outcomes[task_id]["abandon_details"] = dict(details)

    return _result(task_ids, outcomes)


def _result(task_ids: list[str], outcomes: Mapping[str, dict[str, Any]]) -> dict[str, Any]:
    rows = []
    first_occurrence: dict[str, int] = {}
    for index, task_id in enumerate(task_ids):
        row = dict(outcomes.get(task_id) or _error_row(task_id, "failed", "no outcome was recorded"))
        if task_id in first_occurrence:
            row["repeated"] = True
            row["first_occurrence"] = first_occurrence[task_id]
        else:
            first_occurrence[task_id] = index
            row["repeated"] = False
        rows.append(row)
    return {"ok": all(row["outcome"] in {"settled", "already_settled", "lost"} for row in rows), "outcomes": rows}
