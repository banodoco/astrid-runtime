from __future__ import annotations

import inspect

from runtime_protocol.service import RuntimeService
from runtime_protocol.server import RuntimeHandler
from runtime_protocol.store import RealmStore


def test_task_level_settlement_surface_is_absent() -> None:
    handler_source = inspect.getsource(RuntimeHandler)
    assert "self.runtime.settle(" not in handler_source
    assert "self.runtime.settle_attempt(path[2]" in handler_source
    assert not hasattr(RuntimeService, "settle")
    assert not hasattr(RealmStore, "settle_task")


def test_abandon_is_a_distinct_owner_control_operation_and_preserves_public_states():
    import json
    from pathlib import Path
    import yaml

    root = Path(__file__).parents[1]
    document = yaml.safe_load((root / "contract/openapi/workspace-v1.yaml").read_text())
    route = document["paths"]["/v1/control/tasks/{task_id}/abandon"]["post"]
    assert route["operationId"] == "abandonTask"
    assert route["requestBody"]["content"]["application/json"]["schema"]["$ref"] == './schemas/task-abandon.json'
    schema = json.loads((root / "contract/schemas/task.json").read_text())
    assert "lost" not in schema["properties"]["state"]["enum"]
