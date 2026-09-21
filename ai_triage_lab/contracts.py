"""Versioned, validated contracts shared by runners and adapters."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
VARIANTS = ("vulnerable", "prompt-only", "defended")
MAX_JSON_BYTES = 2_000_000
MAX_ACTIONS = 24


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     allow_nan=False).encode()).hexdigest()


def read_json(path: Path) -> Any:
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError(f"JSON exceeds {MAX_JSON_BYTES} bytes: {path.name}")
    def reject(value: str) -> None:
        raise ValueError(f"Non-finite JSON number: {value}")
    return json.loads(raw.decode("utf-8-sig"), parse_constant=reject)


def text(value: Any, name: str, maximum: int = 8000, *, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value):
        raise ValueError(f"{name} must be a {'nonempty ' if not empty else ''}string <= {maximum} characters")
    return value


@dataclass(frozen=True)
class Principal:
    operator_id: str = "analyst-a"
    tenant_id: str = "tenant-a"
    permissions: tuple[str, ...] = ("search_findings", "get_ticket", "propose_ticket_update",
                                    "close_ticket", "publish_report", "retrieve_document", "remember_fact", "recall_memory")
    destinations: tuple[str, ...] = ("team-a",)


@dataclass(frozen=True)
class Action:
    tool: str
    arguments: dict[str, Any]

    @classmethod
    def parse(cls, value: Any) -> Action:
        if not isinstance(value, dict) or set(value) != {"tool", "arguments"}:
            raise ValueError("Action requires only tool and arguments")
        text(value["tool"], "tool", 80)
        if not isinstance(value["arguments"], dict):
            raise ValueError("Action arguments must be an object")
        if len(json.dumps(value, allow_nan=False)) > 32000:
            raise ValueError("Action exceeds size limit")
        return cls(value["tool"], value["arguments"])


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    objective: str
    attack_field: str
    payload: str
    task: str
    actions: tuple[Action, ...]
    control: bool = False
    expected_ticket_state: str = "open"
    tool_budget: int = 5
    schema_version: int = SCHEMA_VERSION

    @classmethod
    def parse(cls, data: Any) -> Scenario:
        fields = {"schema_version", "id", "name", "objective", "attack_field", "payload",
                  "task", "actions", "control", "expected_ticket_state", "tool_budget"}
        if not isinstance(data, dict) or set(data) != fields:
            raise ValueError("Scenario fields do not match schema v1")
        if type(data["schema_version"]) is not int or data["schema_version"] != SCHEMA_VERSION:
            raise ValueError("Unsupported scenario schema")
        for key in ("id", "name", "task"):
            text(data[key], key, 2000)
        if not all(c.isalnum() or c in "-_" for c in data["id"]):
            raise ValueError("Invalid scenario ID")
        if data["objective"] not in {"suppression", "cross_tenant", "closure", "tampering", "leakage", "budget", "none"}:
            raise ValueError("Unknown objective")
        if data["attack_field"] not in {"title", "server", "none"}:
            raise ValueError("Unsupported attack field")
        text(data["payload"], "payload", 200 if data["attack_field"] == "title" else 2000, empty=True)
        if type(data["control"]) is not bool or data["control"] != (data["objective"] == "none"):
            raise ValueError("Controls must have objective none")
        if data["expected_ticket_state"] not in {"open", "closed"}:
            raise ValueError("Invalid expected ticket state")
        if type(data["tool_budget"]) is not int or not 1 <= data["tool_budget"] < MAX_ACTIONS:
            raise ValueError("Invalid tool budget")
        if not isinstance(data["actions"], list) or not 1 <= len(data["actions"]) <= MAX_ACTIONS:
            raise ValueError("Invalid scripted actions")
        return cls(**{**data, "actions": tuple(Action.parse(a) for a in data["actions"])})

    @property
    def digest(self) -> str:
        return canonical_hash(asdict(self))


def load_scenarios(path: Path) -> list[Scenario]:
    scenarios = [Scenario.parse(read_json(p)) for p in sorted(path.glob("*.json"))]
    if not scenarios or len({s.id for s in scenarios}) != len(scenarios):
        raise ValueError("Scenario directory must contain unique scenarios")
    return scenarios
