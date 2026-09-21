"""Host-owned append-only events with a tamper-evident hash chain."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from .contracts import canonical_hash


class Evidence:
    def __init__(self, trial_id: str):
        self.trial_id = trial_id
        self._events: list[dict[str, Any]] = []

    @property
    def events(self) -> list[dict[str, Any]]:
        return deepcopy(self._events)

    def append(self, kind: str, data: dict[str, Any]) -> dict[str, Any]:
        event = {"sequence": len(self._events), "trial_id": self.trial_id, "kind": kind,
                 "at": datetime.now(timezone.utc).isoformat(), "data": deepcopy(data),
                 "previous_hash": self._events[-1]["hash"] if self._events else None}
        event["hash"] = canonical_hash(event)
        self._events.append(event)
        return deepcopy(event)


def verify_chain(events: list[dict[str, Any]], expected_head: str | None = None) -> bool:
    if not events:
        return False
    previous = None
    trial_id = events[0].get("trial_id") if events else None
    for index, event in enumerate(events):
        body = {k: v for k, v in event.items() if k != "hash"}
        if (event.get("sequence") != index or event.get("previous_hash") != previous
                or event.get("trial_id") != trial_id or canonical_hash(body) != event.get("hash")):
            return False
        previous = event["hash"]
    return expected_head is None or previous == expected_head
