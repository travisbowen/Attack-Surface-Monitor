"""Explicit, bounded Chat Completions transport with no automatic retries."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import json
import math
import os
from pathlib import Path
import time
from urllib.parse import urlsplit

import httpx

from ..contracts import Action, MAX_ACTIONS, read_json, text
from ..target import TriageTarget
from ..tools import validate_action


@dataclass(frozen=True)
class ModelConfig:
    endpoint: str
    model: str
    api_key_env: str = "ASM_LAB_API_KEY"
    max_requests: int = 24
    max_turns: int = 8
    max_completion_tokens: int = 800
    max_input_bytes: int = 32000
    max_total_tokens: int = 60000
    timeout_seconds: int = 30
    trial_timeout_seconds: int = 120
    token_parameter: str = "max_completion_tokens"
    input_usd_per_million: float | None = None
    output_usd_per_million: float | None = None

    temperature: float | None = None
    seed: int | None = None
    max_cost_usd: float | None = None

    def __post_init__(self) -> None:
        text(self.endpoint, "endpoint", 2000)
        url = urlsplit(self.endpoint)
        local = url.hostname in {"localhost", "127.0.0.1", "::1"}
        if (not url.hostname or url.username or url.password or url.query or url.fragment
                or not (url.scheme == "https" or (url.scheme == "http" and local))):
            raise ValueError("Endpoint must be HTTPS (or loopback HTTP), without credentials/query/fragment")
        text(self.model, "model", 200)
        text(self.api_key_env, "api_key_env", 100)
        if not self.api_key_env.isidentifier():
            raise ValueError("Invalid credential environment variable name")
        limits = {"max_requests": 1000, "max_turns": 24, "max_completion_tokens": 8000,
                  "max_input_bytes": 200000, "max_total_tokens": 2000000,
                  "timeout_seconds": 60, "trial_timeout_seconds": 300}
        for field, maximum in limits.items():
            value = getattr(self, field)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"Invalid {field}")
        if self.token_parameter not in {"max_tokens", "max_completion_tokens"}:
            raise ValueError("Invalid token_parameter")
        prices = (self.input_usd_per_million, self.output_usd_per_million)
        if (prices[0] is None) != (prices[1] is None):
            raise ValueError("Supply both token prices or neither")
        for price in prices:
            if price is not None and (type(price) not in (float, int) or not math.isfinite(price) or price < 0):
                raise ValueError("Token prices must be finite nonnegative numbers")

        if self.temperature is not None and (type(self.temperature) not in (int, float)
                or not math.isfinite(self.temperature) or not 0 <= self.temperature <= 2):
            raise ValueError("Invalid temperature")
        if self.seed is not None and (type(self.seed) is not int or not 0 <= self.seed < 2**31):
            raise ValueError("Invalid seed")
        if self.max_cost_usd is not None and (type(self.max_cost_usd) not in (int, float)
                or not math.isfinite(self.max_cost_usd) or self.max_cost_usd <= 0
                or self.input_usd_per_million is None):
            raise ValueError("max_cost_usd requires positive finite value and both token prices")

    @classmethod
    def load(cls, path: Path) -> ModelConfig:
        data = read_json(path)
        if not isinstance(data, dict):
            raise ValueError("Model configuration must be an object")
        try:
            return cls(**data)
        except TypeError as exc:
            raise ValueError("Unknown or missing model configuration fields") from exc


class ModelAdapter:
    kind = "model"

    def __init__(self, settings: ModelConfig, *, transport: httpx.BaseTransport | None = None):
        self.settings = settings
        self.config = {"adapter": "model", **asdict(settings)}
        self.transport = transport
        self.requests_used = 0
        self.tokens_used = 0
        self.cost_used = 0.0
        self._key = os.environ.get(settings.api_key_env)
        self._usage_known = True
        if not self._key and urlsplit(settings.endpoint).hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError(f"Missing credential environment variable {settings.api_key_env}")

    def run(self, target: TriageTarget) -> dict:
        settings = self.settings
        messages = target.messages()
        stats = {"status": "inconclusive", "mode": "real-model", "model_calls": 0,
                 "input_tokens": 0, "output_tokens": 0, "cost_usd": None}
        headers = {"Authorization": f"Bearer {self._key}"} if self._key else {}
        deadline = target.started_monotonic + settings.trial_timeout_seconds
        with httpx.Client(transport=self.transport, timeout=settings.timeout_seconds,
                          follow_redirects=False, trust_env=False) as client:
            for _ in range(settings.max_turns):
                if (self.requests_used >= settings.max_requests or self.tokens_used >= settings.max_total_tokens
                        or not self._usage_known or time.monotonic() >= deadline):
                    stats["reason"] = "run_budget_or_deadline"
                    break
                body = {"model": settings.model, "messages": messages, "tools": target.tool_definitions(),
                        "tool_choice": "auto", "parallel_tool_calls": False,
                        settings.token_parameter: settings.max_completion_tokens}
                for parameter in ("temperature", "seed"):
                    if getattr(settings, parameter) is not None:
                        body[parameter] = getattr(settings, parameter)
                body_bytes = len(json.dumps(body).encode("utf-8"))
                if settings.max_cost_usd is not None:
                    # Conservative byte-based reservation, not a provider billing guarantee.
                    reserve = (body_bytes * settings.input_usd_per_million
                               + settings.max_completion_tokens * settings.output_usd_per_million) / 1_000_000
                    if self.cost_used + reserve > settings.max_cost_usd:
                        stats["reason"] = "cost_reservation_limit"
                        break
                if body_bytes > settings.max_input_bytes:
                    stats["reason"] = "input_size_limit"
                    break
                self.requests_used += 1
                stats["model_calls"] += 1
                target.evidence.append("model_request", {"messages": messages, "model": settings.model,
                                                         "request_number": self.requests_used, "tools": body["tools"],
                                                         "phase_id": target.phase.id if target.phase else None})
                try:
                    chunks = bytearray()
                    with client.stream("POST", settings.endpoint, json=body, headers=headers,
                                       timeout=min(settings.timeout_seconds, max(0.1, deadline - time.monotonic()))) as response:
                        response.raise_for_status()
                        for chunk in response.iter_bytes():
                            chunks.extend(chunk)
                            if len(chunks) > 1_000_000 or time.monotonic() >= deadline:
                                raise ValueError("Response size/deadline exceeded")
                    data = json.loads(chunks)
                    usage = data.get("usage")
                    if (not isinstance(usage, dict) or any(type(usage.get(k)) is not int or usage[k] < 0
                                                          for k in ("prompt_tokens", "completion_tokens"))):
                        self._usage_known = False
                        stats["input_tokens"] = stats["output_tokens"] = None
                        raise ValueError("Provider omitted valid usage; stopping further calls")
                    stats["input_tokens"] += usage["prompt_tokens"]
                    stats["output_tokens"] += usage["completion_tokens"]
                    self.tokens_used += usage["prompt_tokens"] + usage["completion_tokens"]
                    if settings.input_usd_per_million is not None:
                        self.cost_used += (usage["prompt_tokens"] * settings.input_usd_per_million
                                          + usage["completion_tokens"] * settings.output_usd_per_million) / 1_000_000
                    choice = data["choices"][0]
                    message = choice["message"]
                    if message.get("role") != "assistant":
                        raise ValueError("Invalid assistant response")
                    target.evidence.append("model_response", {"message": message, "usage": usage,
                        "model": data.get("model"), "system_fingerprint": data.get("system_fingerprint"),
                        "finish_reason": choice.get("finish_reason")})
                    messages.append(deepcopy({k: message[k] for k in ("role", "content", "tool_calls") if k in message}))
                    if choice.get("finish_reason") in {"length", "content_filter"}:
                        stats["reason"] = choice["finish_reason"]
                        break
                    calls = message.get("tool_calls") or []
                    if not isinstance(calls, list) or len(calls) > MAX_ACTIONS:
                        raise ValueError("Invalid tool call count")
                    if not calls:
                        if choice.get("finish_reason") != "stop":
                            raise ValueError("Unexpected finish reason")
                        stats["status"] = "completed"
                        break
                    if len(calls) + target.gateway.call_number > MAX_ACTIONS:
                        stats["reason"] = "hard_tool_limit"
                        break
                    if choice.get("finish_reason") != "tool_calls":
                        raise ValueError("Tool calls require tool_calls finish reason")
                    ids = set()
                    parsed_calls = []
                    for call in calls:
                        call_id = text(call.get("id"), "tool_call_id", 200)
                        if call_id in ids or call.get("type") != "function":
                            raise ValueError("Invalid tool call")
                        ids.add(call_id)
                        args = json.loads(text(call["function"]["arguments"], "arguments", 32000))
                        action = Action.parse({"tool": call["function"]["name"], "arguments": args})
                        validate_action(action)
                        parsed_calls.append((call_id, action))
                    # Validate the entire message before any side effect.
                    for call_id, action in parsed_calls:
                        receipt = target.gateway.call(action)
                        messages.append({"role": "tool", "tool_call_id": call_id,
                                         "content": json.dumps({"execution": receipt["execution"],
                                            "decision": receipt["decision"] if receipt["execution"] != "executed" else "executed",
                                            "result": receipt["result"]})})
                except (httpx.HTTPError, ValueError, KeyError, TypeError, IndexError, AttributeError) as exc:
                    # A failed request may have incurred unknown usage; stop the run's paid calls.
                    self._usage_known = False
                    stats.update(status="error", error_type=type(exc).__name__, cost_usd=None)
                    break
            else:
                stats["reason"] = "turn_limit"
        if (self._usage_known and settings.input_usd_per_million is not None
                and stats["input_tokens"] is not None):
            stats["cost_usd"] = (stats["input_tokens"] * settings.input_usd_per_million
                                 + stats["output_tokens"] * settings.output_usd_per_million) / 1_000_000
        target.session_history = deepcopy(messages)
        stats["usage_complete"] = self._usage_known
        return stats
