"""One local open-weight model, used twice with different instructions.

Qwen2.5-14B-Instruct via Ollama (or vLLM) on the lab GPU. The container has no outbound network; the
model server runs on the same host. `StubLLM` lets the whole pipeline run with
no model at all, for tests and for the skeleton.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Protocol
from urllib import request


class LLMClient(Protocol):
    def complete(self, system: str, user: str) -> str: ...


class StubLLM:
    """Returns canned JSON. Tests use `queue` to script the model's behaviour."""

    def __init__(self, queue: list[str] | None = None, default: str | None = None):
        self.queue = list(queue or [])
        self.default = default or json.dumps({
            "label": "benign", "reasons": ["none"], "sender_auth_failed": False,
            "suspicious_links": False, "dangerous_attachment": False, "confidence": 0.9})
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        return self.queue.pop(0) if self.queue else self.default


class ModelUnavailable(Exception):
    """The model server did not answer (down, still loading the model, timed out, malformed reply)."""


class OllamaClient:
    """Minimal client for a local Ollama server (default http://127.0.0.1:11434).

    A failed call is tried once more after a short wait: the first call after the
    model was unloaded can fail while it loads (seen on the lab server as HTTP 500).
    If it fails again the caller gets `ModelUnavailable`, and the pipeline holds the case.
    """

    def __init__(self, model: str = "qwen2.5:14b", base_url: str = "http://127.0.0.1:11434", timeout: int = 120,
                 retries: int = 1, retry_wait: float = 5.0):
        self.model, self.base_url, self.timeout = model, base_url, timeout
        self.retries, self.retry_wait = retries, retry_wait

    def complete(self, system: str, user: str) -> str:
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            if attempt:
                time.sleep(self.retry_wait)
            try:
                return self._call(system, user)
            except (OSError, ValueError, KeyError, TypeError) as e:     # URLError, HTTPError and timeouts are OSError
                last = e
        raise ModelUnavailable(f"model server gave no answer: {type(last).__name__}: {last}")

    def _call(self, system: str, user: str) -> str:
        payload = {
            "model": self.model, "stream": False, "format": "json",
            "options": {"temperature": 0},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        req = request.Request(f"{self.base_url}/api/chat", data=json.dumps(payload).encode(),
                              headers={"Content-Type": "application/json"})
        with request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())["message"]["content"]


class ModelBudgetExceeded(Exception):
    """Raised by AuditedLLM when a case has used all its model calls."""


class AuditedLLM:
    """Wraps any LLMClient. Every call becomes a `model_call` audit row and counts
    against a per-case budget. The budget lives here, outside both agents, so no
    prompt can raise it (defence layer 6; proposal section 4 cost cap).
    Only hashes and sizes are logged: e-mail text never enters the audit log."""

    def __init__(self, inner: LLMClient, audit, max_calls_per_case: int = 6):
        self.inner, self.audit, self.max_calls_per_case = inner, audit, max_calls_per_case
        self.case_id: str | None = None
        self.calls_this_case = 0

    def start_case(self, case_id: str) -> None:
        self.case_id, self.calls_this_case = case_id, 0

    def complete(self, system: str, user: str) -> str:
        if self.calls_this_case >= self.max_calls_per_case:
            self.audit.append("budget_exceeded", self.case_id,
                              {"what": "model_calls", "limit": self.max_calls_per_case})
            raise ModelBudgetExceeded(f"more than {self.max_calls_per_case} model calls for case {self.case_id}")
        self.calls_this_case += 1
        out = self.inner.complete(system, user)
        self.audit.append("model_call", self.case_id, {
            "n": self.calls_this_case,
            "prompt_sha256": hashlib.sha256((system + "\n" + user).encode("utf-8")).hexdigest(),
            "response_sha256": hashlib.sha256(out.encode("utf-8")).hexdigest(),
            "response_chars": len(out)})
        return out