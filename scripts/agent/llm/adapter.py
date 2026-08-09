"""LLM-in-loop adapter (OpenAI-compatible chat completions).

Default backend: DeepSeek (reads DEEPSEEK_API_KEY); OPENAI_API_KEY also works.
The autonomous driver enforces call/token budgets through LLMUsage.
The API key is read from the environment only and is never logged.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


class BudgetExceeded(Exception):
    """LLM call/token budget exhausted; the autonomous loop must stop or degrade."""


class LLMUsage:
    def __init__(self) -> None:
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.estimated_usd = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "estimated_usd": round(self.estimated_usd, 4),
        }


class LLMClient:
    """Minimal OpenAI-compatible chat client with retry and budget guards."""

    def __init__(self, model: Optional[str] = None, base_url: Optional[str] = None,
                 api_key: Optional[str] = None, max_calls: int = 40,
                 max_tokens_total: int = 300_000, timeout: int = 180,
                 reasoning_effort: Optional[str] = None,
                 json_model: Optional[str] = None):
        self.model = model or os.environ.get("LLM_MODEL") or "deepseek-v4-flash"
        # JSON-output tasks (candidate proposal / audit / novelty verdict) go
        # through the DeepSeek Responses API with natively controlled
        # reasoning budget (reasoning.effort + max_output_tokens), keeping the
        # flash model's full capability. Chat Completions on the reasoning
        # model spends the whole budget on thinking for long structured
        # prompts and returns empty content (verified 2026-08-09).
        self.json_model = (json_model or os.environ.get("LLM_JSON_MODEL")
                           or "deepseek-v4-flash")
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL")
                         or "https://api.deepseek.com/").rstrip("/") + "/"
        self.api_key = (api_key or os.environ.get("DEEPSEEK_API_KEY")
                        or os.environ.get("OPENAI_API_KEY") or "")
        if not self.api_key:
            raise RuntimeError("LLM API key missing: set DEEPSEEK_API_KEY or OPENAI_API_KEY")
        self.max_calls = max_calls
        self.max_tokens_total = max_tokens_total
        self.timeout = timeout
        self.reasoning_effort = reasoning_effort or os.environ.get("LLM_REASONING_EFFORT")
        self.usage = LLMUsage()

    # -- internals ---------------------------------------------------------
    def _post(self, payload: Dict[str, Any], endpoint: str = "chat/completions") -> Dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + endpoint, data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + self.api_key})
        last: Optional[Exception] = None
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                last = exc
                if exc.code in (429, 500, 502, 503, 504) and attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise
            except (urllib.error.URLError, TimeoutError) as exc:
                last = exc
                if attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise
        raise last if last is not None else RuntimeError("unreachable")

    def _response_text(self, data: Dict[str, Any]) -> str:
        """Extract concatenated output_text from a Responses API payload."""
        parts = []
        for item in data.get("output") or []:
            for c in item.get("content") or []:
                txt = c.get("text")
                if txt:
                    parts.append(txt)
        return "".join(parts)

    def _responses_call(self, system: str, user: str,
                        max_output_tokens: int = 16000,
                        effort: str = "low") -> str:
        """One DeepSeek Responses API call.

        effort controls thinking mode natively:
        - "low" for structured JSON tasks (S2/S3/S5): natively bounded
          reasoning budget, complete long JSON output (verified 2026-08-09:
          499 reasoning tokens vs Chat Completions 4001 + empty content);
        - "none" for write-code tasks (S4): thinking off. With thinking on,
          the model prepends a task restatement ("We need to write...") to the
          code output and the file fails to compile; effort=none yields clean
          code-only output (verified 2026-08-09: 2/2 simple + 1/1 complex PoC
          compile OK).
        """
        self._check_budget(max_output_tokens)
        payload = {
            "model": self.json_model or "deepseek-v4-flash",
            "input": [{"role": "user", "content": user}],
            "instructions": system,
            "reasoning": {"effort": effort},
            "max_output_tokens": max_output_tokens,
        }
        data = self._post(payload, endpoint="responses")
        usage = data.get("usage") or {}
        self.usage.calls += 1
        self.usage.prompt_tokens += int(usage.get("input_tokens") or 0)
        self.usage.completion_tokens += int(usage.get("output_tokens") or 0)
        self.usage.total_tokens += int(usage.get("total_tokens") or 0)
        self.usage.estimated_usd += 0.0002 * (int(usage.get("total_tokens") or 0) / 1000)
        return self._response_text(data)

    def _check_budget(self, max_tokens: int) -> None:
        if self.usage.calls >= self.max_calls:
            raise BudgetExceeded("LLM call budget exhausted (max_calls=%d)" % self.max_calls)
        if self.usage.total_tokens + max_tokens > self.max_tokens_total:
            raise BudgetExceeded(
                "LLM token budget exhausted (%d + %d > %d)"
                % (self.usage.total_tokens, max_tokens, self.max_tokens_total))

    # -- public -------------------------------------------------------------
    def chat(self, messages: List[Dict[str, str]], max_tokens: int = 4000,
             temperature: float = 0.2, json_mode: bool = False,
             reasoning_effort: Optional[str] = None,
             model: Optional[str] = None) -> str:
        self._check_budget(max_tokens)
        # Reasoning models occasionally return empty content (all tokens spent
        # on reasoning) or hit 'length'; retry with backoff before giving up.
        for attempt in range(3):
            payload: Dict[str, Any] = {
                "model": model or self.model, "messages": messages,
                "max_tokens": max_tokens, "temperature": temperature,
            }
            if json_mode:
                payload["response_format"] = {"type": "json_object"}
            eff = reasoning_effort or self.reasoning_effort
            if eff:
                payload["reasoning_effort"] = eff
            data = self._post(payload)
            choice = (data.get("choices") or [{}])[0]
            content = choice.get("message", {}).get("content") or ""
            finish = choice.get("finish_reason")
            usage = data.get("usage") or {}
            self.usage.calls += 1
            self.usage.prompt_tokens += int(usage.get("prompt_tokens") or 0)
            self.usage.completion_tokens += int(usage.get("completion_tokens") or 0)
            self.usage.total_tokens += int(usage.get("total_tokens") or 0)
            self.usage.estimated_usd += 0.0002 * (int(usage.get("total_tokens") or 0) / 1000)
            if content.strip():
                return content
            time.sleep(1.5)
        return ""

    @staticmethod
    def extract_json(text: str) -> Dict[str, Any]:
        """Robust JSON extraction: whole-string, first {...} block, or code fence."""
        text = text.strip()
        try:
            return json.loads(text)
        except ValueError:
            pass
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except ValueError:
                pass
        m = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.S)
        if m:
            try:
                return json.loads(m.group(1))
            except ValueError:
                pass
        raise ValueError("LLM did not return JSON: %r" % text[:200])

    def ask_json(self, system: str, user: str, max_tokens: int = 4000) -> Dict[str, Any]:
        # JSON-output tasks use DeepSeek Responses API: reasoning budget is
        # natively controlled (reasoning.effort) and max_output_tokens covers
        # both thinking and visible output. Chat Completions on the reasoning
        # model spends the whole budget on thinking for long structured
        # prompts (verified 2026-08-09: content="", reasoning_tokens=4001);
        # Responses API + effort=low yields complete JSON (499 reasoning
        # tokens, 15.9s). Model: deepseek-v4-flash only (Responses API does
        # not support pro yet).
        max_output = max(8000, max_tokens * 2)
        self._check_budget(max_output)
        # high -> low -> none (none disables thinking; last-resort fallback for
        # long JSON prompts where thinking models keep restating the task).
        efforts = [self.reasoning_effort or "high", "low", "none"]
        last_exc: Optional[Exception] = None
        for effort in efforts:
            try:
                text = self._responses_call(system, user,
                                            max_output_tokens=max_output,
                                            effort=effort)
                if text.strip():
                    return self.extract_json(text)
            except ValueError as exc:
                last_exc = exc
                continue
            except Exception:
                continue
        # Fallback: plain mode with an explicit "JSON only" instruction.
        try:
            return self.extract_json(self.chat(
                [{"role": "system", "content": system},
                 {"role": "user", "content": user
                  + "\n\n只输出 JSON 对象本身，不要 Markdown 围栏，不要任何其他文字。"}],
                max_tokens=max_tokens, json_mode=False, model=self.json_model))
        except ValueError:
            raise last_exc or ValueError("LLM did not return JSON")

    def ask_responses(self, system: str, user: str,
                      max_output_tokens: int = 16000) -> str:
        """Long-form generation (PoC writing) via Responses API: keeps the
        flash model's capability while avoiding Chat Completions' long-task
        timeout/empty-content failure. Thinking is off (effort=none) so the
        output is code-only; verified 2026-08-09: simple and complex PoCs
        compile OK."""
        return self._responses_call(system, user,
                                    max_output_tokens=max_output_tokens,
                                    effort="none")

    def ask(self, system: str, user: str, max_tokens: int = 4000,
            temperature: float = 0.2, json_mode: bool = False,
            reasoning_effort: Optional[str] = None) -> str:
        # Unified Responses API path for write-code / long-text generation.
        # effort defaults to high (user preference; matches Codex daily use);
        # reasoning models may prepend a task restatement before the code, so
        # callers must extract the code segment (run_agent.extract_java_code).
        # Verified 2026-08-09: high + extraction = 3/3 compile OK.
        return self._responses_call(
            system, user,
            max_output_tokens=max(16000, max_tokens * 2),
            effort=(reasoning_effort or self.reasoning_effort or "high"))
