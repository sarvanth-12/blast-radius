"""OpenAI-compatible JSON calls with per-attempt telemetry."""
from __future__ import annotations

import json
import logging
import math
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter
from typing import Callable, Literal

from dotenv import load_dotenv

logger = logging.getLogger(__name__)
Tier = Literal["cheap", "strong"]


class LLMError(RuntimeError):
    """A model call could not return a usable response."""


@dataclass(frozen=True)
class Call:
    """Usage metadata. Missing live usage and unconfigured prices stay unknown."""

    model: str
    prompt_tokens: int | None
    completion_tokens: int | None
    latency_ms: float
    estimated_cost: float | None
    status: str
    flow_rows_in_request: int


class LLM:
    """One client and usage ledger per analysis or benchmark strategy."""

    def __init__(self, demo: bool | None = None):
        load_dotenv(Path(__file__).resolve().parents[1] / ".env")
        self.demo = os.getenv("DEMO_MODE", "true").strip().lower() in {"1", "yes", "true"} if demo is None else demo
        self.calls: list[Call] = []
        self.client = None

    def _rate(self, tier: Tier, kind: str) -> float | None:
        value = os.getenv(f"{tier.upper()}_{kind}_PRICE_PER_1M", "").strip()
        if not value:
            return None
        try:
            price = float(value)
        except ValueError as exc:
            raise LLMError("Token prices must be nonnegative numbers.") from exc
        if not math.isfinite(price) or price < 0:
            raise LLMError("Token prices must be nonnegative numbers.")
        return price

    def complete(
        self, tier: Tier, system: str, prompt: str, canned: Callable[[], dict], *, flow_rows: int = 0,
    ) -> str:
        """Run a JSON completion, or generate the deterministic demo equivalent."""
        start = perf_counter()
        model = os.getenv(f"{tier.upper()}_MODEL", "").strip()
        model_label = model or ("demo / " + tier if self.demo else "(unconfigured)")
        prompt_tokens = completion_tokens = cost = None
        status = "error"
        counted_rows = 0
        try:
            if self.demo:
                counted_rows = flow_rows
                result = json.dumps(canned(), ensure_ascii=False)
                prompt_tokens = math.ceil(len((system + prompt).encode("utf-8")) / 4)
                completion_tokens = math.ceil(len(result.encode("utf-8")) / 4)
                input_rate, output_rate = self._rate(tier, "INPUT"), self._rate(tier, "OUTPUT")
                cost = (prompt_tokens * input_rate + completion_tokens * output_rate) / 1_000_000 if input_rate is not None and output_rate is not None else 0.0
                status = "simulated"
                return result
            base_url = os.getenv("ADAPTION_BASE_URL", "").strip()
            key = os.getenv("ADAPTION_API_KEY", "").strip()
            if not (model and base_url and key):
                raise LLMError(f"Configure ADAPTION_BASE_URL, ADAPTION_API_KEY and {tier.upper()}_MODEL in .env.")
            input_rate, output_rate = self._rate(tier, "INPUT"), self._rate(tier, "OUTPUT")
            if self.client is None:
                from openai import OpenAI
                self.client = OpenAI(base_url=base_url, api_key=key, timeout=90.0, max_retries=0)
            counted_rows = flow_rows
            reply = self.client.chat.completions.create(
                model=model, temperature=0,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": prompt}],
            )
            if reply.usage:
                prompt_tokens = reply.usage.prompt_tokens
                completion_tokens = reply.usage.completion_tokens
                if input_rate is not None and output_rate is not None:
                    cost = (prompt_tokens * input_rate + completion_tokens * output_rate) / 1_000_000
            if not reply.choices or not reply.choices[0].message.content:
                raise LLMError("The model returned an empty response.")
            if reply.choices[0].finish_reason == "length":
                raise LLMError("The model response reached the provider's output limit.")
            status = "ok"
            return reply.choices[0].message.content
        except LLMError:
            raise
        except Exception as exc:
            http_status = getattr(exc, "status_code", None)
            detail = f", HTTP {http_status}" if http_status else ""
            raise LLMError(f"{tier.capitalize()} model call failed ({type(exc).__name__}{detail}).") from exc
        finally:
            record = Call(model_label, prompt_tokens, completion_tokens, (perf_counter() - start) * 1000, cost, status, counted_rows)
            self.calls.append(record)
            logger.info("llm_usage %s", json.dumps(asdict(record)))

    def totals(self) -> dict:
        """Sum known metrics and preserve unknowns across the analysis."""
        def total(field: str):
            values = [getattr(call, field) for call in self.calls]
            return None if None in values else sum(values)

        return {
            "llm_calls": len(self.calls),
            "flow_rows_in_request": total("flow_rows_in_request"),
            "prompt_tokens": total("prompt_tokens"),
            "completion_tokens": total("completion_tokens"),
            "llm_latency_ms": total("latency_ms"),
            "estimated_cost": total("estimated_cost"),
        }
