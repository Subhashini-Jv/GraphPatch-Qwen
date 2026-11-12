"""One OpenAI-compatible chat client for every provider. Keys come only from the
environment. There is no mock fallback: if the model cannot be reached the run
records an error for that CVE instead of inventing a patch."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

import requests

PROVIDERS = {
    # name: (base_url, api key env var)
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai", "GEMINI_API_KEY"),
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "deepseek": ("https://api.deepseek.com/v1", "DEEPSEEK_API_KEY"),
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "ollama": ("http://localhost:11434/v1", None),
}


class LLMError(RuntimeError):
    pass


class StopRun(LLMError):
    """An error that will hit every CVE the same way (bad key or model name, quota used up): stop the whole run."""


class QuotaExhausted(StopRun):
    """The provider's daily request quota is used up: stop the whole run and continue another day."""


@dataclass
class Usage:
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    seconds: float = 0.0
    log: list = field(default_factory=list)


class LLM:
    def __init__(self, provider: str | None = None, model: str | None = None, base_url: str | None = None,
                 api_key: str | None = None, temperature: float = 0.0, max_tokens: int | None = None, timeout: int = 600,
                 rpm: float | None = None):
        provider = provider or os.environ.get("GP_LLM_PROVIDER", "gemini")
        if provider not in PROVIDERS and not base_url:
            raise LLMError(f"unknown provider {provider!r}; pick one of {sorted(PROVIDERS)} or pass --base-url")
        default_url, key_env = PROVIDERS.get(provider, (None, None))
        self.provider = provider
        self.base_url = (base_url or os.environ.get("GP_LLM_BASE_URL") or default_url).rstrip("/")
        self.api_key = api_key or os.environ.get("GP_LLM_API_KEY") or (os.environ.get(key_env) if key_env else None)
        self.model = model or os.environ.get("GP_LLM_MODEL")
        if not self.model:
            raise LLMError("no model name: pass --model or set GP_LLM_MODEL")
        if key_env and not self.api_key:
            raise LLMError(f"no API key: set {key_env} (or GP_LLM_API_KEY) in the environment")
        self.temperature = temperature
        # thinking models (Gemini 2.5, ...) count their hidden reasoning against this limit, so it must be generous
        self.max_tokens = max_tokens or int(os.environ.get("GP_LLM_MAX_TOKENS", "16384"))
        # thinking models can take several minutes on a long prompt before the first byte arrives
        self.timeout = int(os.environ.get("GP_LLM_TIMEOUT", timeout))
        self.max_attempts = 8
        self.on_retry = None   # optional callback(str) so the web app can show retries
        self.retry_empty = False   # ask again on an empty reply (web app and, since v2.15, batch runs); tokens of every try are counted
        self.usage = Usage()
        # free tiers allow only a few requests per minute; spacing calls avoids burning retries on 429s
        rpm = rpm or float(os.environ.get("GP_LLM_RPM", "0") or 0)
        self.min_interval = 60.0 / rpm if rpm else 0.0
        self._last_call = 0.0

    def chat(self, system: str, user: str, role: str = "") -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = {"model": self.model, "temperature": self.temperature, "max_tokens": self.max_tokens,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        last = None
        for attempt in range(self.max_attempts):
            wait = self._last_call + self.min_interval - time.time()
            if wait > 0:
                time.sleep(wait)
            t = self._last_call = time.time()
            try:
                r = requests.post(f"{self.base_url}/chat/completions", json=body, headers=headers, timeout=self.timeout)
            except requests.RequestException as e:
                last = str(e)
                if self.provider == "ollama" and isinstance(e, requests.Timeout):
                    # a local model that needs more than the timeout for one answer will not get faster on a retry;
                    # retrying 8 times kept the first 24k pilot busy for a whole day (v2.19.15)
                    raise StopRun(f"the local model gave no answer within {self.timeout}s: it is too slow on this PC "
                                  "(try a smaller num_ctx or a smaller model)") from e
                if self.on_retry and attempt + 1 < self.max_attempts:
                    self.on_retry(f"no answer from the model ({type(e).__name__}), trying again ({attempt + 2}/{self.max_attempts})")
                time.sleep(min(60, 5 * 2 ** attempt))
                continue
            if r.status_code == 429 and ("spending cap" in r.text or "spend cap" in r.text):
                raise QuotaExhausted("the Google project reached its spending cap; raise it at https://ai.studio/spend, then run again")
            if r.status_code == 402:
                raise QuotaExhausted("the Google project has no prepaid credit left; add credit in AI Studio (Billing), then run again")
            if r.status_code == 429 and "PerDay" in r.text:
                raise QuotaExhausted(f"daily quota used up for {self.model}; run again after it resets")
            if r.status_code in (429, 500, 502, 503, 504):
                last = f"HTTP {r.status_code}: {r.text[:200]}"
                if self.on_retry and attempt + 1 < self.max_attempts:
                    self.on_retry(f"model busy (HTTP {r.status_code}), trying again ({attempt + 2}/{self.max_attempts})")
                time.sleep(min(90, int(r.headers.get("retry-after", 0) or 0) or 10 * 2 ** attempt))
                continue
            if r.status_code in (401, 403, 404) or (r.status_code == 400 and ("model" in r.text.lower() or "api key" in r.text.lower())):
                raise StopRun(f"HTTP {r.status_code} (check the model name and API key): {r.text[:500]}")
            if r.status_code != 200:
                raise LLMError(f"HTTP {r.status_code}: {r.text[:500]}")
            data = r.json()
            choice = (data.get("choices") or [{}])[0]
            text = choice.get("message", {}).get("content") or ""
            finish = choice.get("finish_reason")
            u = data.get("usage") or {}
            self.usage.calls += 1
            self.usage.prompt_tokens += int(u.get("prompt_tokens") or 0)
            self.usage.completion_tokens += int(u.get("completion_tokens") or 0)
            self.usage.seconds += time.time() - t
            self.usage.log.append({"role": role, "prompt_chars": len(system) + len(user), "reply_chars": len(text),
                                   "prompt_tokens": u.get("prompt_tokens"), "completion_tokens": u.get("completion_tokens"),
                                   "finish_reason": finish})
            pt, chars = int(u.get("prompt_tokens") or 0), len(system) + len(user)
            if self.provider == "ollama" and pt and chars > 8000 and chars / pt > 6:
                # code is about 3-4 characters per token; far fewer tokens means Ollama cut the prompt to its
                # context size (2048 by default) and the model never saw most of the code (v2.19.14)
                raise StopRun(f"Ollama read only {pt} tokens of a {chars}-character prompt: its context is too small. "
                              "Use a model made with a bigger num_ctx (see vul4j_run.ps1), then run again.")
            if finish == "length" and body["max_tokens"] < 65536:
                # the reply was cut off: a half-written edit block is worse than no reply, so ask again with more room
                body["max_tokens"] = min(65536, body["max_tokens"] * 2)
                last = "reply cut off at the token limit"
                continue
            if not text.strip():
                if self.retry_empty and attempt + 1 < self.max_attempts:
                    last = "empty reply from model"
                    if self.on_retry:
                        self.on_retry(f"empty answer from the model, asking again ({attempt + 2}/{self.max_attempts})")
                    continue
                raise LLMError("empty reply from model")
            return text
        raise LLMError(f"model unreachable after retries: {last}")
