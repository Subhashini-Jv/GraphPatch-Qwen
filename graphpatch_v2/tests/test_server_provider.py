import importlib
import os

import pytest

pytest.importorskip("fastapi")


def _load(monkeypatch, **env):
    for k in ("GP_LLM_PROVIDER", "GP_LLM_MODEL", "GP_LLM_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY", "GP_LLM_MAX_TOKENS"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    from graphpatch_v2 import server
    return importlib.reload(server)


def test_gemini_is_the_default(monkeypatch):
    s = _load(monkeypatch)
    assert (s.PROVIDER, s.MODEL, s._key_set()) == ("gemini", "gemini-3.8-flash", False)


def test_groq_key_turns_the_agents_on(monkeypatch):
    s = _load(monkeypatch, GP_LLM_PROVIDER="groq", GROQ_API_KEY="x")
    assert (s.PROVIDER, s.MODEL, s._key_set()) == ("groq", "llama-3.3-70b-versatile", True)
    assert os.environ["GP_LLM_MAX_TOKENS"] == "4096"
    assert not _load(monkeypatch, GP_LLM_PROVIDER="groq", GEMINI_API_KEY="x")._key_set()
