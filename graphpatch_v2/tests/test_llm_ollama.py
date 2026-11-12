import pytest

from graphpatch_v2 import llm as llm_mod


class _Resp:
    status_code = 200
    headers = {}
    text = ""

    def __init__(self, pt):
        self.pt = pt

    def json(self):
        return {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": self.pt, "completion_tokens": 5}}


def test_ollama_prompt_cut_by_small_context_stops_the_run(monkeypatch):
    m = llm_mod.LLM("ollama", "qwen2.5-coder:7b")
    monkeypatch.setattr(llm_mod.requests, "post", lambda *a, **k: _Resp(2048))
    with pytest.raises(llm_mod.StopRun, match="context is too small"):
        m.chat("system", "x" * 30000)


def test_ollama_full_prompt_is_fine(monkeypatch):
    m = llm_mod.LLM("ollama", "qwen2.5-coder:7b")
    monkeypatch.setattr(llm_mod.requests, "post", lambda *a, **k: _Resp(9000))
    assert m.chat("system", "x" * 30000) == "ok"


def test_ollama_timeout_stops_instead_of_retrying(monkeypatch):
    m = llm_mod.LLM("ollama", "qwen2.5-coder:7b")
    calls = []

    def slow(*a, **k):
        calls.append(1)
        raise llm_mod.requests.ReadTimeout("read timed out")
    monkeypatch.setattr(llm_mod.requests, "post", slow)
    with pytest.raises(llm_mod.StopRun, match="too slow"):
        m.chat("system", "hello")
    assert len(calls) == 1
