"""Constrained JSON decoding for the Critic (response_format json_object)."""

from graphpatch_v2 import llm as llm_mod


class _R:
    headers = {}

    def __init__(self, code=200, text="", content='{"a": 1}'):
        self.status_code, self.text, self.content = code, text, content

    def json(self):
        return {"choices": [{"message": {"content": self.content}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5}}


def _capture(monkeypatch, replies):
    bodies = []

    def post(url, json=None, **k):
        bodies.append(dict(json))
        return replies.pop(0)
    monkeypatch.setattr(llm_mod.requests, "post", post)
    return bodies


def test_json_mode_sends_response_format(monkeypatch):
    m = llm_mod.LLM("ollama", "qwen2.5-coder:7b")
    bodies = _capture(monkeypatch, [_R()])
    m.chat("s", "u", role="critic", json_mode=True)
    assert bodies[0]["response_format"] == {"type": "json_object"}
    assert m.usage.log[-1]["json_mode"] is True


def test_plain_calls_are_unchanged(monkeypatch):
    m = llm_mod.LLM("ollama", "qwen2.5-coder:7b")
    bodies = _capture(monkeypatch, [_R()])
    m.chat("s", "u", role="coder")
    assert "response_format" not in bodies[0]
    assert m.usage.log[-1]["json_mode"] is False


def test_unsupported_server_falls_back_once(monkeypatch):
    m = llm_mod.LLM("ollama", "qwen2.5-coder:7b")
    bodies = _capture(monkeypatch, [_R(400, "Invalid parameter: response_format is not supported by this model"), _R()])
    assert m.chat("s", "u", json_mode=True) == '{"a": 1}'
    assert "response_format" in bodies[0] and "response_format" not in bodies[1]
    assert m.usage.log[-1]["json_mode"] is False


def test_env_switch_turns_it_off(monkeypatch):
    monkeypatch.setenv("GP_LLM_JSON_MODE", "0")
    m = llm_mod.LLM("ollama", "qwen2.5-coder:7b")
    bodies = _capture(monkeypatch, [_R()])
    m.chat("s", "u", json_mode=True)
    assert "response_format" not in bodies[0]
