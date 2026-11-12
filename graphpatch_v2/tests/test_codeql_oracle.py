"""CodeQL as a held-out oracle: the verdict rule, and the oracle end to end with CodeQL itself faked."""

from graphpatch_v2.codeql_oracle import judge

REF = {"before": ["a", "b", "c"], "after_real_fix": ["c", "d"], "removed_by_real_fix": ["a", "b"]}


def test_patch_that_removes_what_the_fix_removes_passes():
    assert judge(REF, {"c"})["ok"] is True
    assert judge(REF, {"c", "d"})["ok"] is True        # alerts the real fix also has are not held against it


def test_remaining_alert_fails():
    r = judge(REF, {"b", "c"})
    assert r["ok"] is False and r["remaining"] == ["b"]


def test_rewritten_sink_line_with_open_path_fails():
    # the patch changed the sink line, so the old alert key vanished, but CodeQL reports the path under a new key
    r = judge(REF, {"c", "e"})
    assert r["ok"] is False and r["new"] == ["e"]
