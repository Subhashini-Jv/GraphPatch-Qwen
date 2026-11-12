"""Structured (JSON) Critic: parsing, rendering, and how much of the surviving paths it addresses."""

from graphpatch_v2.agents import critic_prompt, critique_coverage, parse_critique, render_critique

GOOD = """```json
{"root_cause": "The entry name is used before any check. The new guard only runs in unzip().",
 "instructions": [
   {"file": "src/A.java", "method": "unpackEntry", "line": "88", "variable": "name",
    "action": "Check that the canonical path of the target stays inside the output directory."},
   {"file": "src/A.java", "method": "Zips.copy", "line": null, "variable": null, "action": "Reuse the same check."}
 ]}
```"""

REMAINING = [
    "[CWE-022] A.unpackEntry line 90: tainted data reaches `new File`\n    1. ...",
    "[CWE-022] Zips.copy line 12: tainted data reaches `FileUtils.copy`\n    1. ...",
    "[CWE-022] A.forceMkdir line 140: tainted data reaches `FileUtils.forceMkdir`\n    1. ...",
]


def test_parse_valid_json_in_fence():
    c, why = parse_critique(GOOD)
    assert why == "" and c["instructions"][0]["line"] == 88
    assert c["instructions"][1]["line"] is None and c["instructions"][1]["variable"] == ""


def test_render_names_place():
    text = render_critique(parse_critique(GOOD)[0])
    assert text.startswith("Root cause:") and "method unpackEntry, line 88, variable `name`" in text


def test_coverage_counts_addressed_paths():
    c, _ = parse_critique(GOOD)
    assert abs(critique_coverage(c, REMAINING) - 2 / 3) < 1e-9
    assert critique_coverage(c, []) is None


def test_invalid_replies_are_reported():
    assert parse_critique("Root cause: something. 1. do this")[0] is None
    assert "root_cause" in parse_critique('{"instructions": [{"action": "x"}]}')[1]
    assert parse_critique('{"root_cause": "x", "instructions": []}')[0] is None
    assert parse_critique('{"root_cause": "x", "instructions": [{"file": "A"}]}')[0] is None
    assert "invalid JSON" in parse_critique('{"root_cause": "x", ')[1] or parse_critique('{"root_cause": "x", ')[0] is None


def test_prompt_modes():
    class C:
        cve_id, cwe, cwe_name, repo_url, summary, target_files, main_fix_rows = "CVE-1", "CWE-022", "Path", "u", "s", ["A.java"], []
    assert '"root_cause"' in critic_prompt(C, "diff", "fb")
    assert '"root_cause"' not in critic_prompt(C, "diff", "fb", structured=False)
