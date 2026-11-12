"""The YAML language spec must hold exactly the catalogues the paper's taint graph used when they were in code."""
import json
import re
from pathlib import Path

from graphpatch_v2 import catalogue, taint

SNAP = json.loads((Path(__file__).parent / "java_catalogue_snapshot.json").read_text())


def _norm(v):
    if isinstance(v, set):
        return sorted(v)
    if isinstance(v, re.Pattern):
        return [v.pattern, bool(v.flags & re.I)]
    if isinstance(v, dict):
        return {k: _norm(x) for k, x in v.items()}
    return v


def test_yaml_catalogue_equals_the_former_hard_coded_one():
    for name, want in SNAP.items():
        assert _norm(getattr(taint, name)) == want, name


def test_catalogue_covers_the_paper_cwes_and_rejects_unknown_language():
    c = catalogue.load("java")
    assert set(c["SINKS"]) == {"CWE-022", "CWE-078", "CWE-079", "CWE-094"}
    assert "getParameter" in c["REQUEST_SOURCES"] and "exec" in c["SINKS"]["CWE-078"]["arg"]
    try:
        catalogue.load("cobol")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("unknown language must fail")
