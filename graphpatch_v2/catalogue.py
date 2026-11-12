"""Declarative language specifications for the taint graph.

The sources, sinks, sanitizers and guards of a language live in a data file
(`catalogues/<language>.yaml`, or `.json`), not in the analysis code. `load()` turns
the file into the Python sets and compiled regular expressions taint.py uses.

Only Java is specified and analysed (the paper's scope). Another language would need its own
file and a parser front end; the paper lists that as future work.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

HERE = Path(__file__).parent / "catalogues"


def _rx(spec: dict) -> re.Pattern:
    return re.compile(spec["regex"], re.I if spec.get("ignore_case") else 0)


def _read(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    import yaml  # PyYAML, in requirements.txt
    return yaml.safe_load(text)


@lru_cache(maxsize=None)
def load(language: str = "java", path: str | None = None) -> dict:
    """The catalogue of one language as ready-to-use Python objects."""
    p = Path(path) if path else next((HERE / f"{language}{ext}" for ext in (".yaml", ".yml", ".json")
                                      if (HERE / f"{language}{ext}").exists()), None)
    if p is None:
        raise FileNotFoundError(f"no catalogue for language '{language}' in {HERE}")
    d = _read(p)
    src, ty, g = d["sources"], d["types"], d["guards"]
    return {
        "language": d["language"],
        "REQUEST_SOURCES": set(src["request_getters"]),
        "ENTRY_SOURCES": set(src["archive_entry_iterators"]),
        "ENTRY_NAME_GETTERS": set(src["archive_entry_name_getters"]),
        "ENTRY_LIKE": _rx(src["archive_entry_variable"]),
        "STRINGISH": set(ty["string_like"]),
        "FS_CLASSES": set(ty["filesystem_classes"]),
        "FILE_MAKERS": set(ty["path_makers"]),
        "PATH_MAKER_CALLS": set(ty["path_maker_calls"]),
        "LOADER_SINKS": set(ty["loader_sinks"]),
        "SINKS": {cwe: {"ctor": set(s.get("ctor") or ()), "arg": set(s.get("arg") or ()), "fsarg": set(s.get("fsarg") or ()),
                        "recv": set(s.get("recv") or ()), "return_kind": s.get("return_kind")} for cwe, s in d["sinks"].items()},
        "SANITIZER_PAT": {cwe: _rx(s) for cwe, s in d["sanitizers"].items()},
        "NON_PROPAGATING": set(g["non_propagating_calls"]),
        "GUARD_CALLS": _rx(g["guard_calls"]),
        "WRAP_GUARD_CALLS": _rx(g["wrapper_guard_calls"]),
        "GUARD_STMT_CALLS": _rx(g["guard_statement_calls"]),
        "WEAK_GUARD_CALLS": set(g["weak_guard_calls"]),
        "DANGEROUS_LITERAL": {cwe: _rx(s) for cwe, s in g["dangerous_literals"].items()},
    }
