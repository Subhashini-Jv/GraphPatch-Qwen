"""Pre-commit guard (precommit.py) against a temporary git repository."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from graphpatch_v2 import precommit

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="no git")

# the built-in Zip Slip demo, read from server.py's text so these tests do not need fastapi
SAMPLE_JAVA = re.search(r'SAMPLE_JAVA = """(.*?)"""', (Path(__file__).parents[1] / "server.py").read_text(), re.S).group(1)
DEMO = "src/main/java/demo/ArchiveExtractor.java"
HARMLESS = "package demo;\n\npublic class Hello {\n    public int add(int a, int b) { return a + b; }\n}\n"


@pytest.fixture
def repo(tmp_path, monkeypatch):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def write(repo: Path, rel: str, text: str, stage: bool = True) -> None:
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).write_text(text)
    if stage:
        subprocess.run(["git", "add", rel], cwd=repo, check=True)


def test_staged_zip_slip_blocks_commit(repo, capsys):
    write(repo, DEMO, SAMPLE_JAVA)
    assert precommit.main([]) == 1
    out = capsys.readouterr().out
    assert f"{DEMO}:" in out and "CWE-022 Path traversal" in out
    assert precommit.main(["--cwe", "CWE-078"]) == 0


def test_harmless_staged_file_passes(repo):
    write(repo, "src/main/java/demo/Hello.java", HARMLESS)
    write(repo, DEMO, SAMPLE_JAVA, stage=False)  # vulnerable but not staged
    assert precommit.main([]) == 0
    assert precommit.main(["--all"]) == 1


def test_nothing_staged_passes(repo):
    assert precommit.main([]) == 0


def test_install_writes_hook_and_refuses_overwrite(repo):
    assert precommit.main(["--install"]) == 0
    hook = repo / ".git/hooks/pre-commit"
    assert "python3" in hook.read_text() and "-m graphpatch_v2.precommit" in hook.read_text()
    assert precommit.main(["--install"]) == 0  # same hook again is fine
    hook.write_text("#!/bin/sh\necho mine\n")
    assert precommit.main(["--install"]) == 1
    assert "mine" in hook.read_text()
    assert precommit.main(["--install", "--force"]) == 0
    assert "graphpatch_v2.precommit" in hook.read_text()
