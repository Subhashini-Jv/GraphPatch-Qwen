"""Attack tests (attacktest.py): generated source shape, and a real JUnit run fail-before / pass-after the rule fix."""

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from graphpatch_v2.attacktest import attack_test
from graphpatch_v2.javasrc import apply_edits, parse_edits
from graphpatch_v2.rules import rule_patch
from graphpatch_v2.scanner import scan_repo
from graphpatch_v2.taint import Finding

DEMO = "src/main/java/demo/ArchiveExtractor.java"
# the built-in Zip Slip demo, read from server.py's text so these tests do not need fastapi
SAMPLE_JAVA = re.search(r'SAMPLE_JAVA = """(.*?)"""', (Path(__file__).parents[1] / "server.py").read_text(), re.S).group(1)

PARAM_JAVA = """package app.files;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class Store {
    private final File base;
    public Store(File base) { this.base = base; }

    public static void save(File dir, String name, int size) throws IOException {
        new FileOutputStream(new File(dir, name)).close();
    }
}
"""


def demo(tmp_path: Path) -> Path:
    (tmp_path / DEMO).parent.mkdir(parents=True)
    (tmp_path / DEMO).write_text(SAMPLE_JAVA)
    return tmp_path


def test_zip_slip_source_shape(tmp_path):
    repo = demo(tmp_path)
    fs = scan_repo(repo, ["CWE-022"])
    t = attack_test(repo, fs[0])
    assert t["kind"] == "zip-slip"
    assert t["class_name"] == "ArchiveExtractorExtractAttackTest"
    assert t["path"] == "src/test/java/demo/ArchiveExtractorExtractAttackTest.java"
    s = t["source"]
    assert s.startswith("package demo;")
    assert "@org.junit.Test" in s and "org.junit.Assert.assertFalse(" in s
    assert '"../" + escapeName' in s and "createTempDirectory" in s
    assert "new ArchiveExtractor()" in s and "subject.extract(new java.io.ByteArrayInputStream(zipBytes), target.toFile());" in s
    assert "deleteTree(target)" in s and "TODO" not in s
    assert s.count("{") == s.count("}")


def test_junit5_when_build_uses_jupiter(tmp_path):
    repo = demo(tmp_path)
    (repo / "pom.xml").write_text("<project><artifactId>junit-jupiter</artifactId><groupId>org.junit.jupiter</groupId></project>")
    s = attack_test(repo, scan_repo(repo, ["CWE-022"])[0])["source"]
    assert "@org.junit.jupiter.api.Test" in s and "org.junit.jupiter.api.Assertions.assertFalse(escaped," in s


def test_path_param_and_other_cwes(tmp_path):
    (tmp_path / "src/main/java/app/files").mkdir(parents=True)
    (tmp_path / "src/main/java/app/files/Store.java").write_text(PARAM_JAVA)
    f = Finding("CWE-022", "src/main/java/app/files/Store.java", "Store", "save", 12, "new FileOutputStream(...)",
                ("parameter `name` of Store.save (line 11) is attacker-controlled",))
    t = attack_test(tmp_path, f)
    assert t["kind"] == "path-param" and t["path"] == "src/test/java/app/files/StoreSaveAttackTest.java"
    assert "Store.save(root.toFile(), hostile, 0);" in t["source"]
    assert '"../../" + escapeName' in t["source"]
    # instance method on a class without a no-arg constructor: generated, but flagged
    g = Finding(f.cwe, f.file, "Store", "save", 12, f.sink, f.steps)
    (tmp_path / f.file).write_text(PARAM_JAVA.replace("public static void save", "public void save"))
    t2 = attack_test(tmp_path, g)
    assert "TODO" in t2["source"] and "TODO" in t2["note"]
    assert attack_test(tmp_path, Finding("CWE-078", f.file, "Store", "save", 12, "x", f.steps)) is None
    assert attack_test(tmp_path, Finding("CWE-022", f.file, "Store", "nope", 12, "x", f.steps)) is None


# ------------------------------------------------------------------ real JUnit run

def _jars() -> list[str]:
    m2 = Path.home() / ".m2" / "repository"
    junit = sorted(glob.glob(str(m2 / "junit/junit/4.1[2-9]*/junit-4.*.jar")))
    ham = sorted(glob.glob(str(m2 / "org/hamcrest/hamcrest-core/*/hamcrest-core-*.jar")))
    return [junit[-1], ham[-1]] if junit and ham else []


def _run(repo: Path, test: dict, jars: list[str]) -> subprocess.CompletedProcess:
    out = repo / "classes"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir()
    cp = os.pathsep.join(jars + [str(out)])
    subprocess.run(["javac", "-nowarn", "-d", str(out), "-cp", cp, str(repo / DEMO), str(repo / test["path"])],
                   check=True, capture_output=True, text=True)
    return subprocess.run(["java", "-cp", cp, "org.junit.runner.JUnitCore", "demo." + test["class_name"]],
                          capture_output=True, text=True, timeout=120)


@pytest.mark.skipif(shutil.which("javac") is None or shutil.which("java") is None, reason="no JDK")
def test_attack_test_fails_on_zip_slip_and_passes_after_fix(tmp_path):
    jars = _jars()
    if not jars:
        pytest.skip("no junit 4.12+ / hamcrest-core jar in ~/.m2")
    repo = demo(tmp_path)
    fs = scan_repo(repo, ["CWE-022"])
    t = attack_test(repo, fs[0])
    (repo / t["path"]).parent.mkdir(parents=True)
    (repo / t["path"]).write_text(t["source"])

    before = _run(repo, t, jars)
    assert before.returncode != 0, before.stdout
    assert "was written outside the target directory" in before.stdout

    assert apply_edits(repo, parse_edits(rule_patch(repo, "CWE-022", fs))) == []
    after = _run(repo, t, jars)
    assert after.returncode == 0, after.stdout + after.stderr
    assert "OK (1 test)" in after.stdout
