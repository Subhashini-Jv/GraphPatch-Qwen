"""Unit tests for the rule-based baseline (rules.py)."""

from pathlib import Path

from graphpatch_v2.javasrc import apply_edits, parse_edits
from graphpatch_v2.rules import rule_patch
from graphpatch_v2.taint import Finding, TargetSpec, find_paths


def scan(tmp_path: Path, methods=("unzip",)):
    return find_paths(tmp_path, TargetSpec("CWE-022", ["A.java"], {("A.java", m, None) for m in methods}))


def fix(tmp_path: Path, java: str) -> tuple[str, str]:
    (tmp_path / "A.java").write_text(java)
    reply = rule_patch(tmp_path, "CWE-022", scan(tmp_path))
    assert apply_edits(tmp_path, parse_edits(reply)) == []
    return reply, (tmp_path / "A.java").read_text()


ZIP_SLIP = """
import java.io.*; import java.util.zip.*;
public class A {
  public void unzip(ZipFile zip, File dir) throws IOException {
    for (ZipEntry entry : java.util.Collections.list(zip.entries())) {
      String name = entry.getName();
      File out = new File(dir, name);
      FileOutputStream fos = new FileOutputStream(out);
    }
  }
}"""


def test_zip_slip_gets_containment_check(tmp_path):
    _, text = fix(tmp_path, ZIP_SLIP)
    assert "startsWith(java.nio.file.Paths.get(String.valueOf(dir))" in text
    assert text.index("File out = new File(dir, name);") < text.index("SecurityException")
    assert scan(tmp_path) == []


def test_resolver_call_counts_as_builder(tmp_path):
    # plexus-archiver (CVE-2018-1002200): final File f = FileUtils.resolveFile( dir, entryName ); ... IOUtil.copy(...)
    java = ZIP_SLIP.replace("File out = new File(dir, name);", "final File out = FileUtils.resolveFile( dir, name );")
    (tmp_path / "A.java").write_text(java)
    line = java.split("\n").index("      FileOutputStream fos = new FileOutputStream(out);") + 1
    decl = line - 1
    f = Finding("CWE-022", "A.java", "A", "unzip", line, "IOUtil.copy(...)",
                ("archive entry name `entry.getName()` (line 6)", f"`out` = ... (line {decl})", f"passed to `IOUtil.copy(...)` (line {line})"))
    reply = rule_patch(tmp_path, "CWE-022", [f])
    assert "String.valueOf(dir)" in reply and "String.valueOf(IOUtil)" not in reply


def test_base_overwritten_by_same_variable(tmp_path):
    java = ZIP_SLIP.replace("File out = new File(dir, name);", "File out = dir;\n      out = new File(out, name);")
    _, text = fix(tmp_path, java)
    assert "final Object gpBaseDir0 = out;" in text
    assert text.index("gpBaseDir0 = out") < text.index("out = new File(out, name)")


def test_other_cwe_has_no_rule(tmp_path):
    (tmp_path / "A.java").write_text(ZIP_SLIP)
    assert rule_patch(tmp_path, "CWE-078", scan(tmp_path)) == ""
