"""Unit tests for the taint checker on small Java snippets."""

from pathlib import Path

import pytest

from graphpatch_v2.taint import TargetSpec, find_paths


def scan(tmp_path: Path, cwe: str, java: str, methods):
    f = tmp_path / "A.java"
    f.write_text(java)
    return find_paths(tmp_path, TargetSpec(cwe, ["A.java"], {("A.java", m, None) for m in methods}))


ZIP_SLIP = """
import java.io.*; import java.util.zip.*;
public class A {
  public void unzip(ZipFile zip, File dir) throws IOException {
    for (ZipEntry entry : java.util.Collections.list(zip.entries())) {
      String name = entry.getName();
      File out = new File(dir, name);
      %s
      FileOutputStream fos = new FileOutputStream(out);
    }
  }
}"""


def test_zip_slip_found(tmp_path):
    fs = scan(tmp_path, "CWE-022", ZIP_SLIP % "", ["unzip"])
    assert len(fs) == 1 and "FileOutputStream" in fs[0].sink


def test_zip_slip_guard_clears(tmp_path):
    guard = 'if (!out.getCanonicalPath().startsWith(dir.getCanonicalPath() + File.separator)) { throw new IOException("bad"); }'
    assert scan(tmp_path, "CWE-022", ZIP_SLIP % guard, ["unzip"]) == []


def test_guard_inside_other_branch_does_not_clear(tmp_path):
    guard = 'if (name.isEmpty()) { if (!out.getCanonicalPath().startsWith("x")) { throw new IOException(); } }'
    assert len(scan(tmp_path, "CWE-022", ZIP_SLIP % guard, ["unzip"])) == 1


def test_plain_absolute_path_is_not_traversal(tmp_path):
    java = """public class A { public void open(String p) throws Exception { new java.io.FileInputStream(new java.io.File(p)); } }"""
    assert scan(tmp_path, "CWE-022", java, ["open"]) == []


def test_field_flow_to_resource_loader(tmp_path):
    java = """public class A { private String path;
      public A(String path) { this.path = path; }
      public java.io.InputStream get() { return getClass().getClassLoader().getResourceAsStream(this.path); } }"""
    fs = scan(tmp_path, "CWE-022", java, ["A"])
    assert len(fs) == 1 and "getResourceAsStream" in fs[0].sink


def test_validation_call_in_constructor_clears_field(tmp_path):
    java = """public class A { private String path;
      public A(String path) { Assert.isTrue(isValid(path), "bad"); this.path = path; }
      public java.io.InputStream get() { return getClass().getClassLoader().getResourceAsStream(this.path); } }"""
    assert scan(tmp_path, "CWE-022", java, ["A"]) == []


def test_xss_and_escape(tmp_path):
    bad = """public class A { public void h(javax.servlet.http.HttpServletRequest req, java.io.PrintWriter out) {
      String q = req.getParameter("q"); out.println("<b>" + q + "</b>"); } }"""
    good = bad.replace('out.println("<b>" + q', 'out.println("<b>" + StringEscapeUtils.escapeHtml4(q)')
    assert len(scan(tmp_path, "CWE-079", bad, ["h"])) == 1
    assert scan(tmp_path, "CWE-079", good, ["h"]) == []


def test_command_injection(tmp_path):
    java = """public class A { public void run(String host) throws Exception { Runtime.getRuntime().exec("ping " + host); } }"""
    assert len(scan(tmp_path, "CWE-078", java, ["run"])) == 1


def test_code_injection_spel(tmp_path):
    java = """public class A { public Object ev(String expr) {
      org.springframework.expression.ExpressionParser p = new SpelExpressionParser();
      return p.parseExpression(expr).getValue(); } }"""
    assert len(scan(tmp_path, "CWE-094", java, ["ev"])) >= 1


def test_interprocedural_through_helper(tmp_path):
    java = """public class A {
      public void entry(String name) throws Exception { write(new java.io.File("/base", name)); }
      private void write(java.io.File f) throws Exception { new java.io.FileOutputStream(f); } }"""
    fs = scan(tmp_path, "CWE-022", java, ["entry"])
    assert len(fs) == 1 and fs[0].method == "write"


# ---- stricter guard recognition (paper, Threats to Validity: `if (name.equals("")) throw` cleared a path)

@pytest.mark.parametrize("guard", [
    'if (name.equals("")) { throw new IOException("bad"); }',
    'if (name.contains("")) { throw new IOException("bad"); }',
    'if (name.equals("x")) { throw new IOException("bad"); }',
    'if (name.contains("a")) { throw new IOException("bad"); }',
])
def test_useless_value_check_does_not_clear(tmp_path, guard):
    assert len(scan(tmp_path, "CWE-022", ZIP_SLIP % guard, ["unzip"])) == 1


@pytest.mark.parametrize("guard", [
    'if (name.contains("..")) { throw new IOException("bad"); }',
    'if (name.indexOf("..") >= 0) { throw new IOException("bad"); }',
    'if (!ALLOWED.contains(name)) { throw new IOException("bad"); }',
    'if (!name.matches(SAFE_NAME)) { throw new IOException("bad"); }',
])
def test_real_value_check_still_clears(tmp_path, guard):
    assert scan(tmp_path, "CWE-022", ZIP_SLIP % guard, ["unzip"]) == []
