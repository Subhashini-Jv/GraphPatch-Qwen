from pathlib import Path

from graphpatch_v2.javasrc import apply_edits, parse_edits

REPLY = """Here you go.

FILE: A.java
<<<<<<< SEARCH
    int x = 1;
=======
    int x = 2;
>>>>>>> REPLACE
"""


def test_parse_and_apply(tmp_path):
    (tmp_path / "A.java").write_text("class A {\n    int x = 1;\n}\n")
    edits = parse_edits(REPLY)
    assert len(edits) == 1
    assert apply_edits(tmp_path, edits) == []
    assert "int x = 2;" in (tmp_path / "A.java").read_text()


def test_whitespace_tolerant_match(tmp_path):
    (tmp_path / "A.java").write_text("class A {\n\tint x = 1;\n}\n")
    assert apply_edits(tmp_path, parse_edits(REPLY)) == []
    assert "\tint x = 2;" in (tmp_path / "A.java").read_text()


def test_missing_search_is_an_error(tmp_path):
    (tmp_path / "A.java").write_text("class A {}\n")
    errs = apply_edits(tmp_path, parse_edits(REPLY))
    assert errs and "not found" in errs[0]


def test_path_outside_repo_rejected(tmp_path):
    reply = REPLY.replace("FILE: A.java", "FILE: ../evil.java")
    assert apply_edits(tmp_path, parse_edits(reply))


def test_not_found_shows_real_lines(tmp_path):
    (tmp_path / "A.java").write_text("class A {\n    int x = 1;\n    int y = 3;\n}\n")
    reply = REPLY.replace("    int x = 1;\n=======", "    int x = 1;\n}\n=======")
    errs = apply_edits(tmp_path, parse_edits(reply))
    assert errs and "actually reads" in errs[0] and "int y = 3;" in errs[0]


# ---- edit-distance matching (paper, Future Work: the CVE-2022-31194 edit-format failures)

JAVA = """class A {
    public void unzip(File dir, String name) throws IOException {
        final File out = new File(dir, name);
        out.getParentFile().mkdirs();
        copy(in, new FileOutputStream(out));
    }

    public void other() {
        System.out.println("unrelated");
    }
}
"""


def _edit(search, replace):
    return parse_edits(f"FILE: A.java\n<<<<<<< SEARCH\n{search}\n=======\n{replace}\n>>>>>>> REPLACE\n")


def test_fuzzy_match_recovers_small_copy_mistake(tmp_path):
    (tmp_path / "A.java").write_text(JAVA)
    log = []
    # the model dropped `final` and wrote mkdir() instead of mkdirs()
    search = "File out = new File(dir, name);\nout.getParentFile().mkdir();"
    replace = "final File out = new File(dir, name);\ncheckInside(dir, out);\nout.getParentFile().mkdirs();"
    assert apply_edits(tmp_path, _edit(search, replace), fuzzy_log=log) == []
    text = (tmp_path / "A.java").read_text()
    assert "        checkInside(dir, out);" in text and text.count("new File(dir, name)") == 1
    assert log and "similarity" in log[0]


def test_fuzzy_match_rejects_unrelated_block(tmp_path):
    (tmp_path / "A.java").write_text(JAVA)
    errs = apply_edits(tmp_path, _edit("int total = 0;\nfor (Item i : items) total += i.size();", "x();"))
    assert errs and "not found" in errs[0]
    assert (tmp_path / "A.java").read_text() == JAVA


def test_fuzzy_match_rejects_ambiguous_block(tmp_path):
    body = "    void f() {\n        a.run(1);\n        b.run(2);\n    }\n"
    (tmp_path / "A.java").write_text("class A {\n" + body + body.replace("f()", "g()") + "}\n")
    errs = apply_edits(tmp_path, _edit("a.run(1);\nb.run(3);", "c.run();"))
    assert errs


def test_fuzzy_match_needs_more_than_one_line(tmp_path):
    (tmp_path / "A.java").write_text(JAVA)
    assert apply_edits(tmp_path, _edit("out.getParentFile().mkdir();", "x();"))


def test_fuzzy_match_never_drops_unseen_lines(tmp_path):
    (tmp_path / "A.java").write_text(JAVA)
    search = ("public void unzip(File dir, String name) throws IOException {\n"
              "final File out = new File(dir, name);\n"
              "copy(in, new FileOutputStream(out));\n"
              "}")
    assert apply_edits(tmp_path, _edit(search, search.replace("final File out", "File out")))
    assert (tmp_path / "A.java").read_text() == JAVA
