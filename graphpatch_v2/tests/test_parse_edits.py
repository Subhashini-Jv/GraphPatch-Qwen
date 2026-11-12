from graphpatch_v2.javasrc import parse_edits


def test_one_file_line_for_several_blocks():
    reply = """Intro text.

FILE: src/A.java
<<<<<<< SEARCH
a1
=======
a2
>>>>>>> REPLACE
<<<<<<< SEARCH
b1
=======
b2
>>>>>>> REPLACE
FILE: `src/B.java`
<<<<<<< SEARCH
c1
=======
c2
>>>>>>> REPLACE
"""
    edits = parse_edits(reply)
    assert [(e.file, e.search, e.replace) for e in edits] == [
        ("src/A.java", "a1", "a2"), ("src/A.java", "b1", "b2"), ("src/B.java", "c1", "c2")]


def test_block_before_any_file_line_is_ignored():
    reply = "<<<<<<< SEARCH\nx\n=======\ny\n>>>>>>> REPLACE\n"
    assert parse_edits(reply) == []


def test_file_line_glued_to_prose():
    reply = "This fixes it.FILE: src/A.java\n<<<<<<< SEARCH\nx\n=======\ny\n>>>>>>> REPLACE\n"
    assert [(e.file, e.search) for e in parse_edits(reply)] == [("src/A.java", "x")]


def test_network_failures_are_recognised():
    from graphpatch_v2.validator import Validator
    assert Validator._network_problem("Exception in thread main\n\tat org.gradle.wrapper.Download.downloadInternal(Download.java:110)")
    assert Validator._network_problem("[ERROR] Could not transfer artifact org.x:y:pom:1.0 from/to central")
    assert not Validator._network_problem("[ERROR] Foo.java:[12,5] cannot find symbol")
