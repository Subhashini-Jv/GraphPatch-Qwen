import pytest
import requests

from graphpatch_v2 import deps
from graphpatch_v2.deps import Dep, OSVError, check_osv, find_dependencies

NS = 'xmlns="http://maven.apache.org/POM/4.0.0"'

PARENT = f"""<project {NS}>
  <groupId>com.ex</groupId><artifactId>parent</artifactId><version>2.0</version>
  <properties><jackson.version>2.9.8</jackson.version><commons.version>1.0</commons.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>${{yaml.version}}</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>[4.0,5.0)</version></dependency>
  </dependencies>
</project>"""

CHILD = f"""<project {NS}>
  <parent><groupId>com.ex</groupId><artifactId>parent</artifactId><version>2.0</version></parent>
  <artifactId>child</artifactId>
  <properties><yaml.version>1.23</yaml.version><commons.version>1.4</commons.version></properties>
  <dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${{jackson.version}}</version></dependency>
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId></dependency>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>${{commons.version}}</version></dependency>
    <dependency><groupId>${{project.groupId}}</groupId><artifactId>core</artifactId><version>${{project.version}}</version></dependency>
    <dependency><groupId>x</groupId><artifactId>unknown</artifactId><version>${{nope}}</version></dependency>
  </dependencies>
</project>"""

GRADLE = """
dependencies {
    implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
    testImplementation("junit:junit:4.12")
    api "com.google.guava:guava:30.0-jre@jar"
    runtimeOnly "x:dynamic:1.+"
    compileOnly "x:interp:$ver"
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.9.8'
}
"""


def _write(tmp_path):
    (tmp_path / "pom.xml").write_text(PARENT)
    (tmp_path / "child").mkdir()
    (tmp_path / "child" / "pom.xml").write_text(CHILD)
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "build.gradle").write_text(GRADLE)
    (tmp_path / "target").mkdir()
    (tmp_path / "target" / "pom.xml").write_text(CHILD.replace("1.4", "9.9"))
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "build.gradle").write_text("implementation 'a:b:1.0'")


def test_find_dependencies(tmp_path):
    _write(tmp_path)
    got = {(d.name, d.version): d.file for d in find_dependencies(tmp_path)}
    assert got[("com.fasterxml.jackson.core:jackson-databind", "2.9.8")] == "child/pom.xml"
    assert ("org.yaml:snakeyaml", "1.23") in got
    assert ("org.apache.commons:commons-text", "1.4") in got
    assert ("com.ex:core", "2.0") in got
    assert got[("org.apache.logging.log4j:log4j-core", "2.14.1")] == "app/build.gradle"
    assert ("junit:junit", "4.12") in got
    assert ("com.google.guava:guava", "30.0-jre") in got
    names = {n for n, _ in got}
    assert not {"x:unknown", "x:dynamic", "x:interp", "a:b"} & names
    assert ("org.apache.commons:commons-text", "9.9") not in got
    assert [v for n, v in got if n == "junit:junit"] == ["4.12"]
    assert len(got) == 7


def test_parent_relative_path_and_project_parent_version(tmp_path):
    (tmp_path / "parentdir").mkdir()
    (tmp_path / "parentdir" / "pom.xml").write_text(PARENT)
    (tmp_path / "mod").mkdir()
    (tmp_path / "mod" / "pom.xml").write_text(
        CHILD.replace("<version>2.0</version></parent>",
                      "<version>2.0</version><relativePath>../parentdir</relativePath></parent>")
             .replace("${project.version}", "${project.parent.version}"))
    got = {(d.name, d.version) for d in find_dependencies(tmp_path)}
    assert ("com.ex:core", "2.0") in got
    assert ("com.fasterxml.jackson.core:jackson-databind", "2.9.8") in got


class _Resp:
    def __init__(self, data, status=200):
        self.data, self.status_code = data, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)

    def json(self):
        return self.data


VULN = {"id": "GHSA-aaaa", "summary": "Bad thing", "aliases": ["CVE-2020-1", "OTHER-1"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific": {"severity": "CRITICAL"},
        "affected": [{"package": {"ecosystem": "Maven", "name": "g:a"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.5"}]}]},
                     {"package": {"ecosystem": "Maven", "name": "other:x"},
                      "ranges": [{"events": [{"fixed": "9"}]}]}]}


def test_check_osv(monkeypatch):
    posted, fetched = [], []

    def post(url, json, timeout):
        posted.append(json)
        return _Resp({"results": [{"vulns": [{"id": "GHSA-aaaa"}]}, {}, {"vulns": [{"id": "GHSA-aaaa"}]}]})

    def get(url, timeout):
        fetched.append(url)
        return _Resp(VULN)

    monkeypatch.setattr(deps.requests, "post", post)
    monkeypatch.setattr(deps.requests, "get", get)
    ds = [Dep("g:a", "1.0", "pom.xml"), Dep("g:b", "2.0", "pom.xml"), Dep("g:a", "1.1", "x/pom.xml")]
    out = check_osv(ds)
    assert posted[0]["queries"][0] == {"package": {"ecosystem": "Maven", "name": "g:a"}, "version": "1.0"}
    assert len(fetched) == 1
    assert len(out) == 2
    v = out[0]
    assert v["aliases"] == ["CVE-2020-1"]
    assert v["fixed"] == ["1.5"]
    assert v["severity"].startswith("CRITICAL CVSS:3.1/")
    assert v["url"] == "https://osv.dev/vulnerability/GHSA-aaaa"
    assert out[1]["file"] == "x/pom.xml"


def test_check_osv_network_error(monkeypatch):
    def post(url, json, timeout):
        raise requests.ConnectionError("proxy said no")

    monkeypatch.setattr(deps.requests, "post", post)
    with pytest.raises(OSVError, match="could not reach osv.dev"):
        check_osv([Dep("g:a", "1.0", "pom.xml")])


def test_check_osv_http_error(monkeypatch):
    monkeypatch.setattr(deps.requests, "post", lambda url, json, timeout: _Resp({}, 503))
    with pytest.raises(OSVError, match="503"):
        check_osv([Dep("g:a", "1.0", "pom.xml")])
