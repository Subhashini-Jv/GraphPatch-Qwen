"""Strict build and test runner. Real exit codes; any error or timeout is a failure.

Builds run in Docker (official maven/gradle images with the JDK the benchmark
records) when Docker is available, otherwise with the local toolchain. Tests are
compared with a baseline run on the unpatched code, so only failures the patch
introduces count against it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path

MVN_FLAGS = [
    "-B", "-e", "-Dfindbugs.skip", "-Dcheckstyle.skip", "-Dpmd.skip=true", "-Dspotbugs.skip",
    "-Denforcer.skip", "-Dmaven.javadoc.skip", "-Dlicense.skip=true", "-Drat.skip=true",
    "-Dspotless.check.skip=true", "-Danimal.sniffer.skip", "-Djacoco.skip=true", "-Dgpg.skip",
]
ERROR_LINE = re.compile(r"(?:\[ERROR\]\s*)?(/\S+?\.java|\S+?\.java):\[?(\d+)[,:\]]")


@dataclass
class StepResult:
    ok: bool
    stage: str
    command: str = ""
    returncode: int | None = None
    seconds: float = 0.0
    log_tail: str = ""
    errors: list[str] = field(default_factory=list)
    failed_tests: list[str] = field(default_factory=list)
    new_failures: list[str] = field(default_factory=list)
    tests_run: int = 0

    def to_dict(self):
        return asdict(self)


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except Exception:
        return False


class Builder:
    def __init__(self, repo: Path, jdk: str = "17", target_files: list[str] | None = None,
                 use_docker: str = "auto", build_timeout: int = 1800, test_timeout: int = 2400,
                 tests: str = "module"):
        self.repo = Path(repo).resolve()
        self.jdk = "8" if str(jdk).startswith("8") else ("17" if str(jdk).startswith("17") else str(jdk))
        self.target_files = target_files or []
        self.build_timeout = build_timeout
        self.test_timeout = test_timeout
        self.tests = tests  # "module" | "related" | "skip"
        scope_file = self.repo / ".graphpatch" / "test_scope"
        if tests != "skip" and scope_file.exists():
            self.tests = scope_file.read_text(encoding="utf-8", errors="replace").strip()
        self.docker = use_docker == "always" or (use_docker == "auto" and docker_available())
        self.state_dir = self.repo / ".graphpatch"
        self.state_dir.mkdir(exist_ok=True)
        self._exclude_state_dir()

    def _exclude_state_dir(self):
        ex = self.repo / ".git" / "info" / "exclude"
        try:
            gitdir = subprocess.run(["git", "rev-parse", "--git-common-dir"], cwd=self.repo, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout.strip()
            ex = (self.repo / gitdir / "info" / "exclude") if gitdir else ex
            ex.parent.mkdir(parents=True, exist_ok=True)
            if ".graphpatch" not in (ex.read_text(encoding="utf-8", errors="replace") if ex.exists() else ""):
                with open(ex, "a", encoding="utf-8") as f:
                    f.write("\n.graphpatch/\n")
        except Exception:
            pass

    # ------------------------------------------------------------ project layout

    @property
    def tool(self) -> str:
        if (self.repo / "pom.xml").exists():
            return "maven"
        if (self.repo / "build.gradle").exists() or (self.repo / "build.gradle.kts").exists():
            return "gradle"
        return "unknown"

    def module_of(self, rel_file: str) -> str:
        """Nearest directory above the file that has its own build file ('' = root)."""
        d = (self.repo / rel_file).parent
        while d != self.repo and self.repo in d.parents:
            if (d / "pom.xml").exists() or (d / "build.gradle").exists() or (d / "build.gradle.kts").exists():
                return str(d.relative_to(self.repo))
            d = d.parent
        return ""

    def modules(self) -> list[str]:
        return sorted({self.module_of(f) for f in self.target_files}) or [""]

    # ------------------------------------------------------------ commands

    def _cmd(self, goal: str) -> list[str]:
        mods = [m for m in self.modules() if m]
        if self.tool == "maven":
            pl = ["-pl", ",".join(mods), "-am"] if mods else []
            if goal == "compile":
                return ["mvn", *MVN_FLAGS, *pl, "-DskipTests", "test-compile"]
            extra = []
            if self.tests == "related":
                names = sorted({Path(f).stem for f in self.target_files})
                extra = [f"-Dtest={','.join(n + '*Test*' for n in names)}", "-Dsurefire.failIfNoSpecifiedTests=false"]
            return ["mvn", *MVN_FLAGS, *pl, "-Dmaven.test.failure.ignore=true", "-DfailIfNoTests=false",
                    "-Dsurefire.failIfNoSpecifiedTests=false", *extra, "test"]
        if self.tool == "gradle":
            g = "./gradlew" if (self.repo / "gradlew").exists() else "gradle"
            prefix = [f":{m.replace('/', ':')}:" for m in mods] or [""]
            if goal == "compile":
                return [g, "--no-daemon", "-q", *[p + "testClasses" for p in prefix]]
            extra = []
            if self.tests == "related":
                for n in sorted({Path(f).stem for f in self.target_files}):
                    extra += ["--tests", f"*{n}*"]
            return [g, "--no-daemon", "--continue", *[p + "test" for p in prefix], *extra]
        return ["false"]

    def _run(self, argv: list[str], timeout: int) -> tuple[int | None, str, float]:
        t = time.time()
        if self.docker:
            image = f"maven:3.9-eclipse-temurin-{self.jdk}" if self.tool == "maven" else f"gradle:8-jdk{self.jdk}"
            m2 = Path(os.environ.get("GP_M2_CACHE", Path.home() / ".m2")).resolve()
            m2.mkdir(parents=True, exist_ok=True)
            user = []
            if hasattr(os, "getuid"):  # keep files in the checkout owned by the current user
                user = ["-u", f"{os.getuid()}:{os.getgid()}", "-e", "MAVEN_CONFIG=/var/maven/.m2",
                        "-e", "HOME=/var/maven", "-e", "GRADLE_USER_HOME=/var/maven/.gradle"]
                argv = argv[:1] + (["-Duser.home=/var/maven"] if argv[0] == "mvn" else []) + argv[1:]
            m2_mount = "/var/maven/.m2" if user else "/root/.m2"
            name = f"gp-{os.getpid()}-{int(t * 1000)}"
            argv = ["docker", "run", "--rm", "--name", name, "-v", f"{self.repo}:/work", "-w", "/work", *user,
                    "-v", f"{m2}:{m2_mount}", "--memory", os.environ.get("GP_DOCKER_MEMORY", "4g"), image] + argv
        elif os.name == "nt":
            # Windows: mvn and gradle are .cmd scripts, gradlew is gradlew.bat
            if argv[0] == "./gradlew":
                argv = [str(self.repo / "gradlew.bat")] + argv[1:]
            else:
                argv = [shutil.which(argv[0]) or argv[0]] + argv[1:]
        env = dict(os.environ)
        jhome = os.environ.get(f"GP_JDK{self.jdk}_HOME")
        if jhome and not self.docker:
            env["JAVA_HOME"] = jhome
            env["PATH"] = f"{jhome}/bin{os.pathsep}{env['PATH']}"
        try:
            p = subprocess.Popen(argv, cwd=self.repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 encoding="utf-8", errors="replace", env=env)
        except FileNotFoundError as e:
            return 127, str(e), time.time() - t
        try:
            out, err = p.communicate(timeout=timeout)
            return p.returncode, (out + "\n" + err), time.time() - t
        except subprocess.TimeoutExpired:
            # killing the docker client does not stop the container (on Windows the pipes then stay open until the
            # build ends), so remove the container first
            if self.docker:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=120)
            p.kill()
            try:
                out, err = p.communicate(timeout=120)
            except subprocess.TimeoutExpired:
                out, err = "", ""
            return None, (out or "") + "\n" + (err or ""), time.time() - t

    # ------------------------------------------------------------ public

    def compile(self) -> StepResult:
        argv = self._cmd("compile")
        rc, log, secs = self._run(argv, self.build_timeout)
        ok = rc == 0
        errors = [l.strip() for l in log.splitlines() if ("[ERROR]" in l and ".java" in l) or ": error:" in l][:40]
        stage = "compile" if rc is not None else "compile_timeout"
        return StepResult(ok, stage, " ".join(argv), rc, round(secs, 1), _tail(log), errors)

    def test(self, baseline: bool = False) -> StepResult:
        if self.tests == "skip":
            return StepResult(False, "tests_skipped")
        self._clear_reports()
        argv = self._cmd("test")
        rc, log, secs = self._run(argv, self.test_timeout)
        if rc is None:
            return StepResult(False, "tests_timeout", " ".join(argv), None, round(secs, 1), _tail(log))
        failed, total = self._read_reports()
        if baseline and total == 0 and self.tests == "related":
            # no test class matches the vulnerable classes: fall back to the whole module's tests
            self.tests = "module"
            (self.state_dir / "test_scope").write_text("module", encoding="utf-8")
            return self.test(baseline=True)
        res = StepResult(rc == 0, "tests", " ".join(argv), rc, round(secs, 1), _tail(log), failed_tests=sorted(failed), tests_run=total)
        if baseline:
            (self.state_dir / "baseline_tests.json").write_text(json.dumps({"failed": sorted(failed), "run": total, "rc": rc}), encoding="utf-8")
            return res
        base = self.baseline_failures()
        res.new_failures = sorted(set(failed) - set(base))
        # a build-level test failure with no test reports (e.g. the module stopped compiling tests) is a failure
        res.ok = rc == 0 and not res.new_failures and total > 0
        if rc != 0 and not failed:
            res.errors = [l.strip() for l in log.splitlines() if "[ERROR]" in l][:20]
        if total == 0:
            res.stage = "tests_none_ran"
        return res

    def run_named_tests(self, classes: list[str]) -> StepResult:
        """Compile and run only the given test classes (simple names). Used for PoV tests."""
        if not classes:
            return StepResult(False, "pov_none")
        self._clear_reports()
        saved = self.tests
        mods = [m for m in self.modules() if m]
        if self.tool == "maven":
            pl = ["-pl", ",".join(mods), "-am"] if mods else []
            argv = ["mvn", *MVN_FLAGS, *pl, "-Dmaven.test.failure.ignore=true", "-DfailIfNoTests=false",
                    "-Dsurefire.failIfNoSpecifiedTests=false", f"-Dtest={','.join(classes)}", "test"]
        elif self.tool == "gradle":
            g = "./gradlew" if (self.repo / "gradlew").exists() else "gradle"
            prefix = [f":{m.replace('/', ':')}:" for m in mods] or [""]
            argv = [g, "--no-daemon", "--continue", *[p + "test" for p in prefix]]
            for c in classes:
                argv += ["--tests", f"*{c}"]
        else:
            return StepResult(False, "pov_no_build_tool")
        self.tests = saved
        rc, log, secs = self._run(argv, self.test_timeout)
        if rc is None:
            return StepResult(False, "pov_timeout", " ".join(argv), None, round(secs, 1), _tail(log))
        failed, total = self._read_reports()
        compiled = total > 0 or rc == 0
        return StepResult(compiled and not failed, "pov" if compiled else "pov_compile", " ".join(argv), rc,
                          round(secs, 1), _tail(log), failed_tests=sorted(failed), tests_run=total,
                          errors=[l.strip() for l in log.splitlines() if "[ERROR]" in l and ".java" in l][:20])

    def baseline_failures(self) -> list[str]:
        p = self.state_dir / "baseline_tests.json"
        if not p.exists():
            return []
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))["failed"]

    def has_baseline(self) -> bool:
        return (self.state_dir / "baseline_tests.json").exists()

    # ------------------------------------------------------------ reports

    def _report_dirs(self):
        for pattern in ("**/target/surefire-reports", "**/build/test-results/test"):
            yield from self.repo.glob(pattern)

    def _clear_reports(self):
        for d in self._report_dirs():
            shutil.rmtree(d, ignore_errors=True)

    def _read_reports(self) -> tuple[set[str], int]:
        failed, total = set(), 0
        for d in self._report_dirs():
            for x in d.glob("*.xml"):
                try:
                    root = ET.parse(x).getroot()
                except Exception:
                    continue
                for tc in root.iter("testcase"):
                    total += 1
                    if tc.find("failure") is not None or tc.find("error") is not None:
                        failed.add(f"{tc.get('classname')}#{tc.get('name')}")
        return failed, total


def _tail(log: str, n: int = 60) -> str:
    lines = [l for l in log.splitlines() if l.strip()]
    keep = [l for l in lines if "[ERROR]" in l or "FAIL" in l or "error:" in l]
    return "\n".join((keep[-30:] if keep else []) + ["--- last lines ---"] + lines[-n:])[-6000:]
