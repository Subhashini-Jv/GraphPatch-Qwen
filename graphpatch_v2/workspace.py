"""Per-CVE git workspaces: the vulnerable commit, a clean baseline, and resets."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .dataset import CVE, Dataset, is_test_path

BASE_BRANCH = "graphpatch-base"  # older work copies; each CVE now has its own branch (see Workspace.base)


def _force_remove(func, path, _exc):
    """Windows marks git object files read-only; clear the flag and retry."""
    import os
    import stat
    os.chmod(path, stat.S_IWRITE)
    func(path)


def git(repo: Path, *args, check=True, timeout=1800) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=repo, check=check, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def final_fix_commit(cache: Path, cve: CVE) -> str:
    """The newest of the CVE's fix commits (the dataset does not always list them oldest first)."""
    best, best_t = cve.fix_commits[-1], -1
    for c in cve.fix_commits:
        if git(cache, "cat-file", "-e", f"{c}^{{commit}}", check=False).returncode != 0:
            git(cache, "fetch", "--filter=blob:none", "origin", c, check=False)
        r = git(cache, "log", "-1", "--format=%ct", c, check=False)
        if r.returncode == 0 and r.stdout.strip().isdigit() and int(r.stdout.strip()) > best_t:
            best, best_t = c, int(r.stdout.strip())
    return best


class Workspace:
    """A checkout of one CVE's project at the vulnerable commit.

    The dataset's build patch (if any) is applied and committed on a local
    branch, so every repair attempt starts from exactly the same tree and
    `reset()` returns to it.
    """

    def __init__(self, cve: CVE, dataset: Dataset, root: Path):
        self.cve = cve
        self.dataset = dataset
        self.cache = Path(root) / "cache" / cve.repo_url.rstrip("/").split("github.com/")[-1].replace("/", "__")
        self.path = Path(root) / "work" / cve.slug
        # Work copies of CVEs from the same project share one git cache, and git lets a branch be checked out
        # in only one of them, so each CVE gets its own baseline branch (yamcs 45277 and 45278 clashed).
        self.base = f"{BASE_BRANCH}-{cve.slug}"

    # ------------------------------------------------------------ setup

    def _ensure_cache(self):
        if not (self.cache / ".git").exists() and not (self.cache / "HEAD").exists():
            self.cache.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "clone", "-c", "core.autocrlf=false", "--filter=blob:none", "--no-checkout", self.cve.repo_url, str(self.cache)],
                           check=True, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=3600)
        # Git for Windows turns LF into CRLF on checkout by default; the builds run in Linux containers, where a
        # CRLF ./gradlew fails with "sh\r: No such file or directory". Keep files byte-for-byte as in the repo.
        git(self.cache, "config", "core.autocrlf", "false")
        git(self.cache, "config", "core.eol", "lf")
        for c in [self.cve.buggy_commit] + self.cve.fix_commits:
            if git(self.cache, "cat-file", "-e", f"{c}^{{commit}}", check=False).returncode != 0:
                git(self.cache, "fetch", "--filter=blob:none", "origin", c, check=False)

    def prepare(self) -> "Workspace":
        self._ensure_cache()
        marker = self.path.parent / f"{self.cve.slug}.lf"
        if self.path.exists() and not marker.exists():
            print("   ! work copy was checked out with Windows line endings; recreating it")
        elif self.path.exists() and git(self.path, "rev-parse", "--verify", self.base, check=False).returncode == 0:
            try:
                self.reset()
                return self
            except subprocess.CalledProcessError as e:
                # a worktree left half-made by an earlier crash or a lost connection: build it again from scratch
                print(f"   ! work copy is broken ({(e.stderr or '').strip()[:200]}); recreating it")
        if self.path.exists():
            shutil.rmtree(self.path, onerror=_force_remove)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        git(self.cache, "worktree", "prune", check=False)
        git(self.cache, "worktree", "add", "-f", "--detach", str(self.path), self.cve.buggy_commit)
        git(self.path, "checkout", "-B", self.base)
        patch = self.dataset.build_patch(self.cve)
        if patch:
            r = git(self.path, "apply", str(patch), check=False)
            if r.returncode != 0:
                print(f"   ! dataset build patch did not apply cleanly: {r.stderr.strip()[:300]}")
        git(self.path, "-c", "user.name=graphpatch", "-c", "user.email=graphpatch@localhost",
            "commit", "-q", "--allow-empty", "-am", "graphpatch baseline (vulnerable commit + dataset build patch)")
        marker.write_text("checked out with core.autocrlf=false\n")
        return self

    # ------------------------------------------------------------ state

    def reset(self):
        git(self.path, "checkout", "-q", "-f", self.base)
        git(self.path, "reset", "-q", "--hard", self.base)
        git(self.path, "clean", "-q", "-fd", "-e", "target/", "-e", "build/", "-e", ".gradle/")

    def diff(self) -> str:
        return git(self.path, "diff", self.base, "--", ".", check=False).stdout

    def changed_files(self) -> list[str]:
        return [l for l in git(self.path, "diff", "--name-only", self.base, check=False).stdout.splitlines() if l]

    # ------------------------------------------------------------ oracle

    @property
    def fix_commit(self) -> str:
        if not hasattr(self, "_fix"):
            self._fix = final_fix_commit(self.cache, self.cve)
        return self._fix

    def apply_reference_fix(self) -> list[str]:
        """Bring the real fix's versions of the vulnerable main-source files into the tree.

        Only non-test Java files the benchmark lists are taken, so the project's
        own tests from the vulnerable commit still run against them.
        """
        last = self.fix_commit
        taken = []
        for f in self.cve.target_files:
            r = git(self.path, "show", f"{last}:{f}", check=False)
            if r.returncode == 0:
                (self.path / f).write_text(r.stdout, encoding="utf-8")
                taken.append(f)
            else:
                (self.path / f).unlink(missing_ok=True)  # file deleted by the fix
                taken.append(f + " (deleted)")
        return taken


def files_at_commit(cache_root: Path, cve: CVE, commit: str, files: list[str], dest: Path) -> list[str]:
    """Check out only the directories holding `files` at `commit` into dest (sparse).

    Used by calibration so it does not need full checkouts of large projects.
    """
    cache = Path(cache_root) / "cache" / cve.repo_url.rstrip("/").split("github.com/")[-1].replace("/", "__")
    if not (cache / ".git").exists() and not (cache / "HEAD").exists():
        cache.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", cve.repo_url, str(cache)],
                       check=True, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=3600)
    if git(cache, "cat-file", "-e", f"{commit}^{{commit}}", check=False).returncode != 0:
        git(cache, "fetch", "--filter=blob:none", "origin", commit, check=False)
    if dest.exists():
        git(cache, "worktree", "remove", "-f", str(dest), check=False)
        shutil.rmtree(dest, ignore_errors=True)
    git(cache, "worktree", "prune", check=False)
    dest.parent.mkdir(parents=True, exist_ok=True)
    git(cache, "worktree", "add", "-f", "--no-checkout", "--detach", str(dest), commit)
    dirs = sorted({str(Path(f).parent) for f in files})
    git(dest, "sparse-checkout", "init", "--no-cone", check=False)
    git(dest, "sparse-checkout", "set", "--no-cone", *[f"/{d}/*.java" for d in dirs], check=False)
    git(dest, "checkout", "-q", "-f", commit, check=False)
    return [f for f in files if (dest / f).exists()]


# ------------------------------------------------------------ proof-of-vulnerability tests

def pov_files(ws: Workspace) -> list[str]:
    """Test files (sources and resources) that the real fix added or changed.

    Run against a candidate patch, these act as proof-of-vulnerability tests:
    they usually fail on the vulnerable code and pass on the fixed code.
    """
    last = ws.fix_commit
    out = git(ws.cache, "diff", "--name-only", "--diff-filter=AM", ws.cve.buggy_commit, last, check=False).stdout.splitlines()
    return [p for p in out if is_test_path(p) or "/src/test/" in "/" + p]


def overlay(ws: Workspace, files: list[str]) -> list[str]:
    """Write the fix commit's versions of `files` into the workspace. Returns the files written."""
    last = ws.fix_commit
    written = []
    for f in files:
        r = subprocess.run(["git", "show", f"{last}:{f}"], cwd=ws.cache, capture_output=True, timeout=600)
        if r.returncode == 0:
            p = ws.path / f
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(r.stdout)
            written.append(f)
    return written


def remove_overlay(ws: Workspace, files: list[str]):
    """Undo `overlay` without touching the candidate patch."""
    for f in files:
        if git(ws.path, "cat-file", "-e", f"{ws.base}:{f}", check=False).returncode == 0:
            git(ws.path, "checkout", ws.base, "--", f, check=False)
        else:
            (ws.path / f).unlink(missing_ok=True)
