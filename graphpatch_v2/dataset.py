"""CWE-Bench-Java dataset access (https://github.com/iris-sast/cwe-bench-java)."""

from __future__ import annotations

import csv
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

DATASET_URL = "https://github.com/iris-sast/cwe-bench-java"
TEST_DIR_MARKERS = ("/src/test/", "src/test/", "/test/", "/tests/", "/it/")


def is_test_path(path: str) -> bool:
    p = "/" + path
    return any(m in p for m in ("/src/test/", "/test/java/", "/tests/", "/src/it/")) or Path(path).name.endswith("Test.java")


@dataclass
class CVE:
    slug: str
    cve_id: str
    cwe: str
    cwe_name: str
    repo_url: str
    buggy_commit: str
    fix_commits: list[str]
    advisory: dict = field(default_factory=dict)
    build: dict = field(default_factory=dict)
    fix_rows: list[dict] = field(default_factory=list)

    @property
    def main_fix_rows(self) -> list[dict]:
        return [r for r in self.fix_rows if r["file"].endswith(".java") and not is_test_path(r["file"])]

    @property
    def target_files(self) -> list[str]:
        return list(dict.fromkeys(r["file"] for r in self.main_fix_rows))

    @property
    def target_methods(self) -> set[tuple[str, str]]:
        return {(r["file"], r.get("method") or "") for r in self.main_fix_rows}

    @property
    def summary(self) -> str:
        a = self.advisory or {}
        return (a.get("summary") or "") + "\n" + (a.get("details") or "")[:1500]


class Dataset:
    def __init__(self, root: Path):
        self.root = Path(root)
        if not (self.root / "data" / "project_info.csv").exists():
            raise FileNotFoundError(f"CWE-Bench-Java not found at {self.root}. Run: git clone {DATASET_URL} {self.root}")
        rows = list(csv.DictReader(open(self.root / "data/project_info.csv", encoding="utf-8")))
        builds = {r["project_slug"]: r for r in csv.DictReader(open(self.root / "data/build_info.csv", encoding="utf-8"))}
        fixes: dict[str, list[dict]] = {}
        fixes_by_cve: dict[str, list[dict]] = {}
        for r in csv.DictReader(open(self.root / "data/fix_info.csv", encoding="utf-8")):
            fixes.setdefault(r["project_slug"], []).append(r)
            fixes_by_cve.setdefault(r["cve_id"], []).append(r)
        self.cves: dict[str, CVE] = {}
        for r in rows:
            slug = r["project_slug"]
            adv_path = self.root / "advisory" / f"{slug}.json"
            adv = json.load(open(adv_path, encoding="utf-8")) if adv_path.exists() else {}
            self.cves[slug] = CVE(
                slug=slug, cve_id=r["cve_id"], cwe=r["cwe_id"], cwe_name=r["cwe_name"],
                repo_url=r["github_url"], buggy_commit=r["buggy_commit_id"],
                fix_commits=[c for c in r["fix_commit_ids"].split(";") if c],
                advisory=adv, build=builds.get(slug, {}),
                # a few slugs differ between the two CSVs; fall back to the CVE id
                fix_rows=fixes.get(slug) or fixes_by_cve.get(r["cve_id"], []),
            )

    def get(self, key: str) -> CVE:
        if key in self.cves:
            return self.cves[key]
        matches = [c for c in self.cves.values() if c.cve_id == key]
        if not matches:
            raise KeyError(f"{key} is not in CWE-Bench-Java")
        return matches[0]

    def select(self, keys: list[str] | None = None, cwe: str | None = None, limit: int | None = None) -> list[CVE]:
        out = [self.get(k) for k in keys] if keys else list(self.cves.values())
        if cwe:
            out = [c for c in out if c.cwe == cwe]
        return out[:limit] if limit else out

    def build_patch(self, cve: CVE) -> Path | None:
        p = self.root / "patches" / f"{cve.slug}.patch"
        return p if p.exists() else None


def ensure_dataset(root: Path) -> Dataset:
    root = Path(root)
    if not (root / "data" / "project_info.csv").exists():
        root.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth", "1", DATASET_URL, str(root)], check=True)
    return Dataset(root)
