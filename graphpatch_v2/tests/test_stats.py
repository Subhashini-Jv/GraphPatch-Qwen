"""The paper's Section V-B numbers, recomputed from Table III."""

from graphpatch_v2.stats import compare, mcnemar_exact, wilson

CVES = ["CVE-2022-25842", "CVE-2018-1002201", "CVE-2018-1002200", "CVE-2018-1002202", "CVE-2018-17297",
        "CVE-2020-35460", "CVE-2018-12036", "CVE-2022-31194", "CVE-2022-26049"]
TABLE3 = {"rule": "VPVVPVVPR", "single": "VPVRPVPPE", "nograph": "VPVPPVVPV", "full": "VPVVVVPRV"}
V = {m: {c: s == "V" for c, s in zip(CVES, col)} for m, col in TABLE3.items()}


def test_wilson_matches_paper():
    lo, hi = wilson(6, 9)
    assert (round(100 * lo), round(100 * hi)) == (35, 88)
    lo, hi = wilson(5, 9)
    assert (round(100 * lo), round(100 * hi)) == (27, 81)


def test_mcnemar_matches_paper():
    assert compare(V["full"], V["single"])["p"] == 0.25
    assert compare(V["full"], V["nograph"])["p"] == 1.0
    assert compare(V["full"], V["rule"])["p"] == 1.0


def test_six_discordant_needed_for_significance():
    assert mcnemar_exact(5, 0) > 0.05 and mcnemar_exact(6, 0) < 0.05
