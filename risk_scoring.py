"""
Risk scoring layer: turns a set of retrieved CVEs into a prioritized list.

Pure domain logic -- no ML model here, deliberately. This is decision-support
reasoning layered on top of retrieval.py's output: given several real CVEs,
which one should a security team patch FIRST?

Score formula (0-100 scale):
    base       = cvss * 10                      (CVSS is 0-10 -> scale to 0-100)
    + network_bonus   if attack_vector is remote/network-based (no physical access needed)
    + no_priv_bonus    if privileges required is "none" (any attacker can exploit)
    capped at 100.

This is intentionally simple and explainable -- you should be able to justify
every point of this formula out loud to a panel.
"""

import pandas as pd

NETWORK_BONUS = 10
NO_PRIVILEGE_BONUS = 10

PRIORITY_THRESHOLDS = [
    (85, "Critical"),
    (65, "High"),
    (40, "Medium"),
    (0, "Low"),
]


def _is_network_vector(attack_vector) -> bool:
    if not isinstance(attack_vector, str):
        return False
    return attack_vector.strip().lower() in {"network", "remote"}


def _requires_no_privileges(privileges) -> bool:
    if not isinstance(privileges, str):
        return False
    return privileges.strip().lower() in {"none", "no privileges required", "unauthenticated"}


def compute_risk_score(row: pd.Series) -> float:
    """Compute a 0-100 risk/priority score for a single CVE row."""
    cvss = row.get("cvss")
    base = float(cvss) * 10 if pd.notna(cvss) else 0.0

    bonus = 0
    if _is_network_vector(row.get("attack_vector")):
        bonus += NETWORK_BONUS
    if _requires_no_privileges(row.get("privileges")):
        bonus += NO_PRIVILEGE_BONUS

    return min(100.0, round(base + bonus, 1))


def _priority_label(score: float) -> str:
    for threshold, label in PRIORITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Low"


def rank_results(results_df: pd.DataFrame) -> pd.DataFrame:
    """
    Adds 'risk_score' and 'priority_label' columns to a retrieval.py results
    DataFrame, sorted descending by risk_score (highest priority first).

    Safe to call on an empty DataFrame -- returns it unchanged.
    """
    if results_df.empty:
        out = results_df.copy()
        out["risk_score"] = pd.Series(dtype=float)
        out["priority_label"] = pd.Series(dtype=str)
        return out

    out = results_df.copy()
    out["risk_score"] = out.apply(compute_risk_score, axis=1)
    out["priority_label"] = out["risk_score"].apply(_priority_label)
    return out.sort_values("risk_score", ascending=False)


if __name__ == "__main__":
    # Quick manual test: python risk_scoring.py
    from retrieval import load_data, find_vulnerabilities

    df = load_data()
    results = find_vulnerabilities(df, "pan-os", "8.1.20")
    ranked = rank_results(results)
    print(ranked[["cve_id", "cvss", "attack_vector", "privileges",
                   "risk_score", "priority_label"]].to_string())