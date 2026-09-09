"""
Retrieval layer: given a product (tech stack) name and a version, find every
real CVE in dataset_fixed.csv that affects it.

Pure lookup -- no model involved here. This is the "R" in RAG.

Data note:
    dataset_fixed.csv stores only the UPPER bound of each vulnerable version
    range (operator "<" or "<=") or an exact version (operator "=="), with no
    lower bound. To avoid a low version falsely matching an unrelated higher
    branch's upper bound, for each CVE we only count the CLOSEST (smallest)
    matching upper-bound branch as the real match.
"""

from pathlib import Path

import pandas as pd
from packaging.version import Version, InvalidVersion

DEFAULT_DATA_FILE = Path("Dataset/dataset_fixed.csv")


def safe_version(v):
    """Parse a version string, returning None if it isn't a valid version."""
    try:
        return Version(str(v))
    except (InvalidVersion, TypeError):
        return None


def condition_holds(query_v: Version, operator: str, threshold_v: Version) -> bool:
    if operator == "<":
        return query_v < threshold_v
    if operator == "<=":
        return query_v <= threshold_v
    if operator == "==":
        return query_v == threshold_v
    if operator == ">":
        return query_v > threshold_v
    if operator == ">=":
        return query_v >= threshold_v
    return False


def load_data(path: Path = DEFAULT_DATA_FILE) -> pd.DataFrame:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Could not find {path}")
    df = pd.read_csv(path)
    required = {"cve_id", "description", "cvss", "attack_vector", "privileges",
                "product", "version", "operator", "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"CSV is missing expected columns: {missing}")
    return df


def find_vulnerabilities(df: pd.DataFrame, product: str, version: str) -> pd.DataFrame:
    """
    Return a DataFrame of real CVE rows affecting `product` at `version`.
    Empty DataFrame (same columns, 0 rows) if nothing matches.
    """
    query_v = safe_version(version)
    if query_v is None:
        raise ValueError(f"'{version}' is not a parseable version string (expected e.g. 9.0.5).")

    product_rows = df[df["product"].str.lower().str.strip() == product.lower().strip()].copy()
    if product_rows.empty:
        return product_rows

    product_rows["_threshold"] = product_rows["version"].apply(safe_version)
    product_rows = product_rows.dropna(subset=["_threshold"])

    matches = []
    for cve_id, group in product_rows.groupby("cve_id"):
        satisfied = [
            row for _, row in group.iterrows()
            if condition_holds(query_v, row["operator"], row["_threshold"])
        ]
        if not satisfied:
            continue
        best = min(satisfied, key=lambda r: r["_threshold"])
        matches.append(best)

    if not matches:
        return pd.DataFrame(columns=df.columns)

    result = pd.DataFrame(matches).drop(columns=["_threshold"])
    return result.sort_values("cvss", ascending=False, na_position="last")


if __name__ == "__main__":
    # Quick manual test: python retrieval.py
    df = load_data()
    results = find_vulnerabilities(df, "pan-os", "8.1.20")
    print(results[["cve_id", "cvss", "label", "description"]].to_string())
