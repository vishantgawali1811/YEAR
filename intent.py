"""
Intent classification layer for the agent.

Deterministic, keyword-based (NOT an LLM call) -- same design philosophy as
parse_query.py: fast, explainable, and reliable for a live demo. The agent
uses this to decide WHICH tools to call, not just what product/version to
look up.

Intents:
    "remediation" -> user wants to know how to fix something
    "stats"       -> user wants dataset-wide numbers/trends, not a single lookup
    "lookup"      -> default -- "is X vulnerable", "check Y version Z"
"""

import re

REMEDIATION_KEYWORDS = [
    "fix", "patch", "remediate", "remediation", "resolve", "mitigate",
    "mitigation", "how do i fix", "how to fix", "solution", "solve",
]

STATS_KEYWORDS = [
    "top", "how many", "stats", "statistics", "trend", "trends",
    "overview", "summary of all", "most vulnerable", "worst",
    "which product", "across all", "total number",
]


def _contains_any(text: str, keywords: list[str]) -> bool:
    return any(re.search(r"\b" + re.escape(kw) + r"\b", text) for kw in keywords)


def classify_intent(text: str) -> str:
    """
    Returns one of: "remediation", "stats", "lookup".

    Order matters: remediation is checked first because a query like
    "how do I fix the pan-os vulnerability" would otherwise also look like
    a plain lookup (it still contains a product/version).
    """
    lowered = text.lower().strip()

    if _contains_any(lowered, REMEDIATION_KEYWORDS):
        return "remediation"

    if _contains_any(lowered, STATS_KEYWORDS):
        return "stats"

    return "lookup"


if __name__ == "__main__":
    tests = [
        "is pan-os 8.1.20 vulnerable?",
        "how do I fix pan-os 8.1.20?",
        "what are the top vulnerable products?",
        "how many critical CVEs do we have?",
        "check firefox version 3.4.5",
        "what's the remediation for android 12.0?",
    ]
    for t in tests:
        print(f"{t!r:55} -> {classify_intent(t)}")