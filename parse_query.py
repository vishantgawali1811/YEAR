"""
Parses a free-text question like "is pan-os 8.1.20 vulnerable?" into a
(product, version) pair that retrieval.py can use.

Deterministic, rule-based (regex + matching against the real product list
from the dataset) -- NOT an LLM call. This is more reliable and much faster
than asking flan-t5-base to extract structured fields, which it was never
trained/tuned to do well.
"""

import re
from typing import Optional

import pandas as pd

VERSION_RE = re.compile(r"\b\d+(?:\.\d+){1,3}\b")

# Common filler words to strip out when isolating the product name.
STOPWORDS = {
    "is", "are", "the", "a", "an", "of", "in", "for", "on", "to",
    "vulnerable", "vulnerability", "vulnerabilities", "cve", "cves",
    "affected", "affects", "check", "does", "do", "have", "has",
    "any", "known", "please", "version", "versions", "using",
    "we", "i", "im", "am", "running", "run", "with", "what",
    "tell", "me", "about", "there", "exist", "exists",
}


def get_known_products(df: pd.DataFrame) -> list[str]:
    """Unique product names from the dataset, used to match against the query text."""
    return sorted(df["product"].dropna().str.lower().unique().tolist())


def extract_version(text: str) -> Optional[str]:
    match = VERSION_RE.search(text)
    return match.group(0) if match else None


def extract_product(text: str, known_products: list[str]) -> Optional[str]:
    lowered = text.lower()

    # 1. Try direct substring match against every known product name first --
    #    this correctly handles multi-word / hyphenated product names
    #    (e.g. "pan-os", "active_iq_unified_manager") without needing to
    #    reconstruct them from split tokens.
    candidates = [p for p in known_products if p.replace("_", " ") in lowered or p in lowered]
    if candidates:
        # Prefer the longest match (most specific) if multiple substrings hit.
        return max(candidates, key=len)

    # 2. Fallback: strip version numbers, punctuation, and stopwords, and
    #    see if what's left matches a known product with some tokens shared.
    text_no_version = VERSION_RE.sub("", lowered)
    tokens = re.findall(r"[a-z0-9\-_]+", text_no_version)
    remaining = [t for t in tokens if t not in STOPWORDS]

    best_match, best_overlap = None, 0
    for product in known_products:
        product_tokens = set(re.split(r"[\-_ ]+", product))
        overlap = len(product_tokens & set(remaining))
        if overlap > best_overlap:
            best_match, best_overlap = product, overlap

    return best_match


def parse_query(text: str, df: pd.DataFrame) -> dict:
    """
    Returns {"product": str or None, "version": str or None, "raw": text}.
    Caller should check for None values and prompt the user if extraction failed.
    """
    known_products = get_known_products(df)
    return {
        "product": extract_product(text, known_products),
        "version": extract_version(text),
        "raw": text,
    }


if __name__ == "__main__":
    # Quick manual test
    from retrieval import load_data

    df = load_data()
    tests = [
        "is pan-os 8.1.20 vulnerable?",
        "any known CVEs for android 12.0",
        "check firefox version 3.4.5",
        "what about pan-os",  # missing version
    ]
    for t in tests:
        print(t, "->", parse_query(t, df))
