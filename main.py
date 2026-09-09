"""
Main entry point: product + version -> retrieve real CVEs -> Flan-T5 summary.

Usage:
    python main.py --product pan-os --version 8.1.20
    python main.py                                        # interactive mode
    python main.py --product pan-os --version 8.1.20 --raw # skip the model, show raw data only
"""

import argparse

from retrieval import load_data, find_vulnerabilities, DEFAULT_DATA_FILE
from generate import summarize
from parse_query import parse_query
from intent import classify_intent
from agent import Agent


def print_raw(results, product, version):
    if results.empty:
        print(f"\nNo known vulnerabilities found for {product} {version}.\n")
        return
    print(f"\n{len(results)} vulnerabilit{'y' if len(results) == 1 else 'ies'} found for {product} {version}:\n")
    for _, row in results.iterrows():
        print(f"  {row['cve_id']}  (CVSS {row['cvss']}, {row['label']})")
        print(f"    {row['description']}")
        print(f"    Attack Vector: {row['attack_vector']} | Privileges Required: {row['privileges']}")
        print(f"    Affected: {row['product']} {row['operator']} {row['version']}")
        print()


def run_query(df, product: str, version: str, raw: bool = False):
    results = find_vulnerabilities(df, product, version)

    print_raw(results, product, version)  # always show grounded facts first

    if not raw and not results.empty:
        print("AI Summaries (one per CVE):\n")
        for item in summarize(results, product, version):
            print(f"  {item['cve_id']}:")
            print(f"    {item['summary']}\n")


def run_remediation_query(agent: Agent, query: str) -> None:
    response = agent.run(query)
    if response.message:
        print(f"\n{response.message}\n")
        return
    for result in response.results:
        print(f"\n{result.cve_id}:")
        for step in result.remediation or []:
            print(f"  - {step}")


def main():
    parser = argparse.ArgumentParser(description="RAG CVE lookup: product + version -> grounded summary.")
    parser.add_argument("--product", help="Product / tech stack name, e.g. pan-os")
    parser.add_argument("--version", help="Version to check, e.g. 9.0.5")
    parser.add_argument("--query", help="Free-text question, e.g. 'is pan-os 8.1.20 vulnerable?'")
    parser.add_argument("--data", default=str(DEFAULT_DATA_FILE), help="Path to dataset_fixed.csv")
    parser.add_argument("--raw", action="store_true", help="Skip the model, print retrieved data only")
    args = parser.parse_args()

    df = load_data(args.data)

    if args.query:
        if classify_intent(args.query) == "remediation":
            run_remediation_query(Agent(df), args.query)
            return
        parsed = parse_query(args.query, df)
        if not parsed["product"] or not parsed["version"]:
            print(f"\nCouldn't work out both a product and a version from: \"{args.query}\"")
            print(f"  Detected product: {parsed['product']}")
            print(f"  Detected version: {parsed['version']}")
            print("Try rephrasing with a clear product name and version number.\n")
            return
        run_query(df, parsed["product"], parsed["version"], raw=args.raw)
        return

    if args.product and args.version:
        run_query(df, args.product, args.version, raw=args.raw)
        return

    print("RAG CVE lookup — ask a question, or type 'quit' to exit.")
    print("e.g. \"is pan-os 8.1.20 vulnerable?\"\n")
    while True:
        question = input("Ask: ").strip()
        if question.lower() in {"quit", "exit"}:
            break
        if classify_intent(question) == "remediation":
            run_remediation_query(Agent(df), question)
            continue
        parsed = parse_query(question, df)
        if not parsed["product"] or not parsed["version"]:
            print(f"  Couldn't detect both a product and version.")
            print(f"  Detected product: {parsed['product']}")
            print(f"  Detected version: {parsed['version']}")
            print("  Try again, e.g. \"is pan-os 8.1.20 vulnerable?\"\n")
            continue
        run_query(df, parsed["product"], parsed["version"])


if __name__ == "__main__":
    main()
