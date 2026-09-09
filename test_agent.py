"""
Stress test for agent.py -- runs a wide variety of queries, including
edge cases that could break it live during a demo. Prints results in a
compact, scannable format so you can eyeball correctness quickly.
 
Run with: python test_agent.py
 
IMPORTANT: edit the product/version values in the test list below to match
products you know exist in your Dataset/dataset_fixed.csv, otherwise the
"known good" tests will just show "No known vulnerabilities found" and
you won't actually be testing anything meaningful.
"""
 
from retrieval import load_data
from agent import Agent
 
df = load_data()
 
 
def print_result(query: str, response) -> None:
    print(f"\n{'='*70}")
    print(f"QUERY: {query!r}")
    print(f"{'-'*70}")
    print(f"  intent={response.intent}  parsed_ok={response.parsed_ok}  "
          f"product={response.product!r}  version={response.version!r}")
    if response.message:
        print(f"  message: {response.message}")
    print(f"  results: {len(response.results)} CVE(s)")
    for r in response.results[:2]:  # only show first 2 per query to keep output short
        has_summary = r.summary is not None
        has_remediation = r.remediation is not None
        print(f"    - {r.cve_id}: risk={r.risk_score} ({r.priority_label}) "
              f"| summary={'YES' if has_summary else 'no'} "
              f"| remediation={'YES' if has_remediation else 'no'}")
    if len(response.results) > 2:
        print(f"    ... and {len(response.results) - 2} more")
 
 
# ============================================================
# GROUP 1: Basic happy-path queries (should all work cleanly)
# ============================================================
print("\n" + "#"*70)
print("# GROUP 1: BASIC LOOKUP QUERIES")
print("#"*70)
 
agent = Agent(df)  # fresh agent, no history yet
basic_queries = [
    "is pan-os 8.1.20 vulnerable?",
    "check pan-os version 9.0.10",
    "any known CVEs for pan-os 10.2.0?",
]
for q in basic_queries:
    print_result(q, agent.run(q))
 
 
# ============================================================
# GROUP 2: Remediation queries (should skip summary, show remediation)
# ============================================================
print("\n" + "#"*70)
print("# GROUP 2: REMEDIATION QUERIES")
print("#"*70)
 
agent2 = Agent(df)
remediation_queries = [
    "how do I fix pan-os 8.1.20?",
    "what's the patch for pan-os 9.0.10?",
    "how to remediate pan-os 10.2.0",
]
for q in remediation_queries:
    print_result(q, agent2.run(q))
 
 
# ============================================================
# GROUP 3: Follow-up / memory queries (missing product or version)
# ============================================================
print("\n" + "#"*70)
print("# GROUP 3: FOLLOW-UP QUERIES (session memory)")
print("#"*70)
 
agent3 = Agent(df)
print_result("is pan-os 8.1.20 vulnerable?", agent3.run("is pan-os 8.1.20 vulnerable?"))
print_result("what about the fix for that?", agent3.run("what about the fix for that?"))
# ^ this SECOND query has no product/version in the text at all --
#   it should reuse "pan-os"/"8.1.20" from history AND correctly
#   detect "fix" as remediation intent.
 
 
# ============================================================
# GROUP 4: Edge cases / things that SHOULD fail gracefully
# ============================================================
print("\n" + "#"*70)
print("# GROUP 4: EDGE CASES (should fail gracefully, not crash)")
print("#"*70)
 
agent4 = Agent(df)
edge_cases = [
    "hello",                                    # no product, no version, nothing
    "is windows vulnerable?",                   # product with no version
    "check version 5.0.0",                      # version with no product
    "is nonexistentproduct 1.0.0 vulnerable?",  # valid format, fake product
    "IS PAN-OS 8.1.20 VULNERABLE???",           # all caps + punctuation
    "",                                         # empty string
]
for q in edge_cases:
    try:
        print_result(q, agent4.run(q))
    except Exception as e:
        print(f"\n{'='*70}")
        print(f"QUERY: {q!r}")
        print(f"  *** CRASHED: {type(e).__name__}: {e}")
 
 
# ============================================================
# GROUP 5: Stats intent (KNOWN GAP -- agent.py has no stats branch yet)
# ============================================================
print("\n" + "#"*70)
print("# GROUP 5: STATS QUERIES (expected to be UNHANDLED for now)")
print("#"*70)
 
agent5 = Agent(df)
stats_queries = [
    "what are the top vulnerable products?",
    "how many critical CVEs do we have?",
]
for q in stats_queries:
    try:
        print_result(q, agent5.run(q))
    except Exception as e:
        print(f"\n{'='*70}")
        print(f"QUERY: {q!r}")
        print(f"  *** CRASHED: {type(e).__name__}: {e}")
 
print("\n" + "#"*70)
print("# DONE -- review each group above:")
print("#"*70)
print("""
  GROUP 1: all should have parsed_ok=True, summary=YES, remediation=no
  GROUP 2: all should have parsed_ok=True, summary=no, remediation=YES
  GROUP 3: second query should have parsed_ok=True (reused product/version
           from the first query) and intent=remediation, remediation=YES
  GROUP 4: NONE of these should crash the script. parsed_ok=False is fine
           and expected for most of these -- that's the correct graceful
           failure. Watch specifically for "nonexistentproduct" -- it
           should parse (parsed_ok=True) but return 0 results, NOT crash.
  GROUP 5: currently intent will say "stats" but the agent will still try
           to do a product/version lookup and likely return parsed_ok=False
           since there's no product/version to find. This is a KNOWN GAP,
           not a bug -- decide if you need a real stats handler before Thursday.
""")
 