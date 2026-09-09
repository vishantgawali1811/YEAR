"""
Interactive stress-test CLI: type any query, see exactly what the agent
does with it against your real dataset -- intent detected, product/version
parsed, risk scores, and summary or remediation output.

Run with: python interactive_test.py

Type 'quit', 'exit', or 'q' to stop.
Type 'reset' to clear session memory (start a fresh "conversation").
Type 'history' to see what the agent currently remembers.
"""

from retrieval import load_data
from agent import Agent

print("Loading dataset and model (this may take a few seconds)...")
df = load_data()
agent = Agent(df)
print(f"Ready. Dataset loaded with {len(df)} rows.\n")
print("Type a query and press Enter. Commands: 'reset', 'history', 'quit'\n")


def print_response(response):
    print(f"\n{'-'*60}")
    print(f"  Intent      : {response.intent}")
    print(f"  Product     : {response.product}")
    print(f"  Version     : {response.version}")
    print(f"  Parsed OK   : {response.parsed_ok}")
    if response.message:
        print(f"  Message     : {response.message}")
    print(f"  Results     : {len(response.results)} CVE(s)")
    print(f"{'-'*60}")

    for r in response.results:
        print(f"\n  [{r.cve_id}]  risk={r.risk_score}  priority={r.priority_label}  "
              f"cvss={r.cvss}  vector={r.attack_vector}  privileges={r.privileges}")
        if r.summary:
            print(f"    Summary: {r.summary}")
        if r.remediation:
            print(f"    Remediation:")
            for step in r.remediation:
                print(f"      - {step}")
    print()


while True:
    try:
        query = input(">> Enter query: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")
        break

    if query.lower() in {"quit", "exit", "q"}:
        print("Exiting.")
        break

    if query.lower() == "reset":
        agent = Agent(df)
        print("Session memory cleared -- starting fresh.\n")
        continue

    if query.lower() == "history":
        if not agent.history:
            print("No history yet in this session.\n")
        else:
            print("\nSession history so far:")
            for i, h in enumerate(agent.history, 1):
                print(f"  {i}. query={h['query']!r} -> product={h['product']!r}, version={h['version']!r}")
            print()
        continue

    response = agent.run(query)
    print_response(response)