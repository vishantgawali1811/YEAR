"""
Agent orchestrator: classifies intent, extracts entities, routes to the
right tool sequence, and assembles a final structured response.
 
Deterministic routing (rule-based) for reliability; the AI reasoning
happens inside each tool (LLM summarization via generate.py, risk scoring
via risk_scoring.py, and rule-based remediation guidance).
"""
 
from typing import Optional
import pandas as pd
from pydantic import BaseModel
 
from parse_query import parse_query
from intent import classify_intent
from retrieval import find_vulnerabilities
from risk_scoring import rank_results
from generate import summarize, suggest_remediation
 
 
class AgentResultItem(BaseModel):
    cve_id: str
    product: str
    operator: str
    version: str
    cvss: Optional[float] = None
    label: Optional[str] = None
    description: str
    attack_vector: Optional[str] = None
    privileges: Optional[str] = None
    risk_score: Optional[float] = None
    priority_label: Optional[str] = None
    summary: Optional[str] = None
    remediation: Optional[list[str]] = None
 
 
class AgentResponse(BaseModel):
    intent: str
    product: Optional[str] = None
    version: Optional[str] = None
    parsed_ok: bool
    message: Optional[str] = None
    results: list[AgentResultItem] = []
 
 
class Agent:
    def __init__(self, df: pd.DataFrame):
        self.df = df
        self.history: list[dict] = []   # simple session memory for follow-ups
 
    def _last_known_entities(self):
        if not self.history:
            return None, None
        last = self.history[-1]
        return last.get("product"), last.get("version")
 
    def run(self, query: str) -> AgentResponse:
        # Guard against empty/blank input BEFORE touching history or parsing,
        # so a blank submission never silently reuses a previous turn's results.
        if not query or not query.strip():
            return AgentResponse(
                intent="lookup", product=None, version=None, parsed_ok=False,
                message="Please enter a question, e.g. 'is pan-os 8.1.20 vulnerable?'",
                results=[],
            )
 
        intent = classify_intent(query)
        parsed = parse_query(query, self.df)
 
        product, version = parsed["product"], parsed["version"]
 
        # Follow-up support: if this turn is missing product/version,
        # reuse the last turn's values (e.g. "what about the critical ones only?")
        if not product or not version:
            prev_product, prev_version = self._last_known_entities()
            product = product or prev_product
            version = version or prev_version
 
        if not product or not version:
            return AgentResponse(
                intent=intent, product=product, version=version, parsed_ok=False,
                message=(
                    "Couldn't detect both a product and a version in that question. "
                    f"Detected product: {product}, detected version: {version}."
                ),
                results=[],
            )
 
        results_df = find_vulnerabilities(self.df, product, version)
 
        if results_df.empty:
            self.history.append({"query": query, "product": product, "version": version})
            return AgentResponse(
                intent=intent, product=product, version=version, parsed_ok=True,
                message=f"No known vulnerabilities found for {product} {version}.",
                results=[],
            )
 
        ranked_df = rank_results(results_df)
 
        # Attach generation output based on intent -- only generate what's needed
        remediation_map, summary_map = {}, {}
        if intent == "remediation":
            for item in suggest_remediation(ranked_df):
                remediation_map[item["cve_id"]] = item["remediation"]
        else:
            for item in summarize(ranked_df, product, version):
                summary_map[item["cve_id"]] = item["summary"]
 
        results = []
        for _, row in ranked_df.iterrows():
            results.append(AgentResultItem(
                cve_id=row["cve_id"],
                product=row["product"],
                operator=row["operator"],
                version=str(row["version"]),
                cvss=row["cvss"] if row["cvss"] == row["cvss"] else None,  # NaN check
                label=row["label"],
                description=row["description"],
                attack_vector=row["attack_vector"],
                privileges=row["privileges"],
                risk_score=row.get("risk_score"),
                priority_label=row.get("priority_label"),
                summary=summary_map.get(row["cve_id"]),
                remediation=remediation_map.get(row["cve_id"]),
            ))
 
        self.history.append({"query": query, "product": product, "version": version})
 
        return AgentResponse(
            intent=intent, product=product, version=version,
            parsed_ok=True, results=results,
        )
 
 
if __name__ == "__main__":
    # Quick manual test: python agent.py
    from retrieval import load_data
 
    df = load_data()
    agent = Agent(df)
 
    tests = [
        "is pan-os 8.1.20 vulnerable?",
        "how do I fix pan-os 8.1.20?",
        "what about pan-os 9.0.10?",
        "",  # empty query -- should now fail cleanly, not reuse history
    ]
 
    for t in tests:
        print(f"\n{'='*70}")
        print(f"QUERY: {t!r}")
        print(f"{'='*70}")
        response = agent.run(t)
        print(f"Intent: {response.intent}")
        print(f"Product/Version: {response.product} / {response.version}")
        print(f"Parsed OK: {response.parsed_ok}")
        if response.message:
            print(f"Message: {response.message}")
        for r in response.results:
            print(f"\n  {r.cve_id} | risk={r.risk_score} ({r.priority_label})")
            if r.summary:
                print(f"    summary: {r.summary}")
            if r.remediation:
                for step in r.remediation:
                    print(f"    - {step}")
 