"""
FastAPI backend for the CVE RAG tool.

Wraps the existing, already-tested pipeline (retrieval.py, generate.py,
parse_query.py) behind HTTP endpoints so a frontend can call it.

Run with:
    uvicorn app:app --reload --port 8000

Then test in your browser at:
    http://localhost:8000/docs   (interactive API docs, auto-generated)
"""
from agent import Agent, AgentResponse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from retrieval import load_data, find_vulnerabilities
from generate import summarize
from parse_query import parse_query

app = FastAPI(title="CVE RAG Lookup API")


class StatResponse(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    top_product: str | None
    top_product_count: int

# Allow the React dev server (usually localhost:3000 or 5173) to call this API.
# Tighten this to your actual frontend URL before deploying anywhere public.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load the dataset once at startup, not on every request.
df = load_data()
agent = Agent(df)   # reuse the already-loaded df, shared across requests


class QueryRequest(BaseModel):
    query: str


class LookupRequest(BaseModel):
    product: str
    version: str


class CVEResult(BaseModel):
    cve_id: str
    cvss: float | None
    label: str | None
    description: str
    attack_vector: str | None
    privileges: str | None
    product: str
    operator: str
    version: str
    summary: str | None = None


class QueryResponse(BaseModel):
    product: str | None
    version: str | None
    parsed_ok: bool
    message: str | None = None
    results: list[CVEResult] = []


def _build_response(product: str, version: str, results_df, with_summary: bool) -> QueryResponse:
    if results_df.empty:
        return QueryResponse(
            product=product,
            version=version,
            parsed_ok=True,
            message=f"No known vulnerabilities found for {product} {version}.",
            results=[],
        )

    summaries = {}
    if with_summary:
        for item in summarize(results_df, product, version):
            summaries[item["cve_id"]] = item["summary"]

    results = []
    for _, row in results_df.iterrows():
        results.append(CVEResult(
            cve_id=row["cve_id"],
            cvss=row["cvss"] if row["cvss"] == row["cvss"] else None,  # NaN check
            label=row["label"],
            description=row["description"],
            attack_vector=row["attack_vector"],
            privileges=row["privileges"],
            product=row["product"],
            operator=row["operator"],
            version=str(row["version"]),
            summary=summaries.get(row["cve_id"]),
        ))

    return QueryResponse(product=product, version=version, parsed_ok=True, results=results)


@app.get("/")
def root():
    return {"status": "ok", "message": "CVE RAG API is running. See /docs for usage."}


@app.get("/stats", response_model=StatResponse)
def stats():
    """Dataset summary counts for the frontend dashboard KPI tiles."""
    label_col = df["label"].str.upper() if "label" in df.columns else None
    top = df["product"].value_counts()
    return StatResponse(
        total=len(df["cve_id"].dropna().unique()),
        critical=int((label_col == "CRITICAL").sum()) if label_col is not None else 0,
        high=int((label_col == "HIGH").sum()) if label_col is not None else 0,
        medium=int((label_col == "MEDIUM").sum()) if label_col is not None else 0,
        low=int((label_col == "LOW").sum()) if label_col is not None else 0,
        top_product=str(top.index[0]) if len(top) > 0 else None,
        top_product_count=int(top.iloc[0]) if len(top) > 0 else 0,
    )


@app.post("/lookup", response_model=QueryResponse)
def lookup(req: LookupRequest):
    """Direct lookup: explicit product + version, no parsing needed."""
    try:
        results_df = find_vulnerabilities(df, req.product, req.version)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _build_response(req.product, req.version, results_df, with_summary=True)


@app.post("/query", response_model=QueryResponse)
def query(req: QueryRequest):
    """Free-text query: e.g. 'is pan-os 8.1.20 vulnerable?' -- parses then looks up."""
    parsed = parse_query(req.query, df)

    if not parsed["product"] or not parsed["version"]:
        return QueryResponse(
            product=parsed["product"],
            version=parsed["version"],
            parsed_ok=False,
            message=(
                "Couldn't detect both a product and a version in that question. "
                f"Detected product: {parsed['product']}, detected version: {parsed['version']}."
            ),
            results=[],
        )

    results_df = find_vulnerabilities(df, parsed["product"], parsed["version"])
    return _build_response(parsed["product"], parsed["version"], results_df, with_summary=True)


@app.post("/lookup-raw", response_model=QueryResponse)
def lookup_raw(req: LookupRequest):
    """Same as /lookup but skips the AI summary step -- faster, for quick checks."""
    try:
        results_df = find_vulnerabilities(df, req.product, req.version)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _build_response(req.product, req.version, results_df, with_summary=False)

@app.post("/agent-query", response_model=AgentResponse)
def agent_query(req: QueryRequest):
    """
    Agentic endpoint: classifies intent (lookup/remediation/stats), routes
    across tools accordingly, and returns a structured response including
    risk scores and, for remediation queries, rule-based fix guidance
    instead of a plain LLM summary.
    """
    return agent.run(req.query)
