"""
Generation layer: takes real, retrieved CVE rows (a DataFrame from
retrieval.py) and asks Flan-T5 to rephrase/summarize them in plain English.

Uses the PRETRAINED google/flan-t5-base model as-is -- no fine-tuning needed,
because the model is only rephrasing facts it's given, not recalling facts
from memory. This is the "G" in RAG.
"""

import pandas as pd
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM

MODEL_NAME = "google/flan-t5-base"
MAX_INPUT_TOKENS = 512
MAX_OUTPUT_TOKENS = 200

_tokenizer = None
_model = None


def _load_model():
    """Lazy-load so importing this module doesn't immediately pull the model into memory."""
    global _tokenizer, _model
    if _model is None:
        _tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        _model = AutoModelForSeq2SeqLM.from_pretrained(MODEL_NAME, attn_implementation="eager")
    return _tokenizer, _model


def _operator_phrase(operator: str) -> str:
    return {
        "<": "earlier than",
        "<=": "up to and including",
        "==": "exactly",
        ">": "later than",
        ">=": "starting from",
    }.get(operator, operator)


def build_single_cve_prompt(row: pd.Series) -> str:
    """Turn ONE retrieved CVE row into a grounded prompt for the model to rephrase."""
    op_phrase = _operator_phrase(row["operator"])
    facts_sentence = (
        f"{row['cve_id']} is a {row['label']} severity vulnerability with a CVSS score of "
        f"{row['cvss']}. {row['description']} It can be exploited over the {row['attack_vector']} "
        f"attack vector and requires {row['privileges']} privileges. It affects {row['product']} "
        f"versions {op_phrase} {row['version']}."
    )
    return (
        "Rewrite the passage below as a short, natural, plain-English paragraph for a "
        "non-technical reader. Do not copy field labels, do not list facts line by line, "
        "and do not add any information that isn't in the passage.\n\n"
        f"Passage: {facts_sentence}\n\nRewritten paragraph:"
    )


def _generate(prompt: str) -> str:
    tokenizer, model = _load_model()
    inputs = tokenizer(
        prompt, return_tensors="pt", truncation=True, max_length=MAX_INPUT_TOKENS
    )
    outputs = model.generate(
        **inputs,
        max_length=MAX_OUTPUT_TOKENS,
        num_beams=4,
        repetition_penalty=1.3,
        no_repeat_ngram_size=3,
    )
    return tokenizer.decode(outputs[0], skip_special_tokens=True)


def summarize(results: pd.DataFrame, product: str, version: str) -> list[dict]:
    """
    Returns a list of {"cve_id": ..., "summary": ...} -- one entry per CVE,
    summarized separately. This plays to flan-t5-base's strengths: it's a
    small model and stays far more faithful to the facts on short, single-CVE
    prompts than when asked to condense many CVEs into one paragraph.
    """
    if results.empty:
        return [{
            "cve_id": None,
            "summary": f"No known vulnerabilities were found for {product} version {version}.",
        }]

    summaries = []
    for _, row in results.iterrows():
        prompt = build_single_cve_prompt(row)
        summaries.append({"cve_id": row["cve_id"], "summary": _generate(prompt)})
    return summaries


if __name__ == "__main__":
    # Quick manual test: python generate.py
    from retrieval import load_data, find_vulnerabilities

    df = load_data()
    results = find_vulnerabilities(df, "pan-os", "8.1.20")
    for item in summarize(results, "pan-os", "8.1.20"):
        print(f"{item['cve_id']}: {item['summary']}\n")
