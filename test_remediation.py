"""
Quick test script: runs remediation generation on several different CVEs
and prints the output clearly, so you can eyeball whether flan-t5-large is
actually giving distinct, sensible, non-copied guidance per CVE -- not just
a formatting check, a QUALITY check.
 
Run with: python test_remediation.py
"""
 
from retrieval import load_data, find_vulnerabilities
from generate import suggest_remediation, summarize
 
# Test against a few different product/version combos from your dataset --
# edit these to match products you know exist in dataset_fixed.csv.
TEST_CASES = [
    ("pan-os", "8.1.20"),
    ("pan-os", "9.0.10"),
    ("pan-os", "10.2.0"),
]
 
 
def run_case(product: str, version: str):
    df = load_data()
    results = find_vulnerabilities(df, product, version)
 
    print(f"\n{'='*70}")
    print(f"  {product} {version}  ({len(results)} CVEs found)")
    print(f"{'='*70}")
 
    if results.empty:
        print("  No results -- try a different product/version from your CSV.")
        return
 
    remediations = suggest_remediation(results)
 
    for item in remediations:
        print(f"\n  {item['cve_id']}")
        print(f"  {'-'*50}")
        remediation_text = item["remediation"]
        if isinstance(remediation_text, list):
            for step in remediation_text:
                print(f"    - {step}")
        else:
            print(f"    {remediation_text}")
 
 
def check_for_repetition(all_outputs: list[str]) -> None:
    """Flags if multiple CVEs got near-identical remediation text --
    a sign the model is anchoring on the prompt/example instead of
    reasoning about each CVE individually."""
    print(f"\n{'='*70}")
    print("  REPETITION CHECK")
    print(f"{'='*70}")
    seen = {}
    for i, text in enumerate(all_outputs):
        normalized = text.strip().lower()[:80]  # compare first 80 chars
        if normalized in seen:
            print(f"  WARNING: output #{i} looks nearly identical to output #{seen[normalized]}")
            print(f"    -> {text[:100]}...")
        else:
            seen[normalized] = i
    if len(seen) == len(all_outputs):
        print("  OK -- all remediation outputs are distinct from each other.")
 
 
if __name__ == "__main__":
    df = load_data()
    all_remediation_texts = []
 
    for product, version in TEST_CASES:
        results = find_vulnerabilities(df, product, version)
        if results.empty:
            continue
        run_case(product, version)
 
        remediations = suggest_remediation(results)
        for item in remediations:
            text = item["remediation"]
            all_remediation_texts.append(" ".join(text) if isinstance(text, list) else str(text))
 
    if all_remediation_texts:
        check_for_repetition(all_remediation_texts)
 
    print(f"\n{'='*70}")
    print("  WHAT TO CHECK MANUALLY:")
    print(f"{'='*70}")
    print("""
  1. Does each CVE's remediation actually reference details specific to
     THAT CVE (its attack vector, privileges, product) -- not just generic
     boilerplate repeated everywhere?
  2. Is any output copying the vulnerability description verbatim instead
     of giving actions?
  3. Is any output cut off mid-sentence (hitting MAX_OUTPUT_TOKENS)?
  4. Does it look noticeably better than the flan-t5-base output you saw
     earlier? If not, it's not worth the extra download size/speed cost --
     fall back to the deterministic rule-based version instead.
""")