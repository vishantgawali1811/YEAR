# AI Concepts and Design Decisions

## 1. Purpose of This Document

This document explains the artificial-intelligence, machine-learning, retrieval,
and decision-support concepts used in the CVE remediation system.

It covers:

- What the system does.
- Which parts use AI and which parts are deliberately deterministic.
- Why each technology was selected.
- Alternatives that were considered and why they were not selected.
- How the system prevents an LLM from inventing security fixes.
- The current limitations and possible future improvements.

The most important design principle is:

> Verified CVE and vendor facts decide the technical remediation. AI may
> explain those facts, but it must not invent or override them.

---

## 2. System Overview

The project is a local CVE lookup and remediation assistant. A user can ask
questions such as:

```text
is pan-os 8.1.20 vulnerable?
how do I fix pan-os 8.1.20?
what vulnerabilities affect android 12?
```

The high-level flow is:

```text
User query
    |
    v
Intent classification
    |
    v
Product and version extraction
    |
    v
Dataset retrieval
    |
    v
Risk scoring and ranking
    |
    +--> Lookup: optional plain-English summary
    |
    +--> Remediation: deterministic verified remediation
                              |
                              v
                     Optional Groq explanation
                              |
                              v
                     Validation and final response
```

Relevant implementation files:

- `parse_query.py` - extracts product and version.
- `intent.py` - identifies lookup, remediation, or statistics intent.
- `retrieval.py` - finds CVEs affecting the requested product and version.
- `risk_scoring.py` - calculates an explainable priority score.
- `generate.py` - creates summaries and remediation output.
- `agent.py` - orchestrates the complete flow.
- `app.py` - exposes the pipeline through FastAPI.
- `Dataset/dataset_fixed.csv` - local CVE source data.

---

## 3. What "AI" Means in This Project

The project combines three different types of logic:

### 3.1 Deterministic software logic

This is ordinary programmed logic with predictable results:

- Intent classification.
- Product and version extraction.
- CVE filtering.
- Affected-version comparison.
- Fixed-version branch selection.
- Risk scoring.
- Primary remediation generation.
- Validation of optional LLM output.

Deterministic logic is used for security-critical decisions because it is
repeatable, testable, explainable, and does not hallucinate.

### 3.2 Local language-model generation

The project can use `google/flan-t5-base` for optional plain-English summaries
of individual CVEs. This model rewrites already retrieved facts into a more
readable paragraph.

It is not the authority for:

- Whether a product is vulnerable.
- Which version fixes a CVE.
- Which component is affected.
- Which mitigation is vendor-supported.

### 3.3 Hosted LLM explanation

The project can optionally call Groq for a richer remediation explanation.
Groq is an explanation layer only. The deterministic remediation is generated
first and remains valid if Groq is unavailable or rejected by validation.

---

## 4. Retrieval-Augmented Generation (RAG)

### 4.1 What RAG means

Retrieval-Augmented Generation means that a system retrieves relevant facts
from a trusted data source before asking a language model to generate text.

In this project:

```text
Retrieval: Dataset/dataset_fixed.csv
Generation: Flan-T5 summary or Groq explanation
```

The retrieved CVE row supplies the factual context. The model is not expected
to remember or discover the vulnerability independently.

### 4.2 Why RAG is useful for CVEs

CVE information changes over time and is too specific to rely on a model's
general training memory. A model may know general security concepts but still
produce an incorrect fixed version or an unrelated mitigation.

Using the local dataset provides:

- Reproducible results.
- A source that can be inspected and versioned.
- Fast offline lookup.
- A clear separation between facts and wording.
- Less dependence on model memory.

### 4.3 This is a tabular RAG design

The system uses direct structured filtering rather than semantic vector
search. The dataset contains fields such as:

- `cve_id`
- `description`
- `cvss`
- `attack_vector`
- `privileges`
- `product`
- `version`
- `operator`
- `label`

This is appropriate because the main question is structured:

```text
Does product X at version Y satisfy this version rule?
```

The answer should be determined by version comparison, not by semantic
similarity.

---

## 5. Intent Classification

### 5.1 Current approach

`intent.py` uses deterministic keyword matching with regular expressions.
The current intents are:

- `remediation`
- `stats`
- `lookup`

Remediation is checked first. This is important because a remediation query
also contains a product and version, which could otherwise look like a normal
lookup.

Examples:

```text
how do I fix pan-os 8.1.20?       -> remediation
how do I remediate pan-os 9.0.10? -> remediation
what is vulnerable in android 12? -> lookup
how many critical CVEs exist?     -> stats
```

### 5.2 Why a rule-based classifier was selected

The intent vocabulary is small and the decision has only a few outcomes.
Rules provide:

- No model download.
- No inference latency.
- No API dependency.
- Easy debugging.
- Predictable routing.
- Simple test coverage.

Routing is infrastructure logic, so determinism is more valuable than
open-ended language understanding here.

### 5.3 Alternatives and why they were not selected

#### LLM intent classification

An LLM could classify more varied wording, but it introduces:

- Network or model availability requirements.
- Latency.
- Non-deterministic classifications.
- A risk that a malformed response selects the wrong pipeline.

It is unnecessary for the current small intent set.

#### Fine-tuned BERT classifier

A BERT classifier could learn intent labels from examples, but it would
require:

- A labeled training dataset.
- Training and evaluation.
- Model packaging and version management.
- More operational complexity than the problem requires.

#### Flan-T5 classification prompt

Flan-T5 can follow instructions, but using it for routing would make a
security-critical branch depend on generative behavior. It is therefore used
only for optional summaries.

---

## 6. Product and Version Extraction

### 6.1 Current approach

`parse_query.py` extracts:

1. A version using a regular expression such as `8.1.20`.
2. A product by matching the query against products that actually exist in the
   dataset.

The longest known product match is preferred. This supports names such as
`pan-os` and multi-word or underscore-separated product names.

### 6.2 Why structured extraction was selected

The expected entities have a constrained format:

- Product names come from the dataset.
- Versions follow numeric dot-separated patterns.

This makes regex and dataset matching more reliable than asking a general
language model to return JSON.

### 6.3 Alternatives and why they were not selected

#### Named-entity recognition

NER could identify products and versions in more varied language, but it would
need a suitable model and may identify products that are not in the dataset.
The current parser must map to a real dataset product.

#### LLM structured extraction

An LLM can extract fields, but it may:

- Normalize a version incorrectly.
- Invent a product spelling.
- Return invalid JSON.
- Require extra validation and retries.

The current constrained parser is faster and easier to verify.

---

## 7. CVE Retrieval and Version Semantics

### 7.1 Dataset-driven matching

`retrieval.py` loads the CSV with pandas and filters by product. It then parses
versions using `packaging.version.Version`.

Version operators are evaluated directly:

```text
<   query version is earlier than the threshold
<=  query version is earlier than or equal to the threshold
==  query version exactly equals the threshold
>   query version is later than the threshold
>=  query version is later than or equal to the threshold
```

### 7.2 Affected and fixed rows

The dataset can contain multiple rows for one CVE:

```text
<  8.1.24  -> affected boundary
== 8.1.24  -> fixed version
```

The system groups rows by CVE, selects the affected rule that matches the
installed version, and then finds the corresponding fixed rule. It does not
infer a fixed version from a description, CVSS score, attack vector, or
vulnerability keyword.

If a fixed version is not present, the output explicitly says that the exact
fixed version is unavailable in the dataset.

### 7.3 Android exact-version records

Some legacy Android records contain only exact `==` rows and no `<` affected
rows. A scoped fallback treats an exact matching row as affected only when the
CVE has no affected-range rows at all.

This preserves normal `<` and `==` semantics for products that use proper
affected/fixed branches.

### 7.4 Why direct structured retrieval was selected

Version matching is a mathematical comparison. Semantic search could retrieve
similar descriptions but cannot reliably answer whether `9.0.10 < 9.0.17`.

### 7.5 Alternatives and why they were not selected

#### Vector database retrieval

Useful for natural-language similarity, but unnecessary for exact product and
version matching. It could also return semantically similar but version-
incorrect CVEs.

#### External live CVE APIs

They could provide fresher data, but introduce:

- Internet dependency.
- Rate limits.
- API changes.
- Availability failures.
- Possible differences between sources.

The local dataset keeps the demo reproducible and works offline.

#### SQL database

SQL would be appropriate for a larger production dataset, but pandas is
sufficient for the current CSV-sized data and keeps the implementation simple.

---

## 8. Risk Scoring

### 8.1 Current formula

`risk_scoring.py` produces a score from 0 to 100:

```text
base score = CVSS * 10
             + 10 if the attack vector is network/remote
             + 10 if no privileges are required
             capped at 100
```

The score is then mapped to:

```text
85-100 -> Critical
65-84  -> High
40-64  -> Medium
0-39   -> Low
```

### 8.2 Why this approach was selected

The score is intentionally simple and explainable. A security analyst can
understand every point and reproduce the calculation.

It is a prioritization aid, not a replacement for a formal CVSS calculator or
a complete enterprise risk model.

### 8.3 Alternatives and why they were not selected

#### Full CVSS v3/v4 recalculation

This would be more standards-compliant but requires all CVSS vector
components and careful standards implementation. The dataset already provides
CVSS values, so recalculating them would add complexity without improving the
current workflow.

#### Machine-learning risk prediction

This would require historical remediation outcomes or incident data. The
project does not currently have a labeled dataset for that purpose.

#### Black-box LLM prioritization

An LLM may produce plausible priorities but would be difficult to audit and
could rank vulnerabilities inconsistently.

---

## 9. Flan-T5 Base

### 9.1 What Flan-T5 is

`google/flan-t5-base` is an instruction-tuned sequence-to-sequence language
model.

It has an:

- **Encoder** that reads and represents the input text.
- **Decoder** that generates output text token by token.

For this project, the input is a short prompt containing verified CVE facts,
and the output is a plain-English summary.

### 9.2 Encoder-decoder meaning

The encoder converts the input sequence into contextual internal
representations. The decoder uses those representations to generate a new
sequence.

This architecture is suitable for:

- Summarization.
- Rewriting.
- Translation.
- Instruction-following text generation.

It is different from an encoder-only model such as BERT, which is generally
better suited to classification or embedding tasks than free-form generation.

### 9.3 How it is used

The model is loaded lazily in `generate.py`. It is used only when
`VIGIL_USE_LLM_SUMMARIES` is enabled. Otherwise, the system uses a fast
template-based summary.

The prompt tells the model to:

- Rewrite one CVE at a time.
- Use only the supplied passage.
- Avoid adding facts.
- Produce a short paragraph.

### 9.4 Why Flan-T5 Base was selected

- It is smaller than large hosted models.
- It can run locally.
- It supports instruction-style prompts.
- It is suitable for short summaries.
- It avoids sending CVE text to an external service for the summary path.

### 9.5 Alternatives and why they were not selected

#### BERT

BERT is encoder-only and is excellent for classification, embeddings, and
similarity. It is not the natural choice for generating a new summary
paragraph.

#### Larger T5 or Llama-style local models

They may produce better prose, but need more memory, download time, and
inference resources. The project prioritizes a practical local demo.

#### Hosted summarization APIs

They add network cost, credentials, latency, privacy concerns, and a failure
mode for a feature that does not decide remediation.

#### No model at all

The current template fallback is deliberately available. A system that only
needs factual lookup can use it and avoid model startup entirely.

---

## 10. Deterministic CVE-Specific Remediation

### 10.1 Why remediation is not generated freely by an LLM

Generic security advice is often technically reasonable but wrong for a
specific product. For example, an XSS keyword should not automatically cause
the system to recommend CSP, input encoding, or application changes when the
actual administrator action is a PAN-OS upgrade.

The system therefore does not map vulnerability keywords to generic controls.

### 10.2 Remediation structure

Each remediation result contains:

```text
AFFECTED VERSION
VERIFIED CVE FACT
PRIMARY REMEDIATION
TEMPORARY MITIGATION
DEFENSE-IN-DEPTH
```

The primary remediation is selected in this order:

1. Dataset fixed version.
2. Dataset vendor remediation.
3. A clearly qualified vendor-supported release statement when the dataset
   contains no exact fixed version or vendor remediation.

The system never fabricates a version.

### 10.3 Same fix, different explanation

Two CVEs may correctly have the same primary upgrade target. That is not a
problem if the dataset says both are fixed by the same version.

The explanation remains CVE-specific because it includes the actual
description and affected facts for that CVE.

### 10.4 Why deterministic remediation was selected

- Security fixes must be reproducible.
- Fixed-version extraction can be tested exactly.
- A fallback must work without internet or API credentials.
- Administrators need to see the source fact behind a recommendation.
- Generic keyword rules create misleading advice.

### 10.5 Alternatives and why they were not selected

#### Pure LLM remediation

Rejected because it can invent fixed versions, mitigations, or unsupported
operational steps.

#### Generic vulnerability playbooks

Useful for defense-in-depth, but too broad to be the primary remediation for a
product-specific CVE.

#### External vendor advisory lookup at request time

Potentially valuable in production, but it requires network access, source
normalization, caching, and conflict handling. The current system uses only
facts present in its verified local source.

---

## 11. Groq Explanation Layer

### 11.1 Role of Groq

Groq is optional and is used to make deterministic remediation easier to
understand. It receives:

- Verified CVE facts.
- The deterministic remediation steps.
- Instructions not to invent unavailable data.

It does not decide the fixed version or replace the deterministic steps.

### 11.2 Reliability behavior

The system remains functional when:

- `GROQ_API_KEY` is missing.
- The Groq package is unavailable.
- The network is unavailable.
- The request times out.
- Groq returns an error.
- The response fails validation.

In every case, `remediation_detail` becomes `None` and the deterministic
remediation remains in the response.

### 11.3 Prompt grounding

The prompt explicitly tells Groq to:

- Use only verified facts.
- Explain why the remediation applies to this CVE.
- State when fixed versions or mitigations are unavailable.
- Avoid invented versions, dates, components, or controls.

### 11.4 Output validation

The generated detail is rejected when it:

- Mentions a version not present in the verified facts.
- Contradicts the verified product or component.
- Claims a vendor recommendation when none exists.
- Claims a vendor mitigation when none exists.
- Adds known unsupported generic actions such as firewall changes, input
  sanitization, rate limiting, session invalidation, or log monitoring.

This is not a perfect natural-language safety proof, but it is an important
defense against common contradictions.

### 11.5 Alternatives and why they were not selected

#### No explanation model

Most reliable, but less helpful for users who need context around the fix.

#### Local Flan-T5 for remediation detail

Possible, but the current model is primarily used for short summaries and
would still require strict validation. Groq provides a separate optional
explanation capability without making the core flow dependent on it.

#### Fully trusted hosted LLM

Rejected because no external model should be trusted to choose a security
fix without checking against source facts.

---

## 12. Agent Orchestration

`agent.py` is the coordinator. It:

1. Rejects blank input safely.
2. Classifies intent.
3. Parses product and version.
4. Reuses entities from the previous query for supported follow-ups.
5. Retrieves matching CVEs.
6. Ranks them.
7. Calls remediation generation for remediation intent.
8. Calls summary generation for other lookup-style intent.
9. Returns a Pydantic response.

This keeps the architecture modular. Each stage has one responsibility and
can be tested independently.

The agent does not use an autonomous planning loop. This is intentional:
security remediation should follow a controlled, inspectable pipeline rather
than unrestricted tool use.

---

## 13. API and Frontend Design

FastAPI exposes:

- `/lookup` for explicit product/version lookup.
- `/lookup-raw` for a faster lookup without summaries.
- `/query` for free-text queries with intent-aware remediation routing.
- `/agent-query` for the structured agent response.
- `/stats` for dataset statistics.

The React frontend calls the intent-aware endpoint for terminal-style natural
language commands. This prevents the frontend from displaying a summary flow
when the user actually requested remediation.

---

## 14. Security and Reliability Principles

The project follows these principles:

### Source authority

The dataset is authoritative for facts available to the system.

### Fail-safe fallback

Optional AI failure must not remove deterministic remediation.

### No fabricated facts

Missing fixed versions and mitigations are reported as unavailable.

### Explainability

The response includes the affected rule, verified CVE description, and
selected remediation.

### Offline operation

Retrieval, parsing, risk scoring, and deterministic remediation do not require
the internet.

### Controlled generation

LLMs rewrite or explain facts instead of deciding security policy.

---

## 15. Current Limitations

The current implementation has several known limits:

1. The CSV may not contain every vendor advisory field.
2. A CVE without a fixed row cannot receive an exact fixed version.
3. The branch pairing logic uses row proximity because the CSV does not have an
   explicit branch identifier.
4. Keyword intent classification does not understand every possible phrasing.
5. Groq validation uses explicit contradiction checks and cannot prove that
   every sentence is factually correct.
6. The risk score is a simplified prioritization score, not a full enterprise
   risk model.
7. The local dataset must be updated when new CVE information becomes
   available.

These limitations are preferable to silently inventing security information.

---

## 16. Testing Strategy

Important test cases include:

### Intent routing

```text
how do I fix pan-os 8.1.20?
how do I remediate pan-os 9.0.10?
what should I do to fix pan-os 9.0.10?
```

All must route to `remediation`.

### Fixed-version branch matching

Test CVEs with:

- One affected and one fixed row.
- Multiple affected/fixed branches.
- A fixed version different from the affected threshold.
- No fixed row.

### Exact-version legacy data

Android exact-version records must remain visible when the query matches the
exact dataset version.

### Failure fallback

Test with:

- No `GROQ_API_KEY`.
- Groq timeout or request failure.
- Invalid or contradictory generated detail.

The deterministic remediation must still be returned.

### Consistency

Two CVEs with the same verified fixed version may have the same upgrade
instruction. Their verified facts and explanations must remain tied to their
own CVE descriptions.

---

## 17. Summary of Technology Choices

| Concern | Current choice | Main reason |
|---|---|---|
| Intent routing | Regex and keyword rules | Fast, deterministic, explainable |
| Entity extraction | Regex plus dataset product matching | Structured input and no hallucination |
| Retrieval | Pandas over local CSV | Exact version semantics and offline operation |
| Version parsing | `packaging.version` | Correct comparable version objects |
| Risk scoring | Explainable CVSS-based formula | Easy to audit and test |
| Summary generation | Optional local Flan-T5 Base | Local instruction-following rewrite |
| Remediation | Deterministic dataset-driven rules | Security-critical and reproducible |
| Explanation | Optional Groq API | Better readability without authority |
| LLM safety | Facts-first prompt plus validation | Reject unsupported claims |
| API | FastAPI | Simple typed HTTP interface |
| Frontend | React and Vite | Interactive dashboard and terminal UI |

---

## 18. Final Design Principle

The system is not designed to be an autonomous security expert that guesses
what to do. It is designed to be a verified CVE assistant:

```text
retrieve facts
    -> compare versions
    -> select verified fixed version
    -> generate deterministic remediation
    -> optionally explain it with AI
    -> validate the explanation
```

That balance gives the project the usability of natural-language AI while
preserving the reliability and auditability required for vulnerability
remediation.

---

## 19. Defensive CVE Verification Flowchart

Each CVE should be investigated defensively. The goal is to confirm exposure,
collect evidence, apply the verified fix, and confirm that the system is no
longer affected. This flow intentionally avoids exploit or compromise
instructions.

```text
START
  |
  v
Identify the product and installed version
  |
  v
Compare the version with the verified CVE affected rule
  |
  +--> Not affected
  |       |
  |       v
  |   Record the result and continue monitoring
  |
  +--> Potentially affected
          |
          v
      Identify the affected component or feature
          |
          v
      Confirm safe exposure conditions and configuration
      without sending exploit payloads
          |
          v
      Collect evidence:
      version output, configuration, logs, asset owner,
      network exposure, and vendor advisory references
          |
          v
      Determine priority using CVSS, attack vector,
      privileges, and organizational context
          |
          v
      Is a verified fixed version available?
          |
          +--> Yes
          |      |
          |      v
          |  Schedule and apply the vendor-supported upgrade
          |
          +--> No
                 |
                 v
             Apply only a documented vendor mitigation,
             if one exists, and track the exception
          |
          v
      Validate the installed version and configuration
          |
          v
      Rescan or re-run the safe detection checks
          |
          v
      Record evidence that remediation is complete
          |
          v
        END
```

### Safe per-CVE text format

The defensive record for an individual CVE should use this structure:

```text
CVE ID:
PRODUCT:
INSTALLED VERSION:
VERIFIED AFFECTED RULE:
AFFECTED COMPONENT:
VERIFIED CVE FACT:
SAFE DETECTION CHECKS:
EVIDENCE TO COLLECT:
RISK / PRIORITY:
PRIMARY REMEDIATION:
TEMPORARY MITIGATION:
POST-REMEDIATION VALIDATION:
REMEDIATION STATUS:
```

`SAFE DETECTION CHECKS` should be limited to non-invasive checks such as
version comparison, configuration review, vendor-supported diagnostics, log
review, and authenticated asset inventory. It must not contain exploit
payloads, weaponized proof-of-concept code, or instructions to gain access to
systems.
