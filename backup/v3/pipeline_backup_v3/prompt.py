"""
Prompt templates for the vulnerability analysis pipeline.

Two variants:
  - RAG_PROMPT_TEMPLATE   : includes a {context} section with retrieved examples
  - DIRECT_PROMPT_TEMPLATE: no retrieval context (direct LLM mode)

Both share identical instructions — only the RAG context block differs.
"""

RAG_PROMPT_TEMPLATE = """\
You are an expert Solidity security auditor specialising in vulnerability detection.

Analyse the smart contract below for ONE specific vulnerability.

Target Vulnerability
- Name: {vulnerability_name}
- Description: {vulnerability_description}

Retrieved Examples (pattern hints only — NOT evidence)
The examples below show known instances of this vulnerability pattern.
Use them only to calibrate what the pattern looks like in code.
Do NOT mark PRESENT solely because the contract resembles these examples.

{context}

Smart Contract Code
{query}

─── ANALYSIS (think before you decide) ──────────────────────────────────────
Work through the following steps in order. Write your reasoning freely here
before producing the JSON output.

Step 1 — Minimum Pattern Check
Does the minimal syntactic or semantic pattern required for {vulnerability_name}
exist in this contract? Quote the relevant lines if yes. If clearly absent, stop.

Step 2 — Element-by-Element Evidence
Break the vulnerability definition into its required elements (A, B, C…).
For each element, explicitly cite the line numbers and code snippets that
support or refute it.

Step 3 — Mitigation & Refutation Check
Actively look for guards, checks, or patterns that mitigate or negate the
vulnerability (e.g. CEI pattern, access modifiers, require checks, SafeMath).
If an apparent vulnerability is clearly mitigated, explain why.

Step 4 — Verdict
Note: most contracts do NOT contain this vulnerability. Only flag PRESENT
if the evidence is unambiguous and specific.

Based on the three steps above, decide:
- PRESENT  if ALL core elements of the vulnerability definition are met
           by direct, unambiguous code evidence AND no clear mitigation
           exists. Partial, indirect, or circumstantial evidence is NOT
           sufficient. The evidence must be specific to {vulnerability_name}
           — a general code quality issue that loosely resembles the pattern
           is NOT enough.
- ABSENT   in all other cases: when the minimal pattern is missing, evidence
           is insufficient or only partial, the vulnerability is mitigated, or
           you are uncertain. When in doubt, choose ABSENT.

─── OUTPUT ───────────────────────────────────────────────────────────────────
{format_instructions}

Output Rules
- Return ONLY valid JSON after your analysis.
- Include a "confidence" field (0.0–1.0): your certainty that the vulnerability
  is PRESENT. Use 0.0 when clearly ABSENT, 0.5 when uncertain, ≥0.7 only when
  ALL required elements are met with strong, direct evidence.
- If ABSENT  → "issues": [] exactly. Do NOT invent issues.
- If PRESENT → each issue must explicitly mention "{vulnerability_name}",
               include line numbers, and include copied code snippets as evidence.
- Do NOT report vulnerabilities other than {vulnerability_name}.
"""

DIRECT_PROMPT_TEMPLATE = """\
You are an expert Solidity security auditor specialising in vulnerability detection.

Analyse the smart contract below for ONE specific vulnerability.

Target Vulnerability
- Name: {vulnerability_name}
- Description: {vulnerability_description}

Smart Contract Code
{query}

─── ANALYSIS (think before you decide) ──────────────────────────────────────
Work through the following steps in order. Write your reasoning freely here
before producing the JSON output.

Step 1 — Minimum Pattern Check
Does the minimal syntactic or semantic pattern required for {vulnerability_name}
exist in this contract? Quote the relevant lines if yes. If clearly absent, stop.

Step 2 — Element-by-Element Evidence
Break the vulnerability definition into its required elements (A, B, C…).
For each element, explicitly cite the line numbers and code snippets that
support or refute it.

Step 3 — Mitigation & Refutation Check
Actively look for guards, checks, or patterns that mitigate or negate the
vulnerability (e.g. CEI pattern, access modifiers, require checks, SafeMath).
If an apparent vulnerability is clearly mitigated, explain why.

Step 4 — Verdict
Note: most contracts do NOT contain this vulnerability. Only flag PRESENT
if the evidence is unambiguous and specific.

Based on the three steps above, decide:
- PRESENT  if ALL core elements of the vulnerability definition are met
           by direct, unambiguous code evidence AND no clear mitigation
           exists. Partial, indirect, or circumstantial evidence is NOT
           sufficient. The evidence must be specific to {vulnerability_name}
           — a general code quality issue that loosely resembles the pattern
           is NOT enough.
- ABSENT   in all other cases: when the minimal pattern is missing, evidence
           is insufficient or only partial, the vulnerability is mitigated, or
           you are uncertain. When in doubt, choose ABSENT.

─── OUTPUT ───────────────────────────────────────────────────────────────────
{format_instructions}

Output Rules
- Return ONLY valid JSON after your analysis.
- Include a "confidence" field (0.0–1.0): your certainty that the vulnerability
  is PRESENT. Use 0.0 when clearly ABSENT, 0.5 when uncertain, ≥0.7 only when
  ALL required elements are met with strong, direct evidence.
- If ABSENT  → "issues": [] exactly. Do NOT invent issues.
- If PRESENT → each issue must explicitly mention "{vulnerability_name}",
               include line numbers, and include copied code snippets as evidence.
- Do NOT report vulnerabilities other than {vulnerability_name}.
"""
