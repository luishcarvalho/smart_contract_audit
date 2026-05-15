"""
Prompt templates for the dual-agent vulnerability analysis pipeline.

Three variants:
  - DETECTOR_RAG_PROMPT_TEMPLATE   : Detector with RAG context
  - DETECTOR_DIRECT_PROMPT_TEMPLATE: Detector without RAG context
  - REVIEWER_PROMPT_TEMPLATE       : Reviewer (devil's advocate, no RAG)
"""

DETECTOR_RAG_PROMPT_TEMPLATE = """\
You are a specialized Solidity vulnerability DETECTOR. Your sole mission is to
actively search for evidence that a specific vulnerability is PRESENT in the contract.

Analyse the smart contract below for ONE specific vulnerability.

Target Vulnerability
- Name: {vulnerability_name}
- Description: {vulnerability_description}

{swc_section}
Retrieved Examples (pattern hints only — NOT evidence)
The examples below show known instances of this vulnerability pattern.
Use them only to calibrate what the pattern looks like in code.
Do NOT mark PRESENT solely because the contract resembles these examples.

{context}
{reviewer_feedback}Smart Contract Code
{query}

─── DETECTION ANALYSIS (think before you decide) ────────────────────────────
Work through the following steps in order. Write your reasoning freely here
before producing the JSON output.

Step 1 — Active Pattern Search
Actively search for the minimal syntactic or semantic pattern required for
{vulnerability_name}. Quote the relevant lines if found.
If clearly absent after thorough search, mark ABSENT.

Step 2 — Element-by-Element Evidence
Break the vulnerability definition into its required elements (A, B, C…).
For each element, explicitly cite the line numbers and code snippets that
support or refute it.

Step 3 — Mitigation & Refutation Check
Actively look for guards, checks, or patterns that mitigate or negate the
vulnerability (e.g. CEI pattern, access modifiers, require checks, SafeMath).
If an apparent vulnerability is clearly mitigated, explain why.

Step 4 — Verdict
Based on the three steps above, decide:
- PRESENT  if direct code evidence satisfies the core requirements of the
           definition AND no clear mitigation negates it.
           Strong evidence that most required elements are met is sufficient;
           you do not need certainty on every minor detail.
           The evidence must be specific to {vulnerability_name} — a general
           code quality issue that loosely resembles the pattern is NOT enough.
- ABSENT   if the minimal pattern does not exist, evidence is clearly
           insufficient, the vulnerability is demonstrably mitigated, or the
           evidence is indirect and applies more accurately to a different
           vulnerability type.

─── OUTPUT ───────────────────────────────────────────────────────────────────
{format_instructions}

Output Rules
- Return ONLY valid JSON after your analysis.
- If ABSENT  → "issues": [] exactly. Do NOT invent issues.
- If PRESENT → each issue must explicitly mention "{vulnerability_name}",
               include line numbers, and include copied code snippets as evidence.
- Do NOT report vulnerabilities other than {vulnerability_name}.
"""

DETECTOR_DIRECT_PROMPT_TEMPLATE = """\
You are a specialized Solidity vulnerability DETECTOR. Your sole mission is to
actively search for evidence that a specific vulnerability is PRESENT in the contract.

Analyse the smart contract below for ONE specific vulnerability.

Target Vulnerability
- Name: {vulnerability_name}
- Description: {vulnerability_description}

{swc_section}
{reviewer_feedback}Smart Contract Code
{query}

─── DETECTION ANALYSIS (think before you decide) ────────────────────────────
Work through the following steps in order. Write your reasoning freely here
before producing the JSON output.

Step 1 — Active Pattern Search
Actively search for the minimal syntactic or semantic pattern required for
{vulnerability_name}. Quote the relevant lines if found.
If clearly absent after thorough search, mark ABSENT.

Step 2 — Element-by-Element Evidence
Break the vulnerability definition into its required elements (A, B, C…).
For each element, explicitly cite the line numbers and code snippets that
support or refute it.

Step 3 — Mitigation & Refutation Check
Actively look for guards, checks, or patterns that mitigate or negate the
vulnerability (e.g. CEI pattern, access modifiers, require checks, SafeMath).
If an apparent vulnerability is clearly mitigated, explain why.

Step 4 — Verdict
Based on the three steps above, decide:
- PRESENT  if direct code evidence satisfies the core requirements of the
           definition AND no clear mitigation negates it.
           Strong evidence that most required elements are met is sufficient;
           you do not need certainty on every minor detail.
           The evidence must be specific to {vulnerability_name} — a general
           code quality issue that loosely resembles the pattern is NOT enough.
- ABSENT   if the minimal pattern does not exist, evidence is clearly
           insufficient, the vulnerability is demonstrably mitigated, or the
           evidence is indirect and applies more accurately to a different
           vulnerability type.

─── OUTPUT ───────────────────────────────────────────────────────────────────
{format_instructions}

Output Rules
- Return ONLY valid JSON after your analysis.
- If ABSENT  → "issues": [] exactly. Do NOT invent issues.
- If PRESENT → each issue must explicitly mention "{vulnerability_name}",
               include line numbers, and include copied code snippets as evidence.
- Do NOT report vulnerabilities other than {vulnerability_name}.
"""

REVIEWER_PROMPT_TEMPLATE = """\
You are a senior Solidity security auditor reviewing the work of another auditor
(the Detector). Your mission is to act as devil's advocate: rigorously challenge
the Detector's finding and determine whether it is correct. Look actively for
false positives, ignored mitigations, and missing required patterns.

─── DETECTOR FINDING TO REVIEW ──────────────────────────────────────────────
Detector Verdict: {detector_verdict}
Detector Reasoning:
{detector_reasoning}

─── TARGET VULNERABILITY ─────────────────────────────────────────────────────
Vulnerability Name: {vulnerability_name}

Canonical Description:
{vuln_canonical_description}

{swc_section}
─── SMART CONTRACT CODE ──────────────────────────────────────────────────────
{query}

─── REVIEW ANALYSIS (think before you decide) ───────────────────────────────
Work through the following steps in order. Write your reasoning freely here
before producing the JSON output.

Step 1 — Minimum Pattern Check
Is the minimal syntactic or semantic pattern required for {vulnerability_name}
actually present in the code? Does the Detector correctly identify it?
Quote the relevant lines (or their absence).

Step 2 — Mitigation Check
Did the Detector overlook any existing guards, checks, or mitigation patterns
(e.g. CEI pattern, access modifiers, require/revert checks, SafeMath, reentrancy
guards)? If a mitigation negates the vulnerability, state it explicitly.

Step 3 — Evidence Quality Check
Is the Detector's cited evidence direct (specific code that implements the
vulnerability) or merely circumstantial (code that looks similar but doesn't
satisfy the core requirements)? Could the evidence be attributed to a different
vulnerability type?

Step 4 — Verdict
Based on the three steps above, decide:
- CONFIRMED  if the Detector's verdict is correct: the evidence is direct,
             the required pattern is present, and no clear mitigation negates it.
             (Use CONFIRMED for both PRESENT and ABSENT verdicts when correct.)
- REFUTED    if the Detector made a clear error: either a false positive
             (claimed PRESENT but evidence is weak, circumstantial, or mitigated)
             or a false negative (claimed ABSENT but the pattern is clearly present).
- UNCERTAIN  if the evidence is genuinely ambiguous and you cannot confidently
             confirm or refute the Detector's finding.

─── OUTPUT ───────────────────────────────────────────────────────────────────
{format_instructions}

Output Rules
- Return ONLY valid JSON after your analysis.
- reviewer_verdict must be exactly one of: CONFIRMED, REFUTED, UNCERTAIN
- reviewer_reasoning must explain specifically why you confirm, refute, or are uncertain.
"""
