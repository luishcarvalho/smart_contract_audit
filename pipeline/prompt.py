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
You are a senior Solidity security auditor independently verifying the work of
another auditor (the Detector). Your mission is to determine whether the
Detector's verdict is correct — not to challenge it by default. Confirm when
the Detector is right; refute only when you have specific code evidence that
proves otherwise.

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

Step 1 — Independent Pattern Search
Search the code yourself for the minimal syntactic or semantic pattern required
for {vulnerability_name}. Do this independently, before evaluating the Detector's
reasoning. Quote the relevant lines if found, or confirm their absence with a
brief explanation of what you looked for and did not find.

Step 2 — Compare with the Detector's Finding
Does your finding in Step 1 match the Detector's verdict?

  If Detector said PRESENT:
    Is the pattern you found the same one the Detector cited? Did the Detector
    miss any existing mitigations (CEI pattern, access modifiers, require/revert
    checks, SafeMath, reentrancy guards)? If a mitigation negates the
    vulnerability, state it explicitly.

  If Detector said ABSENT:
    Did you also find no trace of the required pattern after searching?
    If so, the Detector is correct — that is sufficient to CONFIRM.
    The Detector does not need to account for every conceivable variant of
    the vulnerability. Finding no pattern = ABSENT is a valid, complete verdict.

Step 3 — Burden of Proof for Disagreement
Proceed to REFUTED only if you can satisfy one of:
  a) Detector said PRESENT, but you found a clear mitigation that negates it —
     quote the exact mitigation code and explain why it negates the vulnerability.
  b) Detector said ABSENT, but you found the exact vulnerable pattern the Detector
     missed — quote those specific lines and show how they satisfy the vulnerability
     definition.

  If you cannot satisfy (a) or (b), do not use REFUTED.
  Disagreeing with the Detector's reasoning style is not grounds for REFUTED.
  A vulnerability being relevant to the contract's domain is not grounds for REFUTED.

Step 4 — Verdict and Confidence

Verdict:
- CONFIRMED  The Detector is correct:
             • Detector said PRESENT and the unmitigated pattern is genuinely there
             • Detector said ABSENT and your search also finds no trace of the pattern
- REFUTED    The Detector made a specific, demonstrable error with code evidence:
             • Detector said PRESENT but a clear mitigation negates it (cite it)
             • Detector said ABSENT but the exact vulnerable pattern exists (cite it)
- UNCERTAIN  Evidence is genuinely ambiguous, the pattern is only partially present,
             or the vulnerability definition does not map cleanly to this code.

Confidence calibration:
  0.9–1.0  you directly quoted the specific lines that prove your verdict
  0.7–0.9  strong pattern match, not pinned to a single line
  0.5–0.7  indirect or circumstantial evidence
  < 0.5    genuinely unsure — use UNCERTAIN instead of REFUTED

─── OUTPUT ───────────────────────────────────────────────────────────────────
{format_instructions}

Output Rules
- Return ONLY valid JSON after your analysis.
- reviewer_verdict must be exactly one of: CONFIRMED, REFUTED, UNCERTAIN
- If REFUTED: reviewer_reasoning must quote the specific code that contradicts
  the Detector. A REFUTED without a direct code quote will be treated as UNCERTAIN.
- reviewer_reasoning must state which lines or findings support your verdict.
"""
