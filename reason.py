"""
Reasoning layer.

Takes the alert plus the enrichment results, hands them to an LLM, and gets
back a STRUCTURED verdict (JSON with defined fields). If no API key is set, it
returns a deterministic mock verdict so the pipeline runs end to end.

The output fields are deliberately honest about uncertainty: verdict can be
"indeterminate", and `unknowns` / `requires_human_verification` let the tool
say "I can't decide this without context X" instead of guessing.
"""

import os
import json

# A small/cheap model is plenty here. Check https://docs.claude.com for current
# model names, or override with the ANTHROPIC_MODEL env var.
MODEL = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")

SYSTEM_PROMPT = """You are a SOC alert triage assistant. Given a security alert and \
the results of automated enrichment, classify it.

Return ONLY a JSON object (no markdown fences, no prose) with these fields:
- verdict: one of "benign", "suspicious", "malicious", "indeterminate"
- confidence: a number from 0.0 to 1.0
- reasoning: a short explanation that references specific evidence
- mitre_techniques: a list of {"id", "name"} objects, or []
- unknowns: things you could NOT determine from the data provided
- requires_human_verification: true or false
- verification_prompts: specific things a human analyst should check
- recommended_actions: a list of next steps

Be honest about uncertainty. If key context is missing (e.g. whether a user is \
an authorized admin, or whether a source IP is expected for them), put that in \
`unknowns`, set requires_human_verification to true, and prefer "indeterminate" \
over guessing."""


def reason_about_alert(alert, enrichment):
    """Send alert + enrichment to the LLM, return a structured verdict dict."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return _mock_verdict(alert, enrichment)

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)
        user_content = (
            f"ALERT:\n{json.dumps(alert, indent=2)}\n\n"
            f"ENRICHMENT RESULTS:\n{json.dumps(enrichment, indent=2)}"
        )
        msg = client.messages.create(
            model=MODEL,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )
        text = msg.content[0].text.strip()
        text = text.replace("```json", "").replace("```", "").strip()
        return json.loads(text)
    except Exception as e:
        print(f"[reason] LLM call failed ({e}); using mock verdict.")
        return _mock_verdict(alert, enrichment)


def _mock_verdict(alert, enrichment):
    """Deterministic placeholder so the pipeline runs with no API keys."""
    worst = 0
    for item in enrichment:
        worst = max(worst, item.get("abuse_score", 0) or 0)

    if worst >= 50:
        verdict = "malicious"
    elif worst > 0:
        verdict = "suspicious"
    else:
        verdict = "indeterminate"

    return {
        "verdict": verdict,
        "confidence": 0.4,
        "reasoning": "MOCK verdict (no ANTHROPIC_API_KEY). Based only on the max "
                     "abuse score from enrichment; no real reasoning performed.",
        "mitre_techniques": [{"id": "T1110", "name": "Brute Force"}],
        "unknowns": [
            "Whether the source IP is expected/normal for this user",
            "Whether the successful login was MFA-verified",
        ],
        "requires_human_verification": True,
        "verification_prompts": [
            "Confirm whether 45.83.140.2 is a known IP for jsmith",
            "Check whether the successful login passed MFA",
        ],
        "recommended_actions": ["Review recent auth history for jsmith"],
        "mock": True,
    }
