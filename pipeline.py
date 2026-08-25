"""
ai-alert-triage - Phase 1 pipeline.

Runs one alert through the full loop:
  Step 1: load the alert
  Step 2: enrich its observables (+ a deterministic verification guard)
  Step 3: reason about it  (LLM -> structured verdict)
  Step 4: output the verdict

Run:  python pipeline.py [path_to_alert.json]
      (defaults to sample_alert.json if no file is given)

Works with NO API keys (mock mode). Add keys in a .env file to get real results.
"""

import sys
import json
from dotenv import load_dotenv

load_dotenv()  # read .env into environment before anything reads a key

from enrich import enrich_alert
from reason import reason_about_alert


def load_alert(path="sample_alert_bruteforce.json"):
    """Step 1 - load a structured alert from disk."""
    with open(path) as f:
        return json.load(f)


def verify_observables(alert, enrichment):
    """Deterministic guard: confirm every enriched observable actually appears,
    character-for-character, in the raw log. This catches an extraction layer
    that hallucinated or altered an IOC. Safe to run even in Phase 1."""
    raw = alert.get("raw_log", "")
    for item in enrichment:
        obs = item.get("observable", "")
        if obs and raw and obs not in raw:
            item["verification_warning"] = (
                f"'{obs}' not found verbatim in raw_log - possible extraction error"
            )
    return enrichment


def main():
    # Step 1: load (use the filename passed on the command line, or the default)
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_alert_bruteforce.json"
    alert = load_alert(path)
    print(f"\n=== ALERT: {alert['alert_name']} ===")
    print(f"    (loaded from {path})")
    print(f"    {alert['description']}")

    # Step 2: enrich (+ verify)
    enrichment = enrich_alert(alert)
    enrichment = verify_observables(alert, enrichment)
    print("\n--- Enrichment ---")
    for item in enrichment:
        print(f"  {item['observable']}: {item['result']}")
        if item.get("verification_warning"):
            print(f"    WARNING: {item['verification_warning']}")

    # Step 3: reason
    verdict = reason_about_alert(alert, enrichment)

    # Step 4: output
    print("\n--- Verdict ---")
    print(json.dumps(verdict, indent=2))
    if verdict.get("mock"):
        print("\n(MOCK mode - set ANTHROPIC_API_KEY and ABUSEIPDB_API_KEY in .env "
              "for real results.)")


if __name__ == "__main__":
    main()