"""
ai-alert-triage - pipeline.

Runs one alert through the full loop:
  Step 1: load the alert (from a JSON file, or extract it from raw text)
  Step 2: decode any encoded PowerShell commands (deterministic, verified)
  Step 3: enrich its observables (+ a deterministic verification guard)
  Step 4: reason about it  (LLM -> structured verdict)
  Step 5: output the verdict

Run:
  python pipeline.py [path_to_alert.json]      load a structured alert file
  python pipeline.py --text "raw log text..."  extract an alert from text, confirm, run
  python pipeline.py --text                     prompt to paste multi-line text

Works with NO API keys (mock mode). Add keys in a .env file to get real results.
"""

import sys
import json
from dotenv import load_dotenv

load_dotenv()  # read .env into environment before anything reads a key

from decode import decode_alert
from enrich import enrich_alert
from reason import reason_about_alert
from extract import extract_alert, verify_extraction


def load_alert(path="sample_alert_bruteforce.json"):
    """Step 1 - load a structured alert from disk."""
    with open(path) as f:
        return json.load(f)


def load_from_text(text):
    """Extract a structured alert from raw text, show it to the analyst, run a
    deterministic verification, and let them confirm / save / abort before the
    pipeline runs. Returns the alert dict, or None if aborted."""
    alert = extract_alert(text)

    # deterministic safety check: did the extractor invent or alter any observable?
    warnings = verify_extraction(alert)

    print("\n=== EXTRACTED ALERT (review before running) ===")
    print(json.dumps(alert, indent=2))
    if warnings:
        print("\n  EXTRACTION WARNINGS:")
        for w in warnings:
            print(f"    - {w}")
    else:
        print("\n  All observables verified against the raw text.")

    choice = input(
        "\nProceed with this alert? [y]es / [s]ave to file / [n]o: "
    ).strip().lower()
    if choice == "n":
        print("Aborted.")
        return None
    if choice == "s":
        fname = input("Filename to save (e.g. extracted_alert.json): ").strip()
        with open(fname, "w") as f:
            json.dump(alert, f, indent=2)
        print(f"Saved to {fname}")
    return alert


def verify_observables(alert, enrichment):
    """Deterministic guard: confirm every enriched observable actually appears,
    character-for-character, in the raw log. This catches an extraction layer
    that hallucinated or altered an IOC."""
    raw = alert.get("raw_log", "")
    for item in enrichment:
        obs = item.get("observable", "")
        if obs and raw and obs not in raw:
            item["verification_warning"] = (
                f"'{obs}' not found verbatim in raw_log - possible extraction error"
            )
    return enrichment


def main():
    # Step 1: get an alert - either extracted from raw text (--text) or loaded from a file
    if len(sys.argv) > 1 and sys.argv[1] == "--text":
        raw = " ".join(sys.argv[2:]) or input("Paste the raw log / alert text:\n")
        alert = load_from_text(raw)
        if alert is None:
            return
    else:
        path = sys.argv[1] if len(sys.argv) > 1 else "sample_alert_bruteforce.json"
        alert = load_alert(path)
        print(f"    (loaded from {path})")

    print(f"\n=== ALERT: {alert['alert_name']} ===")
    print(f"    {alert['description']}")

    # Step 2: decode any encoded PowerShell commands (deterministic, verified)
    decoded = decode_alert(alert)
    if decoded:
        print("\n--- Decoded commands ---")
        for d in decoded:
            if d["ok"]:
                print(f"  {d['process']}: {d['decoded']}")
            else:
                print(f"  {d['process']}: [decode failed: {d.get('error')}]")

    # Step 3: enrich (+ verify)
    enrichment = enrich_alert(alert)
    enrichment = verify_observables(alert, enrichment)
    print("\n--- Enrichment ---")
    for item in enrichment:
        print(f"  {item['observable']}: {item['result']}")
        if item.get("verification_warning"):
            print(f"    WARNING: {item['verification_warning']}")

    # Step 4: reason
    verdict = reason_about_alert(alert, enrichment)

    # Step 5: output
    print("\n--- Verdict ---")
    print(json.dumps(verdict, indent=2))
    if verdict.get("mock"):
        print("\n(MOCK mode - set ANTHROPIC_API_KEY and ABUSEIPDB_API_KEY in .env "
              "for real results.)")


if __name__ == "__main__":
    main()