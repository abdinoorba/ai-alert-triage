"""
Extraction layer.

Turns messy input (a raw log line, a pasted alert, free-text description) into the
tool's structured alert schema, so an analyst doesn't have to hand-write JSON.

IMPORTANT: an LLM extracting observables can hallucinate or alter them (a wrong
digit in an IP or hash is enough to send enrichment down the wrong path). So this
layer is treated as UNTRUSTED:
  1. The LLM structures the text into the schema.
  2. verify_extraction() deterministically confirms every observable it pulled out
     actually appears, character-for-character, in the original raw text.
  3. The analyst reviews/edits the structured alert before the pipeline runs.

Falls back to a naive regex-only extraction when no LLM key is set, so it still
produces something runnable offline.
"""

import os
import re
import json

MODEL = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")

# deterministic patterns used both for the offline fallback and for verification
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_RE = re.compile(r"https?://[^\s\"']+")

EXTRACTION_PROMPT = """You convert a raw security log or free-text description into a \
structured alert JSON. Return ONLY the JSON object, no prose, no markdown fences.

Use exactly this schema (use empty lists/strings where a field is unknown):
{
  "alert_id": "", "timestamp": "", "alert_name": "", "severity": "low|medium|high|critical",
  "source": "extracted", "description": "one-line summary you write",
  "entities": {
    "source_ips": [], "dest_ips": [], "domains": [], "urls": [],
    "file_hashes": [{"type": "sha256|sha1|md5", "value": ""}],
    "users": [], "hosts": [], "processes": [{"name": "", "command_line": ""}]
  },
  "raw_log": "the ORIGINAL input text, copied verbatim and unchanged",
  "environment_context": {"known_admins": [], "admin_hosts": [],
    "maintenance_windows": [], "allowlisted_tasks": [], "notes": ""}
}

CRITICAL: copy IPs, hashes, domains, and URLs EXACTLY as they appear in the input.
Never invent, correct, or complete an observable. If unsure, leave it out. Put the
untouched original text in raw_log."""


def _regex_extract(text):
    """Offline fallback: pull observables with regex only. Crude but safe."""
    hashes = ([{"type": "sha256", "value": h} for h in SHA256_RE.findall(text)]
              or [{"type": "sha1", "value": h} for h in SHA1_RE.findall(text)]
              or [{"type": "md5", "value": h} for h in MD5_RE.findall(text)])
    # domains: exclude ones that are just the tail of a URL already captured
    urls = URL_RE.findall(text)
    domains = [d for d in DOMAIN_RE.findall(text)
               if not any(d in u for u in urls) and not IP_RE.fullmatch(d)]
    # common log keywords that look like domains but aren't (word.word tokens)
    log_noise = {"auth.failure", "auth.success", "proc.create", "file.write", "net.conn"}
    clean_domains = sorted({d for d in domains
                            if d.lower() not in log_noise and "." in d
                            and not d.split(".")[-1].isdigit()})
    return {
        "alert_id": "", "timestamp": "", "alert_name": "Extracted alert",
        "severity": "medium", "source": "extracted (regex fallback)",
        "description": "Auto-extracted from raw text (no LLM key set).",
        "entities": {
            "source_ips": sorted(set(IP_RE.findall(text))), "dest_ips": [],
            "domains": clean_domains, "urls": urls,
            "file_hashes": hashes, "users": [], "hosts": [], "processes": [],
        },
        "raw_log": text,
        "environment_context": {"known_admins": [], "admin_hosts": [],
            "maintenance_windows": [], "allowlisted_tasks": [], "notes": ""},
    }


def extract_alert(text):
    """Turn raw text into a structured alert dict. Uses the LLM if a key is set,
    else a regex fallback. Always stores the original text in raw_log."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return _regex_extract(text)
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model=MODEL, max_tokens=1024, system=EXTRACTION_PROMPT,
            messages=[{"role": "user", "content": text}],
        )
        raw = msg.content[0].text.strip().replace("```json", "").replace("```", "").strip()
        alert = json.loads(raw)
        alert.setdefault("raw_log", text)
        # safety: force raw_log to the true original so verification is meaningful
        alert["raw_log"] = text
        return alert
    except Exception as e:
        print(f"[extract] LLM extraction failed ({e}); using regex fallback.")
        return _regex_extract(text)


def verify_extraction(alert):
    """Deterministic guard: confirm every extracted observable appears verbatim in
    raw_log. Returns a list of warnings (empty means clean)."""
    raw = alert.get("raw_log", "")
    warnings = []
    ents = alert.get("entities", {})
    checkset = []
    for key in ("source_ips", "dest_ips", "domains", "urls", "users", "hosts"):
        checkset += [(key, v) for v in ents.get(key, [])]
    checkset += [("file_hash", h.get("value", "")) for h in ents.get("file_hashes", [])]
    for kind, value in checkset:
        if value and value not in raw:
            warnings.append(f"{kind} '{value}' not found verbatim in raw text - possible extraction error")
    return warnings