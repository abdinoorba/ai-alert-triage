"""
Deterministic decoding layer.

PowerShell's -EncodedCommand takes a base64 string of UTF-16LE text. Attackers
use it to hide what a command actually does; so do legitimate admin scripts. Either
way, the analyst should see the REAL command, not trust a label that claims what it
contains.

This module finds encoded PowerShell commands in an alert's processes and decodes
them. It's pure, deterministic Python - no LLM, no guessing - so the decoded text
is ground truth the reasoning layer can rely on.
"""

import re
import base64

# Matches PowerShell's -EncodedCommand and its accepted abbreviations
# (-e, -ec, -enc, -encodedcommand), case-insensitive, followed by the base64 blob.
ENC_FLAG_RE = re.compile(
    r"-(?:encodedcommand|enc|ec|e)\s+([A-Za-z0-9+/=]{8,})",
    re.IGNORECASE,
)


def decode_encoded_command(command_line):
    """Return the decoded PowerShell command from a command line, or None if there
    is no -EncodedCommand blob to decode."""
    if not command_line:
        return None
    match = ENC_FLAG_RE.search(command_line)
    if not match:
        return None

    b64 = match.group(1)
    try:
        raw = base64.b64decode(b64)
        # -EncodedCommand is UTF-16LE encoded
        decoded = raw.decode("utf-16-le", errors="replace")
        return {"encoded": b64, "decoded": decoded, "ok": True}
    except Exception as e:
        return {"encoded": b64, "decoded": None, "ok": False, "error": str(e)}


def decode_alert(alert):
    """Scan an alert's processes for encoded commands and attach the decoded text
    in-place. Returns a list of decode results for display."""
    results = []
    for proc in alert.get("entities", {}).get("processes", []):
        result = decode_encoded_command(proc.get("command_line", ""))
        if result:
            # attach to the process so the reasoning layer sees verified content
            proc["decoded_command"] = result["decoded"]
            results.append(
                {"process": proc.get("name", "?"), **result}
            )
    return results