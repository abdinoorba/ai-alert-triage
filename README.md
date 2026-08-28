# ai-alert-triage

An AI-assisted SOC alert triage tool. It enriches a security alert, reasons about
whether it's a threat, and returns a **structured verdict for a human to verify** -
not an autonomous system that closes alerts on its own.

The design goal is a **glass box, not an autopilot**. The tool is explicitly
allowed to say *"indeterminate"* and to flag exactly what a human needs to check,
rather than guessing with false confidence. That human-in-the-loop honesty is the
whole point: the automation surfaces reasoning and evidence, and a person keeps the
judgment.

---

## The core idea: context changes the verdict

The hardest problem in real triage isn't catching obvious malware - it's **not
crying wolf** on legitimate activity that happens to look alarming. A tool that
flags every encoded PowerShell command is useless; the signal is drowned in noise.

Below is the *same alert* - an encoded, execution-policy-bypassing PowerShell
command run at 3 AM by a service account - run twice. The only thing that changes
between the two runs is the **environment context** supplied to the tool.

| | Without context | With context |
|---|---|---|
| **Verdict** | `suspicious` | `benign` |
| **Confidence** | 0.78 | 0.95 |
| **Needs human review?** | **Yes** | No |

**Without context**, the tool correctly hedges. It refuses to convict on surface
features alone, lands on *suspicious*, and its `unknowns` name precisely what it's
missing - *"Whether svc-backup is authorized to run scheduled tasks"*,
*"Maintenance windows for FS-02"*, *"Decoded content of the EncodedCommand."* It
does not guess.

**With context** (a documented 02:00-04:00 maintenance window, `svc-backup` as a
known account, an allowlisted nightly backup job), the verdict flips to *benign*.
The reasoning now re-reads the same scary features as routine:

> *"The use of ExecutionPolicy Bypass and encoding are defensive measures commonly
> employed in backup scripts to ensure execution reliability."*

The 3 AM timing that counted **against** the alert without context now counts **for**
it, because 3 AM falls inside the stated maintenance window. Same fact, opposite
meaning - resolved by context, exactly as a human analyst would.

Notably, even when it clears the alert, the tool keeps a few residual `unknowns`
(*"does the encoded command do only the claimed listing, or chain to other
operations?"*) rather than declaring a naive all-clear. Calibrated caution, not a
rubber stamp.

**This is the thesis of the project:** automated triage is only as good as the
context it's given, and the human supplies the context the machine lacks.

---

## Pipeline

```
input (JSON file  OR  raw text -> extract -> confirm)
  -> decode encoded commands -> enrich observables -> verify observables
  -> reason (LLM) -> verdict
```

1. **Input.** Either load a structured alert (JSON), or paste a raw log / free text
   and have the LLM **extract** it into the alert schema. Extracted alerts are shown
   to the analyst to confirm or edit before anything runs.
2. **Decode** any PowerShell `-EncodedCommand` blobs deterministically (base64 /
   UTF-16LE) and attach the real command to the alert, so the model reasons over
   verified content instead of a description of it.
3. **Enrich** the observables against threat intel: IP reputation via **AbuseIPDB**,
   and files (hashes), domains, and URLs via **VirusTotal** multi-engine detection.
4. **Verify** every observable actually appears, verbatim, in the raw text - a
   deterministic guard against the extraction layer hallucinating or altering an IOC.
5. **Reason** with an LLM that returns a structured verdict: classification,
   confidence, MITRE ATT&CK mapping, `unknowns`, `requires_human_verification`,
   and recommended actions.

Each stage is written against the alert **schema**, not against any specific file,
so new alerts and new enrichment sources drop in without touching downstream code.
The three VirusTotal observable types share one generic lookup function rather than
a separate copy per type.

---

## Run it

Works with **no API keys** out of the box (mock mode), so the full loop runs before
you sign up for anything.

```bash
pip install -r requirements.txt
python pipeline.py                                      # runs the default alert
python pipeline.py sample_alert_admin_nocontext.json    # benign-but-scary, hedged
python pipeline.py sample_alert_admin_withcontext.json  # same alert, cleared by context
python pipeline.py sample_alert_malware.json            # malicious file (EICAR test hash)
python pipeline.py --text "raw log line with an IP or hash..."  # extract from text, confirm, run
python pipeline.py --text                               # prompts you to paste text
```

Go live one key at a time by adding them to a `.env` file (copy `.env.example`):

- `ABUSEIPDB_API_KEY` - free tier at abuseipdb.com; turns on real IP reputation.
- `VIRUSTOTAL_API_KEY` - free tier at virustotal.com; turns on real file/domain/URL detection.
- `ANTHROPIC_API_KEY` - turns on real LLM reasoning, and the smart extraction layer.

To reproduce the before/after above, run the `nocontext` and `withcontext` alert
files back to back.

---

## Sample alerts

The included alerts span the full range of verdicts, each exercising a different
part of the pipeline:

- **`sample_alert_bruteforce.json`** - failed logins then success (IP reputation).
- **`sample_alert_admin_nocontext.json`** - encoded PowerShell scheduled task, no
  context (decode + hedged verdict).
- **`sample_alert_admin_withcontext.json`** - the same alert with environment
  context (verdict flips to benign).
- **`sample_alert_malware.json`** - a file executed from Downloads, flagged by most
  VirusTotal engines (hash enrichment + confident malicious verdict).

---

## From raw text to a structured alert (extraction layer)

Analysts don't work in clean JSON - they get raw log lines, copied alert blobs, and
plain-English descriptions. The `--text` mode takes any of that and turns it into a
structured alert, so nothing has to be hand-formatted.

The extraction layer is treated as **untrusted by design**, because an LLM reading
free text can misread or invent an observable - and a single wrong digit in an IP or
hash would send enrichment down the wrong path. Three safeguards address this:

1. **Deterministic verification.** After extraction, every observable it pulled out
   is checked to confirm it appears, character-for-character, in the original text.
   Anything that doesn't match is flagged before enrichment runs.
2. **Human confirmation.** The extracted alert is shown to the analyst to review,
   edit, save, or reject - a second human-in-the-loop checkpoint, this time at the
   *input* stage rather than the verdict stage.
3. **Offline fallback.** With no LLM key set, a regex-only extractor still pulls IPs,
   hashes, domains, and URLs, so the path runs (more crudely) with zero keys.

Example: pasting *"file executed from Downloads sha256=275a021b... on host WKS-2210"*
produces a structured alert with the hash and host correctly extracted and verified,
which then enriches (61/75 VirusTotal engines) into a high-confidence malicious verdict.

---

## A note on the alert schema

The alert format here is a **deliberately simplified internal schema**. Production
SIEMs use their own richer schemas - Microsoft Sentinel normalizes to **ASIM**,
Splunk to **CIM**, Elastic to **ECS** - and the industry is converging on the
vendor-neutral **OCSF** (Open Cybersecurity Schema Framework) standard. This tool
normalizes input into one clean internal shape so the enrichment and reasoning
stages have a stable contract to work against - the same problem OCSF solves at
industry scale.

---

## Verifying, not trusting: encoded command decoding

Encoded PowerShell commands are a favorite of both attackers (to hide intent) and
legitimate admin scripts (for reliability). A triage tool should never take a
*description* of what an encoded command does on faith - it should decode it.

Before reasoning, the pipeline deterministically decodes any `-EncodedCommand`
blob and shows the analyst the real command. For the benign example above, that
means the tool doesn't trust a note claiming the command is safe - it decodes it
to `$source="D:\Backups"; Get-ChildItem -Path $source` and reasons from that.

A recurring finding across test alerts: **the model's MITRE ATT&CK accuracy tracks
the quality of the evidence it's given.** With decisive input - a decoded benign
command, or a file flagged by 60+/75 VirusTotal engines - it maps techniques
precisely (or correctly maps none). On alerts with only ambiguous surface features,
it over-reaches. Verified evidence doesn't just change the verdict; it sharpens the
reasoning.

---

## Known limitations (and why they matter)

Being honest about where the tool is wrong is part of the design - an analyst's job
is to know when *not* to trust the output.

- **The LLM over-maps MITRE ATT&CK on weak evidence.** On alerts without decisive
  input, it can reach for techniques with only weak support (e.g. tagging a routine
  `-ExecutionPolicy Bypass` as *Impair Defenses*). MITRE mappings should be treated
  as suggestions for a human to confirm, not ground truth.
- **It sometimes returns deprecated ATT&CK IDs** (e.g. the retired `T1086` instead of
  the current `T1059.001`). Mappings should be validated against the current ATT&CK
  version.
- **The model summarizes even verified content.** It may paraphrase a decoded command
  (e.g. shortening `$source="D:\Backups"; Get-ChildItem -Path $source` to
  `Get-ChildItem -Path D:\Backups`), which is why the raw decoded string is always
  shown to the analyst as the source of truth.
- **Extraction currently verifies observables, not full command lines.** IPs, hashes,
  domains, and URLs are checked verbatim against the source text; a long
  `-EncodedCommand` blob pulled during extraction is not yet verified the same way.

These aren't reasons to distrust the tool; they're reasons the human-verification
layer exists.

---

## Roadmap

- [x] Deterministic base64 decode of `-EncodedCommand`, shown to the analyst (verify, don't trust the label)
- [x] Hash, domain, and URL enrichment (VirusTotal)
- [x] LLM extraction layer: paste a raw log or free text -> structured alert, with verification and analyst confirmation
- [ ] Extend verbatim verification to extracted command-line / encoded-command blobs
- [ ] Additional enrichment source (OTX) and multi-source cross-referencing on IPs
- [ ] React front end: paste text or edit an alert, confirm, and view the verdict in a UI
- [ ] Prompt tuning to reduce MITRE over-mapping and enforce current ATT&CK IDs
- [ ] More sample alerts, including additional benign-but-scary cases