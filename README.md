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
alert (JSON) -> decode encoded commands -> enrich observables -> verify observables -> reason (LLM) -> verdict
```

1. **Load** a structured alert.
2. **Decode** any PowerShell `-EncodedCommand` blobs deterministically (base64 /
   UTF-16LE) and attach the real command to the alert, so the model reasons over
   verified content instead of a description of it.
3. **Enrich** its observables against threat intel: IP reputation via **AbuseIPDB**,
   and files (hashes), domains, and URLs via **VirusTotal** multi-engine detection.
4. **Verify** every enriched observable actually appears, verbatim, in the raw log -
   a deterministic guard against a future extraction layer hallucinating or altering
   an IOC.
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
python pipeline.py                                  # runs the default alert
python pipeline.py sample_alert_admin_nocontext.json    # benign-but-scary, hedged
python pipeline.py sample_alert_admin_withcontext.json  # same alert, cleared by context
python pipeline.py sample_alert_malware.json            # malicious file (EICAR test hash)
```

Go live one key at a time by adding them to a `.env` file (copy `.env.example`):

- `ABUSEIPDB_API_KEY` - free tier at abuseipdb.com; turns on real IP reputation.
- `VIRUSTOTAL_API_KEY` - free tier at virustotal.com; turns on real file/domain/URL detection.
- `ANTHROPIC_API_KEY` - turns on real LLM reasoning instead of the mock verdict.

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
command, or a file flagged by 66/75 VirusTotal engines - it maps techniques
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

These aren't reasons to distrust the tool; they're reasons the human-verification
layer exists.

---

## Roadmap

- [x] Deterministic base64 decode of `-EncodedCommand`, shown to the analyst (verify, don't trust the label)
- [x] Hash, domain, and URL enrichment (VirusTotal)
- [ ] Additional enrichment source (OTX) and multi-source cross-referencing on IPs
- [ ] LLM extraction layer: paste a raw log or free text -> structured alert (verification guard already wired in)
- [ ] `environment_context` toggle exposed in a UI, to demo the verdict flip interactively
- [ ] React front end with an analyst review/confirm step before enrichment runs
- [ ] Prompt tuning to reduce MITRE over-mapping and enforce current ATT&CK IDs
- [ ] More sample alerts, including additional benign-but-scary cases
