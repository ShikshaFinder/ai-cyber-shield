# AI Cyber Shield workspace

This is the AI Cyber Shield local harness: a Kali Linux container with security tooling, used for
**authorized** web application security testing and bug bounty work. It is the self-hosted, open-source
counterpart of the AI Cyber Shield browser extension.

## Authorization is mandatory

Only assess targets the operator is explicitly authorized to test (their own systems, or a program whose
scope permits it). Every scan job carries an explicit `scope`. A scope guard enforces this at the network
layer; do not attempt to bypass it. Third-party hosts observed in a capture (CDNs, analytics, identity
providers, cloud storage) are out of scope unless they appear in the job's `scope`.

## Layout

- `data/captures/<id>/` — traffic exported by the browser extension. Begin with `*_summary.txt`, then the
  categorized files (critical APIs, authentication, query parameters, security headers, cookies, endpoints).
  `*_complete_raw.json` can be very large — query it with `jq`, never print it whole.
- `data/scans/<scan-id>.json` — the job: `mode`, `scope`, `captureId`, `notes`.
- `data/scope.txt` — scope for sessions started by hand in the OpenCode UI (one host, `*.domain`, IP or CIDR per line).
- `data/reports/` — where reports are written.

## Operating modes

- `passive` — analyze the capture files only. No network tools of any kind.
- `active` — low-impact, authorized testing against in-scope hosts is permitted.

## Constraints (both modes)

1. Stay within scope. In-scope hosts only, every time.
2. Be low-impact and non-destructive: rate-limit requests, avoid anything that could degrade availability,
   and never perform state-changing or account-altering actions. Read-only verification only.
3. Captures hold the operator's own cookies and tokens. Use them only against in-scope hosts, and never write
   them into reports in full — truncate to the first few characters.
4. Evidence over guesses. Mark a finding `confirmed` only when reproduced; otherwise `needs-verification`
   with a note on what to check. Never invent findings.

## Tooling

Standard Kali web-assessment tools are installed (nmap, nuclei, httpx, whatweb, sslscan, testssl.sh,
nikto, ffuf, gobuster, dirb, sqlmap, arjun, dalfox, subfinder, wafw00f, curl, wget, jq, dig, whois).
Use them non-interactively with conservative settings. Save raw output under `data/reports/<scan-id>/raw/`.
