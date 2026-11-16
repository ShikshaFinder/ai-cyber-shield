# Security Policy & Acceptable Use

## Acceptable use

AI Cyber Shield is a tool for **authorized** security testing only. By using it you agree to test only:

- systems you own, or
- systems you have **explicit, written permission** to test (including bug bounty programs, within their
  published scope and rules).

Scanning or testing systems without authorization is illegal in most jurisdictions. The authors accept no
liability for misuse. The harness enforces an in-scope allowlist as a safeguard, but **you** remain
responsible for ensuring every target is authorized.

## Data and privacy

The browser extension captures traffic from pages you visit, which can include your own cookies, tokens and
other secrets. This data stays on your machine: the extension exports to local files, and the local harness
processes them in a container on your own computer. Nothing is sent to AI Cyber Shield servers. If you
configure a cloud AI provider (e.g. OpenAI), prompt content is sent to that provider under their terms.

## Reporting a vulnerability

Please report security issues in AI Cyber Shield privately via GitHub Security Advisories on this repository,
rather than opening a public issue. We aim to respond within a few days.
