# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ |

## Reporting a Vulnerability

**Please do NOT open a public issue for security problems.**

Instead, report privately via GitHub's
[Security Advisory](../../security/advisories/new) feature.

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigation

You will receive a response within **72 hours**.

## Scope

CleanIP runs on `127.0.0.1` only and makes no outbound calls except to
Cloudflare's public APIs. We still appreciate reports on:

- Local privilege escalation
- Arbitrary file read/write
- Command injection via config strings
- XSS in the web UI
- Denial of service via crafted configs

## Out of Scope

- Vulnerabilities in third-party components (Xray, Go runtime)
- Issues requiring an already-compromised local machine
- Social engineering

## Preferred Languages

English, Persian (فارسی)

---

**Maintainer:** Meysam Khademshams ([@khademdev](https://github.com/khademdev))
