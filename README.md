# Security Tooling Test Target

> **This repository intentionally contains vulnerable code and dependencies
> on the `known-bad` branch for testing security scanners.**

[![Dependabot](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/awallgren/herd-test-target/main/badges/dependabot.json)](https://github.com/awallgren/herd-test-target/security/dependabot)
[![Code Scanning](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/awallgren/herd-test-target/main/badges/code-scanning.json)](https://github.com/awallgren/herd-test-target/security/code-scanning)

## Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Clean scaffolding — no vulnerable code, no scanner noise |
| `known-bad` | Layers intentionally vulnerable code and dependencies on top of `main` |

### `main`

Contains only repository infrastructure: README, badge workflows,
Dependabot config (GitHub Actions ecosystem only), and `.gitignore`.
No application code, no vulnerable dependencies, no test corpus.

### `known-bad`

Based on `main`. Adds:

- **Vulnerable applications** — Python (Flask) and Node.js (Express) apps
  with intentional SQL injection, command injection, XSS, path traversal,
  and prototype pollution
- **Vulnerable dependencies** — Pinned to known-vulnerable versions of
  Flask, requests, lodash, express, axios, etc.
- **AI ecosystem test corpus** (`ai-vulns/`) — Realistic samples covering
  prompt injection, overprivileged AI bots, insecure AI-generated code,
  training data poisoning, tool invocation abuse, hallucinated security
  guarantees, AI in CI/CD, typosquatted dependencies, context leakage,
  and supply chain intersection patterns
- **CodeQL workflow** — Configured to scan the `known-bad` branch

## Usage

To test a security scanner against this repo, scan the `known-bad` branch:

```bash
git clone https://github.com/awallgren/herd-test-target
cd herd-test-target
git checkout known-bad
# run your scanner here
```

Do not use any code from this repository in production.
