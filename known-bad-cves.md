# CVEs in the `known-bad` Branch

This document catalogs all known CVEs present in the `known-bad` branch of
herd-test-target. It maps each CVE to the specific dependency manifest file(s)
that trigger it. This serves as a test fixture for validating winnow scan output.

Generated from GitHub Advisory Database on 2026-03-03.

## CVE Table

| CVE-ID | Package | Ecosystem | Severity | Summary | File(s) |
|--------|---------|-----------|----------|---------|---------|
| CVE-2021-44906 | minimist | npm | CRITICAL | Prototype Pollution in minimist | `package.json` |
| CVE-2021-23337 | lodash | npm | HIGH | Command Injection in lodash | `package.json` |
| CVE-2021-3749 | axios | npm | HIGH | Inefficient Regular Expression Complexity (ReDoS) | `package.json` |
| CVE-2025-27152 | axios | npm | HIGH | SSRF and Credential Leakage via Absolute URL | `package.json`, `ai-vulns/api-server/package.json` |
| CVE-2026-25639 | axios | npm | HIGH | Denial of Service via `__proto__` key in mergeConfig | `package.json`, `ai-vulns/api-server/package.json` |
| CVE-2025-58754 | axios | npm | HIGH | DoS attack through lack of data size check | `ai-vulns/api-server/package.json` |
| CVE-2024-39338 | axios | npm | HIGH | Server-Side Request Forgery (SSRF) | `ai-vulns/api-server/package.json` |
| CVE-2022-0235 | node-fetch | npm | HIGH | Forwards secure headers to untrusted sites on redirect | `package.json` |
| CVE-2019-19771 | lodahs | npm | HIGH | lodahs is malware (typosquat of lodash) | `ai-vulns/api-server/package.json` |
| CVE-2017-16074 | crossenv | npm | HIGH | crossenv is malware (typosquat of cross-env) | `ai-vulns/api-server/package.json` |
| CVE-2025-13465 | lodash | npm | MODERATE | Prototype Pollution in `_.unset` and `_.omit` | `package.json` |
| CVE-2020-28500 | lodash | npm | MODERATE | Regular Expression Denial of Service (ReDoS) | `package.json` |
| CVE-2024-29041 | express | npm | MODERATE | Open Redirect in malformed URLs | `package.json`, `ai-vulns/api-server/package.json` |
| CVE-2023-45857 | axios | npm | MODERATE | Cross-Site Request Forgery (XSRF-TOKEN exposure) | `package.json` |
| CVE-2024-43796 | express | npm | LOW | XSS via `response.redirect()` | `package.json`, `ai-vulns/api-server/package.json` |
| CVE-2023-30861 | Flask | pip | HIGH | Disclosure of permanent session cookie due to missing `Vary: Cookie` header | `requirements.txt` |
| CVE-2023-37920 | certifi | pip | HIGH | Removal of e-Tugra root certificate | `requirements.txt` |
| CVE-2023-43804 | urllib3 | pip | HIGH | `Cookie` HTTP header not stripped on cross-origin redirects | `requirements.txt` |
| CVE-2025-66418 | urllib3 | pip | HIGH | Unbounded number of links in decompression chain | `requirements.txt` |
| CVE-2025-66471 | urllib3 | pip | HIGH | Streaming API improperly handles highly compressed data | `requirements.txt` |
| CVE-2026-21441 | urllib3 | pip | HIGH | Decompression-bomb safeguards bypassed when following HTTP redirects | `requirements.txt` |
| CVE-2022-23491 | certifi | pip | MODERATE | Removal of TrustCor root certificate | `requirements.txt` |
| CVE-2023-32681 | requests | pip | MODERATE | Unintended leak of Proxy-Authorization header | `requirements.txt` |
| CVE-2024-35195 | requests | pip | MODERATE | `Session` object does not verify requests after first request with `verify=False` | `requirements.txt`, `ai-vulns/ml-project/requirements.txt` |
| CVE-2024-47081 | requests | pip | MODERATE | `.netrc` credentials leak via malicious URLs | `requirements.txt`, `ai-vulns/ml-project/requirements.txt` |
| CVE-2024-22195 | Jinja2 | pip | MODERATE | XSS via keys passed to `xmlattr` filter | `requirements.txt` |
| CVE-2024-34064 | Jinja2 | pip | MODERATE | HTML attribute injection via `xmlattr` filter | `requirements.txt` |
| CVE-2024-56201 | Jinja2 | pip | MODERATE | Sandbox breakout through malicious filenames | `requirements.txt` |
| CVE-2024-56326 | Jinja2 | pip | MODERATE | Sandbox breakout via indirect reference to format method | `requirements.txt` |
| CVE-2025-27516 | Jinja2 | pip | MODERATE | Sandbox breakout through `attr` filter selecting format method | `requirements.txt` |
| CVE-2024-37891 | urllib3 | pip | MODERATE | `Proxy-Authorization` header not stripped during cross-origin redirects | `requirements.txt` |
| CVE-2023-45803 | urllib3 | pip | MODERATE | Request body not stripped after redirect from 303 status | `requirements.txt` |
| CVE-2025-50181 | urllib3 | pip | MODERATE | Redirects not disabled when retries are disabled on PoolManager | `requirements.txt` |
| CVE-2026-27205 | Flask | pip | LOW | Session does not add `Vary: Cookie` header when accessed in some ways | `requirements.txt`, `ai-vulns/ml-project/requirements.txt` |
| CVE-2024-39689 | certifi | pip | LOW | Removal of GLOBALTRUST root certificate | `requirements.txt` |

## File-to-CVE Mapping

### `package.json`

Declares: `lodash@4.17.20`, `minimist@1.2.5`, `express@4.17.1`, `axios@0.21.1`, `node-fetch@2.6.1`

| CVE-ID | Package | Severity |
|--------|---------|----------|
| CVE-2021-44906 | minimist@1.2.5 | CRITICAL |
| CVE-2021-23337 | lodash@4.17.20 | HIGH |
| CVE-2021-3749 | axios@0.21.1 | HIGH |
| CVE-2025-27152 | axios@0.21.1 | HIGH |
| CVE-2026-25639 | axios@0.21.1 | HIGH |
| CVE-2022-0235 | node-fetch@2.6.1 | HIGH |
| CVE-2025-13465 | lodash@4.17.20 | MODERATE |
| CVE-2020-28500 | lodash@4.17.20 | MODERATE |
| CVE-2024-29041 | express@4.17.1 | MODERATE |
| CVE-2023-45857 | axios@0.21.1 | MODERATE |
| CVE-2024-43796 | express@4.17.1 | LOW |

### `requirements.txt`

Declares: `Flask==2.0.1`, `requests==2.25.1`, `Jinja2==3.0.1`, `urllib3==1.26.5`, `certifi==2021.5.30`

| CVE-ID | Package | Severity |
|--------|---------|----------|
| CVE-2023-30861 | Flask==2.0.1 | HIGH |
| CVE-2023-37920 | certifi==2021.5.30 | HIGH |
| CVE-2023-43804 | urllib3==1.26.5 | HIGH |
| CVE-2025-66418 | urllib3==1.26.5 | HIGH |
| CVE-2025-66471 | urllib3==1.26.5 | HIGH |
| CVE-2026-21441 | urllib3==1.26.5 | HIGH |
| CVE-2022-23491 | certifi==2021.5.30 | MODERATE |
| CVE-2023-32681 | requests==2.25.1 | MODERATE |
| CVE-2024-35195 | requests==2.25.1 | MODERATE |
| CVE-2024-47081 | requests==2.25.1 | MODERATE |
| CVE-2024-22195 | Jinja2==3.0.1 | MODERATE |
| CVE-2024-34064 | Jinja2==3.0.1 | MODERATE |
| CVE-2024-56201 | Jinja2==3.0.1 | MODERATE |
| CVE-2024-56326 | Jinja2==3.0.1 | MODERATE |
| CVE-2025-27516 | Jinja2==3.0.1 | MODERATE |
| CVE-2024-37891 | urllib3==1.26.5 | MODERATE |
| CVE-2023-45803 | urllib3==1.26.5 | MODERATE |
| CVE-2025-50181 | urllib3==1.26.5 | MODERATE |
| CVE-2026-27205 | Flask==2.0.1 | LOW |
| CVE-2024-39689 | certifi==2021.5.30 | LOW |

### `ai-vulns/api-server/package.json`

Declares: `express@^4.18.0`, `axios@^1.6.0`, `lodahs@^4.17.21` (malware),
`crossenv@^7.0.0` (malware), and other typosquatted/hallucinated packages.

| CVE-ID | Package | Severity |
|--------|---------|----------|
| CVE-2019-19771 | lodahs@^4.17.21 | HIGH |
| CVE-2017-16074 | crossenv@^7.0.0 | HIGH |
| CVE-2025-27152 | axios@^1.6.0 | HIGH |
| CVE-2025-58754 | axios@^1.6.0 | HIGH |
| CVE-2026-25639 | axios@^1.6.0 | HIGH |
| CVE-2024-39338 | axios@^1.6.0 | HIGH |
| CVE-2024-29041 | express@^4.18.0 | MODERATE |
| CVE-2024-43796 | express@^4.18.0 | LOW |

### `ai-vulns/ml-project/requirements.txt`

Declares: `Flask==3.0.0`, `requests==2.31.0`, `tensorflow==2.15.0`, `numpy==1.26.0`,
plus typosquatted/hallucinated packages (no CVEs in advisory databases).

| CVE-ID | Package | Severity |
|--------|---------|----------|
| CVE-2024-35195 | requests==2.31.0 | MODERATE |
| CVE-2024-47081 | requests==2.31.0 | MODERATE |
| CVE-2026-27205 | Flask==3.0.0 | LOW |

## Notes

- **Malware packages**: `lodahs` and `crossenv` in `ai-vulns/api-server/package.json`
  are known malware typosquats. These packages have been unpublished from npm but
  their presence in a manifest is itself a security finding.

- **Typosquatted/hallucinated packages without CVEs**: The `ai-vulns/` manifests
  contain additional suspicious packages (e.g., `types-node`, `node-crypto-utils`,
  `python3-dateutil`, `colourama`, `jeIlyfish`, etc.) that have no entries in the
  GitHub Advisory Database but represent supply chain risks. These are not listed
  in the CVE table since they lack formal CVE assignments.

- **Caret version ranges**: Packages in `ai-vulns/api-server/package.json` use
  caret (`^`) version ranges. CVE applicability is determined by the minimum
  version in the range (e.g., `^4.18.0` is evaluated as `4.18.0`).

- **Code-level vulnerabilities**: Files such as `app.py`, `index.js`, and the
  `ai-vulns/*.py`/`ai-vulns/*.js` files contain intentional code-level security
  issues (command injection, SQL injection, XSS, etc.) that correspond to CWEs
  rather than CVEs. These are not included in this document.

- **`ai-vulns/poisoned-package/setup.py`**: Contains a malicious post-install
  hook that exfiltrates environment variables. This is a code-level supply chain
  attack pattern, not a CVE-tracked vulnerability.
