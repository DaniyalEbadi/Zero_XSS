# XSStrike — Complete Command Reference

## Basic Usage

```
py xsstrike.py -u <URL>
```

Scans a URL for XSS vulnerabilities. The URL must include at least one parameter (e.g., `?q=test`).

---

## Target Options

| Flag | Description |
|------|-------------|
| `-u, --url <URL>` | Target URL to scan (required unless using `--seeds`) |
| `--data <DATA>` | POST data as a query string (e.g., `user=admin&pass=123`) |
| `--path` | Treat each URL path segment as a parameter for injection |

**Examples:**
```
py xsstrike.py -u "http://test.site/page.php?id=1"
py xsstrike.py -u "http://test.site/api" --data "username=admin&password=123"
py xsstrike.py -u "http://test.site/page/param1/param2" --path
```

---

## Encoding Options

| Flag | Description |
|------|-------------|
| `-e, --encode <TYPE>` | Encode payloads using the specified encoder |

**Available encoders:**

| Encoder | Description | Example Output |
|---------|-------------|----------------|
| `base64` | Standard Base64 encoding | `YWxlcnQoMSk=` |
| `double-url` | Double URL-encode each character | `%2561%256c%2572%2574` |
| `unicode` | Unicode `\uXXXX` escapes | `\u0061\u006c\u0065\u0072\u0074` |
| `hex` | Hex `\xXX` escapes | `\x61\x6c\x65\x72\x74` |
| `decimal-entities` | Decimal HTML entities | `&#97;&#108;&#101;&#114;&#116;` |
| `hex-entities` | Hex HTML entities | `&#x61;&#x6c;&#x65;&#x72;&#x74;` |
| `mixed` | Random mix of all encodings per character | `\x61%256c&#101;\u0072&#116;` |

**Example:**
```
py xsstrike.py -u "http://test.site/?q=test" -e unicode
```

---

## Scan Modes

### Standard Scan (default)

```
py xsstrike.py -u <URL>
```

Tests each parameter for reflected XSS using context-aware payload generation.

### Crawl Mode

| Flag | Description |
|------|-------------|
| `--crawl` | Crawl the target to discover forms and test them |
| `-l, --level <N>` | Crawling depth (default: 2) |
| `--seeds <FILE>` | Load seed URLs from a file for crawling |
| `--blind` | Inject blind XSS payload while crawling |

**Examples:**
```
py xsstrike.py -u "http://test.site" --crawl
py xsstrike.py -u "http://test.site" --crawl -l 3
py xsstrike.py --seeds urls.txt
py xsstrike.py -u "http://test.site" --crawl --blind
```

### Fuzzer Mode

| Flag | Description |
|------|-------------|
| `--fuzzer` | Test WAF behavior with fuzz strings |

```
py xsstrike.py -u "http://test.site/?q=test" --fuzzer
```

Tests what characters/patterns the WAF blocks, passes, or filters.

### Bruteforce Mode

| Flag | Description |
|------|-------------|
| `-f, --file <FILE>` | Load payloads from a file and test them |
| `-f default` | Use the built-in default payload list |

```
py xsstrike.py -u "http://test.site/?q=test" -f my_payloads.txt
py xsstrike.py -u "http://test.site/?q=test" -f default
```

---

## Advanced Analysis Flags

| Flag | Description |
|------|-------------|
| `--csp` | Parse and analyze Content Security Policy headers for bypass opportunities |
| `--mxss` | Detect Mutation XSS patterns in the page |
| `--dom-clobber` | Detect DOM clobbering gadgets |
| `--polyglot` | Include polyglot payloads that work across multiple injection contexts |
| `--discover-params` | Brute-force common parameter names (150+) to find hidden parameters |

**Examples:**
```
py xsstrike.py -u "http://test.site/?q=test" --csp
py xsstrike.py -u "http://test.site/?q=test" --mxss --dom-clobber
py xsstrike.py -u "http://test.site/?q=test" --polyglot
py xsstrike.py -u "http://test.site/" --discover-params --skip
```

**CSP Analyzer (`--csp`) checks for:**
- `unsafe-inline` — allows inline scripts
- `unsafe-eval` — allows `eval()` and similar
- CDN whitelist bypasses (Cloudflare, Google, jsDelivr, etc.)
- Missing `base-uri` — allows base tag injection
- Missing `object-src` — allows plugin execution
- Report-only mode — CSP is not enforced

**Mutation XSS (`--mxss`) detects:**
- Hidden/overflowed elements that can mutate on re-parse
- Nested tags inside `<noscript>`, `<select>`, `<form>`, `<math>`, `<svg>`
- Content hidden inside `<style>`, `<template>`, `<title>` that gets re-parsed

**DOM Clobbering (`--dom-clobber`) finds:**
- Named elements (form, img, iframe, embed, object) whose `name`/`id` matches JavaScript variable references
- Input elements that could clobber global variables via `window[name]`

---

## Reporting

| Flag | Description |
|------|-------------|
| `--report-json <FILE>` | Save scan results as a JSON file |
| `--report-html <FILE>` | Save scan results as a styled HTML report |

**Examples:**
```
py xsstrike.py -u "http://test.site/?q=test" --report-json results.json
py xsstrike.py -u "http://test.site/?q=test" --report-html report.html
py xsstrike.py -u "http://test.site/?q=test" --csp --polyglot --report-html full_report.html
```

---

## Request Configuration

| Flag | Description | Default |
|------|-------------|---------|
| `--headers <HEADERS>` | Custom HTTP headers (string) | Default browser-like headers |
| `--headers` (no value) | Opens editor to input headers | — |
| `--proxy` | Route requests through a proxy | Uses `http://0.0.0.0:8080` |
| `--timeout <SECONDS>` | Request timeout | 10 |
| `-d, --delay <SECONDS>` | Delay between requests | 0 |
| `-t, --threads <N>` | Number of threads | 10 |
| `--data <DATA>` | POST data as query string | — |
| `--json` | Treat POST data as JSON | — |

**Examples:**
```
py xsstrike.py -u "http://test.site/?q=test" --proxy
py xsstrike.py -u "http://test.site/?q=test" --timeout 30 -d 2
py xsstrike.py -u "http://test.site/api" --data '{"user":"admin"}' --json
py xsstrike.py -u "http://test.site/?q=test" --headers "Cookie: session=abc123"
```

---

## Behavior Control

| Flag | Description |
|------|-------------|
| `--skip` | Don't prompt to continue after each finding |
| `--skip-dom` | Skip DOM XSS analysis (faster) |
| `--update` | Update XSStrike to the latest version |

**Examples:**
```
py xsstrike.py -u "http://test.site/?q=test" --skip
py xsstrike.py -u "http://test.site/?q=test" --skip-dom
py xsstrike.py --update
```

---

## Logging

| Flag | Description | Choices |
|------|-------------|---------|
| `--console-log-level <LEVEL>` | Console log verbosity | `DEBUG`, `INFO`, `RUN`, `GOOD`, `WARNING`, `ERROR`, `CRITICAL`, `VULN` |
| `--file-log-level <LEVEL>` | File log verbosity | Same as above |
| `--log-file <FILE>` | Log file path | Default: `xsstrike.log` |

**Example:**
```
py xsstrike.py -u "http://test.site/?q=test" --console-log-level DEBUG --log-file scan.log
```

---

## Quick Examples

```bash
# Basic scan
py xsstrike.py -u "http://test.site/page.php?q=test"

# Full analysis with all features
py xsstrike.py -u "http://test.site/page.php?q=test" --csp --mxss --dom-clobber --polyglot

# Stealth scan with delay and no prompts
py xsstrike.py -u "http://test.site/page.php?q=test" -d 2 --skip

# WAF bypass with mixed encoding + report
py xsstrike.py -u "http://test.site/page.php?q=test" -e mixed --report-html bypass.html

# Crawl + discover params + blind XSS
py xsstrike.py -u "http://test.site" --crawl -l 2 --discover-params --blind

# Full recon + scan + export
py xsstrike.py -u "http://test.site" --crawl -l 3 --csp --polyglot --discover-params --report-json full_scan.json

# Fuzzer to test WAF rules
py xsstrike.py -u "http://test.site/page.php?q=test" --fuzzer

# Custom payload bruteforce
py xsstrike.py -u "http://test.site/page.php?q=test" -f custom_payloads.txt

# Base64 encoded payloads
py xsstrike.py -u "http://test.site/page.php?q=test" -e base64
```

---

## What Each Module Detects

| Module | Vulnerability Type |
|--------|-------------------|
| Standard scan | Reflected XSS |
| DOM scanner (`dom.py`) | DOM-based XSS (source → sink flow) |
| Crawler (`--crawl`) | XSS in HTML forms across multiple pages |
| CSP analyzer (`--csp`) | Weak/misconfigured Content Security Policies |
| mXSS (`--mxss`) | Mutation Cross-Site Scripting patterns |
| DOM clobbering (`--dom-clobber`) | DOM clobbering gadgets |
| Fuzzer (`--fuzzer`) | WAF behavior analysis |
| Blind XSS (`--blind`) | Blind XSS via callback payloads |
| Retire.js (built-in) | Outdated/vulnerable JavaScript libraries |

---

## File Locations

| Path | Contents |
|------|----------|
| `xsstrike.py` | Main entry point |
| `core/` | All core scanning modules |
| `modes/` | Scan, fuzz, crawl, bruteforce modes |
| `plugins/` | Retire.js plugin |
| `db/wafSignatures.json` | WAF fingerprint database (55 WAFs) |
| `db/definitions.json` | Vulnerable JS library definitions (retire.js) |
