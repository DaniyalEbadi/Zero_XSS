import re
from core.log import setup_logger

logger = setup_logger(__name__)


def parse_csp(headers):
    csp = {}
    for header, value in headers.items():
        if header.lower() in ('content-security-policy', 'content-security-policy-report-only'):
            csp[header] = value
    if not csp:
        return None
    parsed = {}
    for header, value in csp.items():
        directives = {}
        for part in value.split(';'):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directives[tokens[0]] = tokens[1:] if len(tokens) > 1 else []
        parsed[header] = directives
    return parsed


def find_csp_bypasses(csp):
    findings = []
    if not csp:
        return findings
    for header, directives in csp.items():
        is_report_only = 'report-only' in header.lower()
        if is_report_only:
            findings.append(('info', 'CSP is report-only — not enforced'))
        script_src = directives.get('script-src', directives.get('default-src', []))
        script_src_str = ' '.join(script_src)
        if not script_src or '*' in script_src:
            findings.append(('vuln', 'script-src allows all sources (*)'))
        if "'unsafe-inline'" in script_src_str:
            findings.append(('warn', 'script-src allows unsafe-inline'))
        if "'unsafe-eval'" in script_src_str:
            findings.append(('warn', 'script-src allows unsafe-eval'))
        cdn_bypasses = [
            '//cdnjs.cloudflare.com', '//ajax.googleapis.com',
            '//cdn.jsdelivr.net', '//code.jquery.com',
            '//maxcdn.bootstrapcdn.com', '//stackpath.bootstrapcdn.com',
            '//unpkg.com', '//cdn.jsdelivr.net',
        ]
        for src in script_src:
            if any(cdn in src for cdn in cdn_bypasses):
                findings.append(('warn', f'CDN whitelisted ({src}) — may allow library-based bypass'))
        if not script_src and 'default-src' not in directives and base_uri_vulnerable(directives):
            findings.append(('vuln', 'no script-src or default-src — combined with missing base-uri allows base tag injection'))
        if 'object-src' not in directives:
            findings.append(('warn', 'no object-src — plugins may execute'))
        if 'base-uri' not in directives:
            base_uri_missing = True
            findings.append(('warn', 'no base-uri — allows base tag injection'))
    return findings


def base_uri_vulnerable(directives):
    return 'base-uri' not in directives
