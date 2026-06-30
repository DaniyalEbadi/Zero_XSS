import re
from core.log import setup_logger

logger = setup_logger(__name__)

CLOBBER_SINKS = [
    r'window\[[\'"](\w+)[\'"]\]',
    r'window\.(\w+)',
    r'document\[[\'"](\w+)[\'"]\]',
    r'document\.(\w+)',
    r'globalThis\[[\'"](\w+)[\'"]\]',
    r'globalThis\.(\w+)',
    r'(?:var|let|const)\s+(\w+)\s*=',
    r'(?:location|document\.location)\s*=\s*(?:window\.)?(\w+)',
    r'(?:href|src)\s*=\s*(?:window\.)?(\w+)',
    r'(?:innerHTML|outerHTML|insertAdjacentHTML)\s*=\s*.*?(?:window\.)?(\w+)',
    r'eval\s*\(\s*(?:window\.)?(\w+)',
    r'Function\s*\(\s*(?:window\.)?(\w+)',
    r'setTimeout\s*\(\s*(?:window\.)?(\w+)',
    r'setInterval\s*\(\s*(?:window\.)?(\w+)',
    r'(?:\.src|\.href)\s*=\s*(?:window\.)?(\w+)',
]


def detect_dom_clobbering(response):
    findings = []
    for sink in CLOBBER_SINKS:
        matches = re.findall(sink, response, re.I)
        for match in matches:
            findings.append({
                'sink': sink,
                'variable': match,
                'snippet': match
            })
    named_elements = re.findall(r'<(?:form|img|iframe|embed|object)\s[^>]*?(?:name|id)=[\'"]([^\'"]+)[\'"]', response, re.I)
    for element in named_elements:
        for finding in findings:
            if element == finding['variable']:
                finding['clobberable'] = True
                finding['element_name'] = element
    controllable = re.findall(
        r'<input[^>]*?(?:name|id)=[\'"]([^\'"]+)[\'"][^>]*>',
        response, re.I
    )
    for ctrl in controllable:
        for finding in findings:
            if ctrl == finding['variable']:
                finding['clobberable'] = True
                finding['element_name'] = ctrl
    return [f for f in findings if f.get('clobberable')]
