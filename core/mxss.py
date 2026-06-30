import re
from core.log import setup_logger

logger = setup_logger(__name__)

MXSS_PATTERNS = [
    r'<([a-zA-Z][a-zA-Z0-9]*)\s+([^>]*?)style\s*=\s*["\']?[^"\'>]*?(?:display\s*:\s*none|visibility\s*:\s*hidden)[^>]*?>',
    r'<([a-zA-Z][a-zA-Z0-9]*)\s+([^>]*?)style\s*=\s*["\']?[^"\'>]*?white-space\s*:\s*pre[^>]*?>',
    r'<([a-zA-Z][a-zA-Z0-9]*)\s+([^>]*?)style\s*=\s*["\']?[^"\'>]*?overflow\s*:\s*hidden[^>]*?>',
    r'<noscript[^>]*?>.*?<',
    r'<select[^>]*?>.*?<',
    r'<form[^>]*?>.*?<',
    r'<math[^>]*?>.*?<',
    r'<svg[^>]*?>.*?<',
]


def detect_mxss(response):
    findings = []
    for i, pattern in enumerate(MXSS_PATTERNS):
        matches = re.findall(pattern, response, re.I | re.S)
        if matches:
            findings.append({
                'pattern_index': i,
                'pattern': pattern,
                'matches': len(matches),
                'snippet': str(matches[:3])
            })
    non_executable_tags = ['<style[^>]*?>.*?</style>',
                           '<template[^>]*?>.*?</template>',
                           '<title[^>]*?>.*?</title>']
    for tag_pattern in non_executable_tags:
        for match in re.finditer(tag_pattern, response, re.I | re.S):
            content = match.group()
            if re.search(r'<[a-z]', content[7:], re.I):
                findings.append({
                    'pattern_index': -1,
                    'pattern': tag_pattern,
                    'matches': 1,
                    'snippet': content[:200]
                })
    return findings
