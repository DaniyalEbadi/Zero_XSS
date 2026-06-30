import json
import re
import sys

from core.requester import requester
from core.log import setup_logger

logger = setup_logger(__name__)


def wafDetector(url, params, headers, GET, delay, timeout):
    with open(sys.path[0] + '/db/wafSignatures.json', 'r') as file:
        wafSignatures = json.load(file)
    noise = '<script>alert("XSS")</script>'
    params['xss'] = noise
    response = requester(url, params, headers, GET, delay, timeout)
    page = response.text
    code = str(response.status_code) if response.status_code else '0'
    headers = str(response.headers)
    logger.debug('Waf Detector code: {}'.format(code))
    logger.debug_json('Waf Detector headers:', response.headers)

    if response.status_code and int(code) >= 400:
        bestMatch = [0, None]
        for wafName, wafSignature in wafSignatures.items():
            score = 0
            pageSign = wafSignature['page']
            codeSign = wafSignature['code']
            headersSign = wafSignature['headers']
            if pageSign:
                if re.search(pageSign, page, re.I):
                    score += 1
            if codeSign:
                if re.search(codeSign, code, re.I):
                    score += 0.5
            if headersSign:
                if re.search(headersSign, headers, re.I):
                    score += 1
            if score > bestMatch[0]:
                del bestMatch[:]
                bestMatch.extend([score, wafName])
        if bestMatch[0] != 0:
            return bestMatch[1]
        else:
            return None
    else:
        return None


def get_bypass_strategy(waf_name):
    try:
        from core.config import waf_bypass_strategies
        if waf_name in waf_bypass_strategies:
            return waf_bypass_strategies[waf_name]
        for key in waf_bypass_strategies:
            if key.lower() in waf_name.lower():
                return waf_bypass_strategies[key]
    except (ImportError, AttributeError):
        pass
    return None
