import base64 as b64
import re
import random


def base64(string):
    if re.match(r'^[A-Za-z0-9+\/=]+$', string) and (len(string) % 4) == 0:
        return b64.b64decode(string.encode('utf-8')).decode('utf-8')
    else:
        return b64.b64encode(string.encode('utf-8')).decode('utf-8')


def double_url_encode(string):
    result = ''
    for char in string:
        result += '%25' + format(ord(char), 'x')
    return result


def unicode_encode(string):
    result = ''
    for char in string:
        result += '\\u' + format(ord(char), '04x')
    return result


def hex_encode(string):
    result = ''
    for char in string:
        result += '\\x' + format(ord(char), '02x')
    return result


def decimal_html_entities(string):
    result = ''
    for char in string:
        result += '&#' + str(ord(char)) + ';'
    return result


def hex_html_entities(string):
    result = ''
    for char in string:
        result += '&#x' + format(ord(char), 'x') + ';'
    return result


def mixed_encode(string):
    encoders = [double_url_encode, unicode_encode, hex_encode, decimal_html_entities]
    result = ''
    for char in string:
        enc = random.choice(encoders)
        result += enc(char)
    return result


encoder_map = {
    'base64': base64,
    'double-url': double_url_encode,
    'unicode': unicode_encode,
    'hex': hex_encode,
    'decimal-entities': decimal_html_entities,
    'hex-entities': hex_html_entities,
    'mixed': mixed_encode,
}
