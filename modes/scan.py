import copy
import re
from urllib.parse import urlparse, quote, unquote

from core.checker import checker
from core.colors import end, green, que
import core.config
from core.config import xsschecker, minEfficiency
from core.dom import dom
from core.filterChecker import filterChecker
from core.generator import generator
from core.htmlParser import htmlParser
from core.requester import requester
from core.utils import getUrl, getParams, getVar
from core.wafDetector import wafDetector, get_bypass_strategy
from core.cspAnalyzer import parse_csp, find_csp_bypasses
from core.mxss import detect_mxss
from core.domClobber import detect_dom_clobbering
from core.reporter import generate_report, save_json, save_html
from core.paramDiscovery import discover_params
from core.wafBypass import build_char_matrix, craft_payload_from_matrix, generate_waf_specific_payloads, auto_select_encoding, test_bypass_payloads, hpp_payload
from core.log import setup_logger

logger = setup_logger(__name__)


def scan(target, paramData, encoding, headers, delay, timeout, skipDOM, skip):
    GET, POST = (False, True) if paramData else (True, False)
    if not target.startswith('http'):
        try:
            response = requester('https://' + target, {},
                                 headers, GET, delay, timeout)
            target = 'https://' + target
        except:
            target = 'http://' + target
    logger.debug('Scan target: {}'.format(target))
    response = requester(target, {}, headers, GET, delay, timeout)
    response_text = response.text

    csp_analysis = None
    csp_report = None
    if not skipDOM:
        csp_parsed = parse_csp(response.headers)
        if csp_parsed:
            csp_report = find_csp_bypasses(csp_parsed)
            if csp_report:
                logger.run('CSP Analysis')
                for severity, msg in csp_report:
                    if severity == 'vuln':
                        logger.error('CSP: %s' % msg)
                    elif severity == 'warn':
                        logger.warning('CSP: %s' % msg)
                    else:
                        logger.info('CSP: %s' % msg)
                csp_analysis = csp_report

    if not skipDOM:
        logger.run('Checking for DOM vulnerabilities')
        highlighted = dom(response_text)
        if highlighted:
            logger.good('Potentially vulnerable objects found')
            logger.red_line(level='good')
            for line in highlighted:
                logger.no_format(line, level='good')
            logger.red_line(level='good')

        mxss_findings = detect_mxss(response_text)
        if mxss_findings:
            logger.good('Potential mXSS patterns found (%i)' % len(mxss_findings))

        clobber_findings = detect_dom_clobbering(response_text)
        if clobber_findings:
            logger.good('Potential DOM clobbering sinks found (%i)' % len(clobber_findings))

    host = urlparse(target).netloc
    logger.debug('Host to scan: {}'.format(host))
    url = getUrl(target, GET)
    logger.debug('Url to scan: {}'.format(url))
    params = getParams(target, paramData, GET)
    logger.debug_json('Scan parameters:', params)
    if not params:
        logger.error('No parameters to test.')
        return

    WAF = wafDetector(
        url, {list(params.keys())[0]: xsschecker}, headers, GET, delay, timeout)
    waf_encoding = None
    if WAF:
        logger.error('WAF detected: %s%s%s' % (green, WAF, end))
        bypass_hint = get_bypass_strategy(WAF)
        if bypass_hint:
            logger.info('WAF Bypass: auto-applying %s encoding' % bypass_hint.get('encoding', ['mixed'])[0])
        waf_encoding = auto_select_encoding(WAF)
        if not encoding:
            encoding = waf_encoding
            logger.info('Auto-selected encoding for %s' % WAF)
        logger.run('Probing WAF character filter')
        matrix = build_char_matrix(url, {list(params.keys())[0]: xsschecker}, headers, GET, delay, timeout)
        allowed = len(matrix['allowed'])
        blocked = len(matrix['blocked'])
        encoded = len(matrix['encoded'])
        logger.info('Char matrix: %i allowed, %i blocked, %i encoded' % (allowed, blocked, encoded))
    else:
        logger.good('WAF Status: %sOffline%s' % (green, end))
        matrix = None

    findings = []

    if core.config.globalVariables.get('discover_params', False):
        logger.run('Discovering hidden parameters')
        discovered = discover_params(url, headers, GET, delay, timeout)
        for param in discovered:
            if param not in params:
                params[param] = xsschecker
                logger.info('Added discovered parameter: %s' % param)

    for paramName in params.keys():
        paramsCopy = copy.deepcopy(params)
        logger.info('Testing parameter: %s' % paramName)
        if encoding:
            paramsCopy[paramName] = encoding(xsschecker)
        else:
            paramsCopy[paramName] = xsschecker
        response = requester(url, paramsCopy, headers, GET, delay, timeout)
        occurences = htmlParser(response, encoding)
        positions = occurences.keys()
        logger.debug('Scan occurences: {}'.format(occurences))
        if not occurences:
            logger.error('No reflection found')
            continue
        else:
            logger.info('Reflections found: %i' % len(occurences))

        logger.run('Analysing reflections')
        efficiencies = filterChecker(
            url, paramsCopy, headers, GET, delay, occurences, timeout, encoding)
        logger.debug('Scan efficiencies: {}'.format(efficiencies))
        logger.run('Generating payloads')
        include_polyglot = core.config.globalVariables.get('polyglot', False)
        vectors = generator(occurences, response.text, include_polyglot)
        if WAF:
            from core.config import bypass_payloads
            waf_vectors = generate_waf_specific_payloads(WAF, bypass_payloads)
            for p in waf_vectors:
                vectors[4].add(p)
            logger.info('WAF bypass payloads added: %i' % len(waf_vectors))
        total = 0
        for v in vectors.values():
            total += len(v)
        if total == 0:
            logger.error('No vectors were crafted.')
            continue
        logger.info('Payloads generated: %i' % total)
        progress = 0
        for confidence, vects in vectors.items():
            for vect in vects:
                if core.config.globalVariables['path']:
                    vect = vect.replace('/', '%2F')
                loggerVector = vect
                progress += 1
                logger.run('Progress: %i/%i\r' % (progress, total))
                if not GET:
                    vect = unquote(vect)
                efficiencies = checker(
                    url, paramsCopy, headers, GET, delay, vect, positions, timeout, encoding)
                if not efficiencies:
                    for i in range(len(occurences)):
                        efficiencies.append(0)
                bestEfficiency = max(efficiencies)
                if bestEfficiency == 100 or (vect[0] == '\\' and bestEfficiency >= 95):
                    logger.red_line()
                    logger.good('Payload: %s' % loggerVector)
                    logger.info('Efficiency: %i' % bestEfficiency)
                    logger.info('Confidence: %i' % confidence)
                    findings.append({
                        'type': 'reflected_xss',
                        'parameter': paramName,
                        'payload': loggerVector,
                        'efficiency': bestEfficiency,
                        'confidence': confidence,
                        'severity': 'critical' if bestEfficiency == 100 else 'high',
                    })
                    if not skip:
                        choice = input(
                            '%s Would you like to continue scanning? [y/N] ' % que).lower()
                        if choice != 'y':
                            if getVar('report_json') or getVar('report_html'):
                                report = generate_report(findings, target)
                                if getVar('report_json'):
                                    save_json(report, getVar('report_json'))
                                    logger.good('JSON report saved: %s' % getVar('report_json'))
                                if getVar('report_html'):
                                    save_html(report, getVar('report_html'))
                                    logger.good('HTML report saved: %s' % getVar('report_html'))
                            quit()
                elif bestEfficiency > minEfficiency:
                    logger.red_line()
                    logger.good('Payload: %s' % loggerVector)
                    logger.info('Efficiency: %i' % bestEfficiency)
                    logger.info('Confidence: %i' % confidence)
                    findings.append({
                        'type': 'reflected_xss',
                        'parameter': paramName,
                        'payload': loggerVector,
                        'efficiency': bestEfficiency,
                        'confidence': confidence,
                        'severity': 'high' if bestEfficiency >= 95 else 'medium',
                    })
    logger.no_format('')

    if getVar('report_json') or getVar('report_html'):
        report = generate_report(findings, target)
        if getVar('report_json'):
            save_json(report, getVar('report_json'))
            logger.good('JSON report saved: %s' % getVar('report_json'))
        if getVar('report_html'):
            save_html(report, getVar('report_html'))
            logger.good('HTML report saved: %s' % getVar('report_html'))
