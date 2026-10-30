"""Reflected XSS detection and exploitability checks."""

import re
from urllib.parse import parse_qs, quote, urlparse

from . import runtime
from .config import ADVANCED_XSS_PAYLOADS, XSS_PAYLOADS, load_custom_payloads
from .network import request_with_retry
from .runtime import (
    print_debug,
    print_info,
    print_success,
    tagged_output,
    print_vulnerability,
    print_warning,
)


args = None


def analyze_xss_context(content, payload):
    contexts = []


    script_pattern = r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>'
    if re.search(script_pattern, content, re.IGNORECASE | re.DOTALL):
        contexts.append('script')


    attr_pattern = r'\w+=["\']?[^"\'>]*' + re.escape(payload) + r'[^"\'>]*["\']?'
    if re.search(attr_pattern, content, re.IGNORECASE):
        contexts.append('attribute')


    comment_pattern = r'<!--.*?' + re.escape(payload) + r'.*?-->'
    if re.search(comment_pattern, content, re.IGNORECASE | re.DOTALL):
        contexts.append('comment')


    url_pattern = r'(?:href|src|action)=["\']?[^"\'>]*' + re.escape(payload) + r'[^"\'>]*["\']?'
    if re.search(url_pattern, content, re.IGNORECASE):
        contexts.append('url')


    if payload in content and not contexts:
        contexts.append('html_content')

    return contexts

def verify_xss_exploitability(url, param_name, original_payload, context, header):
    verification_results = []


    if 'script' in context:
        test_payloads = ADVANCED_XSS_PAYLOADS['script_context']
    elif 'attribute' in context:
        test_payloads = ADVANCED_XSS_PAYLOADS['attribute_context']
    elif 'url' in context:
        test_payloads = ADVANCED_XSS_PAYLOADS['url_context']
    else:
        test_payloads = ADVANCED_XSS_PAYLOADS['html_context']


    test_payloads.extend(ADVANCED_XSS_PAYLOADS['bypass_waf'])

    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)

    for payload in test_payloads[:5]:
        try:
            test_params = params.copy()
            test_params[param_name] = [payload]

            test_query = '&'.join([f"{k}={quote(v[0])}" for k, v in test_params.items()])
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"

            response = request_with_retry(test_url, header, args.timeout, args.proxy, args.retries)

            if response:
                content = response.content.decode("utf-8", "ignore")

                if payload in content:
                    new_contexts = analyze_xss_context(content, payload)

                    exploitability = assess_xss_exploitability(payload, new_contexts, content)

                    verification_results.append({
                        'payload': payload,
                        'contexts': new_contexts,
                        'exploitability': exploitability,
                        'test_url': test_url
                    })

                    if exploitability['score'] >= 8:  # 高可利用性
                        break

        except Exception as e:
            continue

    return verification_results

def assess_xss_exploitability(payload, contexts, content):
    """Assess the exploitability of a reflected XSS payload."""
    score = 0
    risk_factors = []

    # 基于上下文评分
    if 'script' in contexts:
        score += 9
        risk_factors.append("载荷位于脚本元素内，可能直接执行")
    elif 'attribute' in contexts:
        if 'onerror' in payload or 'onload' in payload or 'onclick' in payload:
            score += 8
            risk_factors.append("载荷可在事件处理器中执行")
        else:
            score += 6
            risk_factors.append("载荷反射到HTML属性中")
    elif 'url' in contexts:
        if payload.startswith('javascript:'):
            score += 7
            risk_factors.append("可通过JavaScript URI执行")
        else:
            score += 4
            risk_factors.append("载荷反射到URL中")
    elif 'html_content' in contexts:
        if '<script>' in payload or 'onerror=' in payload:
            score += 8
            risk_factors.append("HTML正文中包含可执行脚本")
        else:
            score += 5
            risk_factors.append("载荷反射到HTML正文中")

    # 编码、转义或 CSP 会降低载荷实际执行概率，因此从基础分中扣减。
    if '&lt;' in content or '&gt;' in content:
        score -= 3
        risk_factors.append("检测到HTML实体编码")

    if '\\"' in content or "\\" in content:
        score -= 2
        risk_factors.append("检测到转义字符")


    if 'content-security-policy' in content.lower():
        score -= 4
        risk_factors.append("检测到CSP策略")


    score = max(0, min(10, score))


    if score >= 8:
        risk_level = "高危"
    elif score >= 6:
        risk_level = "中危"
    elif score >= 3:
        risk_level = "低危"
    else:
        risk_level = "信息"

    return {
        'score': score,
        'risk_level': risk_level,
        'risk_factors': risk_factors
    }

def enhanced_xss_detection(url, param_name, payload, header):
    vulnerabilities = []

    try:
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        test_params = params.copy()
        test_params[param_name] = [payload]

        test_query = '&'.join([f"{k}={quote(v[0])}" for k, v in test_params.items()])
        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"

        response = request_with_retry(test_url, header, args.timeout, args.proxy, args.retries)

        if response:
            content = response.content.decode("utf-8", "ignore")

            # 反射只说明参数进入了页面，后面还要结合上下文和二次验证。
            if payload in content:
                contexts = analyze_xss_context(content, payload)

                if contexts:
                    verification_results = verify_xss_exploitability(url, param_name, payload, contexts, header)

                    initial_exploitability = assess_xss_exploitability(payload, contexts, content)

                    vuln = {
                        "type": "反射型XSS",
                        "url": url,
                        "parameter": param_name,
                        "payload": payload,
                        "test_url": test_url,
                        "contexts": contexts,
                        "exploitability": initial_exploitability,
                        "verification_results": verification_results,
                        "risk_level": initial_exploitability['risk_level'],
                        "auto_verified": len(verification_results) > 0
                    }

                    vulnerabilities.append(vuln)

                    print_vulnerability(vuln)
                    print_info(
                        "可利用性："
                        f"{runtime.display_text(initial_exploitability['risk_level'])}"
                        f"（{initial_exploitability['score']}/10）"
                    )

                    if verification_results:
                        best_verification = max(verification_results, key=lambda x: x['exploitability']['score'])
                        print_success(
                            "自动验证成功，最佳载荷评分："
                            f"{best_verification['exploitability']['score']}/10"
                        )
                        print_info(f"已验证载荷：{best_verification['payload']}")

                    for factor in initial_exploitability['risk_factors']:
                        print_info(f"风险因素：{factor}")

    except Exception as e:
        if args.verbose:
            print_debug("处理数据时增强XSS验证失败")

    return vulnerabilities

@tagged_output("XSS")
def test_xss_vulnerability(url):
    global args
    vulnerabilities = []
    print_info("开始XSS检测")


    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)


    if not params:
        common_params = ['q', 'search', 'query', 'keyword', 'name', 'message', 'comment', 'text', 'input']
        params = {param: ['test'] for param in common_params}
        print_info(
            "URL中没有参数，开始测试常见XSS参数："
            f"{', '.join(common_params)}"
        )

    xss_payloads = XSS_PAYLOADS
    if args.custom_xss:
        custom_payloads = load_custom_payloads(args.custom_xss)
        if custom_payloads:
            xss_payloads.extend(custom_payloads)

    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36"
    }
    if args.cookie:
        header["Cookie"] = args.cookie


    enhanced_mode = hasattr(args, 'enhanced_xss') and args.enhanced_xss

    for param_name in params.keys():

        if enhanced_mode:
            for payload in xss_payloads[:10]:
                if runtime.should_stop():
                    print_warning("收到中断信号，停止XSS检测")
                    return vulnerabilities
                enhanced_vulns = enhanced_xss_detection(url, param_name, payload, header)
                vulnerabilities.extend(enhanced_vulns)
                if enhanced_vulns:
                    break
        else:
            for payload in xss_payloads:
                if runtime.should_stop():
                    print_warning("收到中断信号，停止XSS检测")
                    return vulnerabilities
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]

                    test_query = '&'.join([f"{k}={quote(v[0])}" for k, v in test_params.items()])
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"

                    test_response = request_with_retry(test_url, header, args.timeout, args.proxy, args.retries)

                    if test_response:
                        if test_response.status_code >= 400:
                            if args.verbose:
                                print_debug(
                                    "跳过HTTP "
                                    f"{test_response.status_code}: {test_url}"
                                )
                            continue

                        test_content = test_response.content.decode("utf-8", "ignore")

                        if payload in test_content:
                            contexts = analyze_xss_context(test_content, payload)

                            if contexts:
                                exploitability = assess_xss_exploitability(payload, contexts, test_content)
                                verification_results = verify_xss_exploitability(url, param_name, payload, contexts, header)

                                vuln = {
                                    "type": "反射型XSS",
                                    "url": url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "test_url": test_url,
                                    "contexts": contexts,
                                    "exploitability": exploitability,
                                    "verification_results": verification_results,
                                    "risk_level": exploitability['risk_level'],
                                    "auto_verified": len(verification_results) > 0,
                                    "evidence": (
                                        "载荷反射位置："
                                        + ", ".join(
                                            runtime.display_text(context)
                                            for context in contexts
                                        )
                                    ),
                                }
                                vulnerabilities.append(vuln)

                                print_vulnerability(vuln)
                                print_info(
                                    "可利用性："
                                    f"{runtime.display_text(exploitability['risk_level'])}"
                                    f"（{exploitability['score']}/10）"
                                )

                                if verification_results:
                                    print_success(
                                        "自动验证成功："
                                        f"{len(verification_results)} 个可利用载荷"
                                    )
                                    for result in verification_results:
                                        result_contexts = ", ".join(
                                            runtime.display_text(context)
                                            for context in result.get("contexts", [])
                                        )
                                        print_info(
                                            f"  - {result['payload']} "
                                            f"（上下文：{result_contexts or '未知'}）"
                                        )
                                else:
                                    print_warning(
                                        "自动验证未发现可直接利用的载荷"
                                    )

                                break

                except Exception as e:
                    if args.verbose:
                        error_msg = str(e).strip()
                        if len(error_msg) > 100:
                            error_msg = error_msg[:100] + "..."
                        print_debug(f"XSS测试失败：{error_msg}")
                    continue

    return vulnerabilities
