"""Read-only directory traversal and local file inclusion checks."""

import re
from urllib.parse import parse_qsl, urlparse

from . import runtime
from .network import request_with_retry
from .params import build_url_with_parameter
from .runtime import (
    print_debug,
    print_info,
    print_vulnerability,
    print_warning,
    tagged_output,
)


args = None


DEFAULT_FILE_PARAMETERS = (
    "file",
    "filename",
    "path",
    "filepath",
    "page",
    "template",
    "download",
    "include",
    "document",
)

TRAVERSAL_PAYLOADS = (
    ("../../../../../../etc/passwd", "linux"),
    ("..\\..\\..\\..\\..\\..\\Windows\\win.ini", "windows"),
    ("....//....//....//....//....//....//etc/passwd", "linux"),
    ("....\\....\\....\\....\\....\\....\\Windows\\win.ini", "windows"),
)

FILE_INCLUSION_PAYLOADS = (
    ("/etc/passwd", "linux"),
    ("C:\\Windows\\win.ini", "windows"),
    ("php://filter/convert.base64-encode/resource=/etc/passwd", "php_linux"),
    (
        "php://filter/convert.base64-encode/resource=C:\\Windows\\win.ini",
        "php_windows",
    ),
)

SIGNATURES = {
    "linux": re.compile(rb"(?m)^root:[^:\r\n]*:0:0:"),
    "windows": re.compile(rb"(?im)^[ \t]*\[(?:fonts|extensions|mci extensions)\]"),
    "php_linux": re.compile(rb"cm9vdDp4OjA6MDp[A-Za-z0-9+/=]{12,}"),
    "php_windows": re.compile(rb"W2ZvbnRzXQ[A-Za-z0-9+/=]{8,}"),
}


def _request_options():
    timeout = getattr(args, "timeout", 3)
    if getattr(args, "fast_mode", False):
        timeout *= 0.5

    configured_retries = max(1, getattr(args, "retries", 1))
    retries = 1 if getattr(args, "fast_mode", False) else min(2, configured_retries)
    return timeout, retries


def _build_header():
    header = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/74.0.3729.108 Safari/537.36"
        )
    }
    cookie = getattr(args, "cookie", None)
    if cookie:
        header["Cookie"] = cookie
    return header


def _candidate_parameters(url):
    parameters = list(
        dict.fromkeys(
            name
            for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)
        )
    )
    if not parameters:
        parameters = list(DEFAULT_FILE_PARAMETERS)

    if getattr(args, "fast_mode", False):
        limit = 4
    else:
        limit = min(
            max(1, getattr(args, "max_param_combinations", 20)),
            len(DEFAULT_FILE_PARAMETERS),
        )
    return parameters[:limit]


def _payloads_for_scan(payloads):
    if getattr(args, "fast_mode", False):
        return payloads[:2]
    return payloads


def _extract_evidence(content, signature_name):
    match = SIGNATURES[signature_name].search(content)
    if not match:
        return None

    start = max(0, match.start() - 40)
    end = min(len(content), match.end() + 80)
    evidence = content[start:end].decode("utf-8", "ignore")
    return " ".join(evidence.split())[:180]


def _scan_file_payloads(url, vulnerability_type, payloads):
    vulnerabilities = []
    header = _build_header()
    timeout, retries = _request_options()
    proxy = getattr(args, "proxy", None)

    baseline = request_with_retry(url, header, timeout, proxy, retries)
    if baseline is None:
        return vulnerabilities

    baseline_content = baseline.content
    # 正常页面本身就包含这些特征时，后续命中不能作为漏洞证据。
    baseline_signatures = {
        name for name, pattern in SIGNATURES.items() if pattern.search(baseline_content)
    }

    for parameter in _candidate_parameters(url):
        if runtime.should_stop():
            print_warning("收到中断信号，停止文件类漏洞检测")
            return vulnerabilities

        for payload, signature_name in _payloads_for_scan(payloads):
            if signature_name in baseline_signatures:
                continue

            test_url = build_url_with_parameter(url, parameter, payload)
            try:
                response = request_with_retry(
                    test_url,
                    header,
                    timeout,
                    proxy,
                    retries,
                )
                if response is None:
                    continue

                # 只匹配已知系统文件特征，避免仅凭状态码或页面标题误报。
                evidence = _extract_evidence(response.content, signature_name)
                if not evidence:
                    continue

                vulnerability = {
                    "type": vulnerability_type,
                    "url": url,
                    "parameter": parameter,
                    "payload": payload,
                    "test_url": test_url,
                    "risk_level": "高危",
                    "confirmed": True,
                    "auto_verified": True,
                    "evidence": evidence,
                }
                vulnerabilities.append(vulnerability)
                print_vulnerability(vulnerability)
                break
            except Exception as exc:
                if getattr(args, "verbose", False):
                    print_debug(
                        f"{vulnerability_type}检测失败：{type(exc).__name__}"
                    )

    return vulnerabilities


@tagged_output("目录遍历")
def test_path_traversal(url):
    """Detect traversal payloads that expose a known local system file."""
    print_info("开始目录遍历检测")
    return _scan_file_payloads(url, "目录遍历", TRAVERSAL_PAYLOADS)


@tagged_output("文件包含")
def test_file_inclusion(url):
    """Detect local file inclusion through absolute paths and PHP wrappers."""
    print_info("开始本地文件包含检测")
    return _scan_file_payloads(url, "本地文件包含", FILE_INCLUSION_PAYLOADS)
