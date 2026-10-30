"""Read-only command injection checks using the fixed id command."""

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


DEFAULT_COMMAND_PARAMETERS = (
    "cmd",
    "command",
    "exec",
    "ping",
    "host",
    "ip",
    "query",
    "name",
)

COMMAND_PAYLOADS = (
    # 只使用固定的 id 命令，不提供任意命令执行入口。
    ";id",
    "|id",
    "$(id)",
    "`id`",
    "\nid",
)

ID_OUTPUT_PATTERN = re.compile(
    rb"\buid=\d+\([^)]{1,64}\)\s+gid=\d+\([^)]{1,64}\)"
)


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
        parameters = list(DEFAULT_COMMAND_PARAMETERS)

    if getattr(args, "fast_mode", False):
        limit = 4
    else:
        limit = min(
            max(1, getattr(args, "max_param_combinations", 20)),
            len(DEFAULT_COMMAND_PARAMETERS),
        )
    return parameters[:limit]


def _payloads_for_scan():
    if getattr(args, "fast_mode", False):
        return COMMAND_PAYLOADS[:3]
    return COMMAND_PAYLOADS


@tagged_output("命令注入")
def test_command_injection(url):
    """Detect command injection by looking only for output from the id command."""
    vulnerabilities = []
    print_info("开始命令注入检测")
    header = _build_header()
    timeout, retries = _request_options()
    proxy = getattr(args, "proxy", None)

    baseline = request_with_retry(url, header, timeout, proxy, retries)
    # 基线页面已经包含 id 输出时直接跳过，避免把原页面内容当成注入结果。
    if baseline is None or ID_OUTPUT_PATTERN.search(baseline.content):
        return vulnerabilities

    for parameter in _candidate_parameters(url):
        if runtime.should_stop():
            print_warning("收到中断信号，停止命令注入检测")
            return vulnerabilities

        for payload in _payloads_for_scan():
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

                match = ID_OUTPUT_PATTERN.search(response.content)
                if not match:
                    continue

                evidence = match.group(0).decode("utf-8", "ignore")[:180]
                vulnerability = {
                    "type": "命令注入",
                    "url": url,
                    "parameter": parameter,
                    "payload": payload,
                    "test_url": test_url,
                    "risk_level": "高危",
                    "confirmed": True,
                    "auto_verified": True,
                    "command": "id",
                    "evidence": evidence,
                }
                vulnerabilities.append(vulnerability)
                print_vulnerability(vulnerability)
                break
            except Exception as exc:
                if getattr(args, "verbose", False):
                    print_debug(
                        f"命令注入检测失败：{type(exc).__name__}"
                    )

    return vulnerabilities
