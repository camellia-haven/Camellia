"""Console output, report formatting, and scan interruption state."""

import contextvars
import signal
import sys
import threading
from contextlib import contextmanager
from datetime import datetime
from functools import wraps

from colorama import Fore, Style, init


stop_scanning = False
_color_enabled = True
_verbose_enabled = False
_RULE_WIDTH = 78
output_lock = threading.RLock()
_output_tag = contextvars.ContextVar("output_tag", default=None)

_TAG_MAP = {
    "INFO": "INFO",
    "SUCCESS": "成功",
    "WARNING": "警告",
    "ERROR": "错误",
    "DEBUG": "调试",
    "SYSTEM": "系统",
    "SCAN": "扫描",
    "FINDING": "发现",
    "CRITICAL": "严重",
}

_DISPLAY_MAP = {
    "script": "脚本块",
    "attribute": "HTML属性",
    "comment": "注释",
    "url": "URL",
    "html_content": "HTML正文",
}


def _configure_standard_streams():
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, OSError, ValueError):
                pass


_configure_standard_streams()
init(autoreset=True)


def configure_output(no_color=False, verbose=False):
    """Configure color output for all scanner log helpers."""
    global _color_enabled, _verbose_enabled
    _color_enabled = not no_color
    _verbose_enabled = bool(verbose)


def display_text(value):
    """Keep internal labels readable in the Chinese console and report."""
    if value is None:
        return None
    text = str(value)
    return _DISPLAY_MAP.get(text, text)


@contextmanager
def output_tag(tag):
    """Attach a test-specific tag to logs emitted in the current context."""
    token = _output_tag.set(str(tag))
    try:
        yield
    finally:
        _output_tag.reset(token)


def tagged_output(tag):
    """Decorate a scan entry point so all of its logs carry one tag."""
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            with output_tag(tag):
                return function(*args, **kwargs)

        return wrapper

    return decorator


def _paint(text, color):
    if not _color_enabled:
        return text
    return f"{color}{text}{Style.RESET_ALL}"


def _prefix(tag):
    localized_tag = _TAG_MAP.get(tag, tag)
    prefix = f"[{datetime.now().strftime('%H:%M:%S')}] [{localized_tag}]"
    active_tag = _output_tag.get()
    if active_tag:
        prefix += f" [{display_text(active_tag)}]"
    return prefix


def _write(text):
    with output_lock:
        sys.stdout.write(text)
        sys.stdout.flush()


def _emit(tag, message, color):
    lines = str(message).splitlines() or [""]
    prefix = _prefix(tag)
    continuation = " " * len(prefix)
    rendered = [f"{prefix} {lines[0]}"]
    rendered.extend(f"{continuation} {line}" for line in lines[1:])
    _write(_paint("\n".join(rendered), color) + "\n")


def should_stop():
    return stop_scanning


def install_signal_handlers():
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)


def signal_handler(signum, frame):
    global stop_scanning
    stop_scanning = True
    print_warning("收到中断信号，正在安全停止...")
    print_info("正在等待当前任务结束")
    sys.exit(0)


def print_banner():
    banner_lines = (
        "  ██████╗ █████╗ ███╗   ███╗███████╗██╗     ██╗     ██╗ █████╗ ",
        " ██╔════╝██╔══██╗████╗ ████║██╔════╝██║     ██║     ██║██╔══██╗",
        " ██║     ███████║██╔████╔██║█████╗  ██║     ██║     ██║███████║",
        " ██║     ██╔══██║██║╚██╔╝██║██╔══╝  ██║     ██║     ██║██╔══██║",
        " ╚██████╗██║  ██║██║ ╚═╝ ██║███████╗███████╗███████╗██║██║  ██║",
        "  ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝╚═╝╚═╝  ╚═╝",
    )
    banner_colors = (
        Fore.LIGHTCYAN_EX,
        Fore.CYAN,
        Fore.LIGHTGREEN_EX,
        Fore.LIGHTYELLOW_EX,
        Fore.LIGHTMAGENTA_EX,
        Fore.MAGENTA,
    )
    rendered = [""]
    for line, color in zip(banner_lines, banner_colors):
        rendered.append(_paint(line, color))
    rendered.append(
        _paint("           作者：Camellia", Fore.LIGHTCYAN_EX)
    )
    rendered.append(
        _paint("           未经任何授权的扫描探测都是攻击行为", Fore.RED)
    )
    rendered.append("")
    _write("\n".join(rendered) + "\n")


def print_legal_warning():
    """Print the full authorization warning before an actual scan."""
    lines = (
        (
            "[!] Warning: This security scanning tool is for authorized "
            "security testing and educational purposes only."
        ),
        (
            "Any scanning, detection or intrusion behavior without explicit "
            "written authorization from the asset owner is an illegal attack."
        ),
        "You shall bear all legal liabilities for improper use.",
        "",
        (
            "⚠️ 警告：本安全检测工具仅用于已获得资产所有者书面授权的"
            "安全测试与学习研究。"
        ),
        (
            "未经授权对任何网络资产进行扫描、探测均属于网络攻击行为，"
            "不当使用产生的全部法律责任由使用者自行承担。"
        ),
    )
    _write(_paint("\n".join(lines), Fore.RED) + "\n")


def print_rule(color=Fore.CYAN):
    _write(_paint("-" * _RULE_WIDTH, color) + "\n")


def print_section(title, details=None):
    """Print a sqlmap-style section header with optional key/value details."""
    lines = [""]
    prefix = _prefix("SCAN")
    lines.append(_paint(f"{prefix} {display_text(title)}", Fore.CYAN))
    if details:
        if isinstance(details, dict):
            details = details.items()
        for label, value in details:
            lines.extend(_format_kv(label, value))
    _write("\n".join(lines) + "\n")


def _format_kv(label, value, indent=9, label_width=16):
    if value is None or value == "":
        return []

    value_lines = str(value).splitlines() or [""]
    padding = " " * indent
    lines = [
        f"{padding}{display_text(label):<{label_width}}: {value_lines[0]}"
    ]
    for line in value_lines[1:]:
        lines.append(f"{padding}{'':<{label_width}}  {line}")
    return lines


def print_kv(label, value, indent=9, label_width=16):
    """Print an aligned key/value row used by findings and summaries."""
    lines = _format_kv(label, value, indent, label_width)
    if lines:
        _write("\n".join(lines) + "\n")


def _first_value(data, *keys):
    for key in keys:
        value = data.get(key)
        if value not in (None, "", [], ()):
            return value
    return None


def _format_payload(data):
    payload = _first_value(data, "payload", "test_payload")
    if payload:
        return payload

    payload_true = _first_value(data, "payload_true")
    payload_false = _first_value(data, "payload_false")
    if payload_true or payload_false:
        return f"真条件: {payload_true or '-'} | 假条件: {payload_false or '-'}"
    return None


def print_vulnerability(vulnerability):
    """Render a confirmed or suspected vulnerability using one stable format."""
    vulnerability_type = display_text(
        _first_value(vulnerability, "type") or "未知漏洞"
    )
    raw_risk = _first_value(vulnerability, "risk_level") or "未评级"
    risk = display_text(raw_risk)
    confirmed = bool(vulnerability.get("confirmed"))
    tag = "CRITICAL" if raw_risk in ("严重", "高危") else "WARNING"

    color = Fore.RED if tag == "CRITICAL" else Fore.YELLOW
    lines = ["", _paint(
        f"{_prefix(tag)} {vulnerability_type}",
        color,
    )]
    details = (
        ("类型", vulnerability_type),
        ("风险", risk),
        ("状态", "已确认" if confirmed else "待确认"),
        ("地址", _first_value(vulnerability, "url")),
        ("参数", _first_value(vulnerability, "parameter", "param_name")),
        ("载荷", _format_payload(vulnerability)),
        ("测试地址", _first_value(vulnerability, "test_url")),
    )
    for label, value in details:
        lines.extend(_format_kv(label, value))

    locations = _first_value(vulnerability, "locations", "paths")
    if isinstance(locations, (list, tuple)):
        locations = "\n".join(str(item) for item in locations)

    score = _first_value(vulnerability, "cvss_score", "score")
    cvss_version = _first_value(vulnerability, "cvss_version")
    cvss = None
    if score is not None:
        cvss = str(score)
        if cvss_version:
            cvss += f"（CVSS {cvss_version}）"

    description = _first_value(vulnerability, "description")
    if description and len(str(description)) > 600:
        description = str(description)[:600] + "..."

    component_details = (
        ("CVE编号", _first_value(vulnerability, "cve_id", "cve_number")),
        ("组件", _first_value(vulnerability, "component", "product")),
        ("版本", _first_value(vulnerability, "version")),
        ("CVSS", cvss),
        ("文件位置", locations),
    )
    for label, value in component_details:
        lines.extend(_format_kv(label, value))

    contexts = _first_value(vulnerability, "contexts", "context")
    if isinstance(contexts, (list, tuple)):
        contexts = ", ".join(display_text(item) for item in contexts)
    else:
        contexts = display_text(contexts)
    extra_details = (
        ("上下文", contexts),
        ("命令", _first_value(vulnerability, "command")),
        (
            "检测方式",
            display_text(
                _first_value(vulnerability, "detection_method", "method")
            ),
        ),
        ("数据来源", display_text(_first_value(vulnerability, "source"))),
        ("说明", description),
        ("证据", display_text(_first_value(vulnerability, "evidence"))),
    )
    for label, value in extra_details:
        lines.extend(_format_kv(label, value))
    lines.append(_paint("-" * _RULE_WIDTH, color))
    _write("\n".join(lines) + "\n")


def print_finding(finding):
    """Render a sensitive-information finding."""
    finding_type = display_text(_first_value(finding, "type") or "敏感信息")
    lines = [
        "",
        _paint(f"{_prefix('FINDING')} {finding_type}", Fore.MAGENTA),
    ]
    for label, value in (
        ("类型", finding_type),
        ("地址", _first_value(finding, "url")),
        ("内容", _first_value(finding, "value")),
    ):
        lines.extend(_format_kv(label, value))
    _write("\n".join(lines) + "\n")


def print_summary(title, rows):
    """Print a compact aligned summary block."""
    print_section(title)
    if isinstance(rows, dict):
        rows = rows.items()
    for label, value in rows:
        print_kv(label, value)


def print_info(message):
    _emit("INFO", message, Fore.LIGHTGREEN_EX)


def print_verbose(message):
    if _verbose_enabled:
        _emit("INFO", message, Fore.LIGHTGREEN_EX)


def print_success(message):
    _emit("SUCCESS", message, Fore.GREEN)


def print_error(message):
    _emit("ERROR", message, Fore.LIGHTRED_EX)


def print_cool(message):
    _emit("SYSTEM", message, Fore.MAGENTA)


def print_warning(message):
    _emit("WARNING", message, Fore.YELLOW)


def print_debug(message):
    if _verbose_enabled:
        _emit("DEBUG", message, Fore.BLUE)


def print_vuln(message):
    _emit("CRITICAL", message, Fore.RED)


def print_progress(current, total, prefix='', suffix=''):
    bar_length = 50
    filled_length = int(round(bar_length * current / float(total)))
    percents = round(100.0 * current / float(total), 1)
    bar = '#' * filled_length + '-' * (bar_length - filled_length)
    with output_lock:
        sys.stdout.write(f'\r{prefix} |{bar}| {percents}% {suffix}')
        sys.stdout.flush()


install_signal_handlers()
