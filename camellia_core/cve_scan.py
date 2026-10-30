"""Local component vulnerability scanning through cve-bin-tool."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlparse


CVE_BIN_TOOL_GITHUB_URL = "https://github.com/ossf/cve-bin-tool"
CVE_BIN_TOOL_RELEASES_URL = (
    "https://github.com/ossf/cve-bin-tool/releases/latest"
)

SEVERITY_MAP = {
    "CRITICAL": "严重",
    "HIGH": "高危",
    "MEDIUM": "中危",
    "LOW": "低危",
    "UNKNOWN": "未知",
}


class CVEScanError(RuntimeError):
    """Raised when the optional local CVE scanner cannot complete."""


def _first_value(data, *keys):
    for key in keys:
        value = data.get(key)
        if value not in (None, "", [], ()):
            return value
    return None


def _as_list(value):
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, "")]
    return [str(value)]


def _normalize_severity(value, score=None):
    severity = str(value or "").strip().upper()
    severity = severity.rsplit(".", 1)[-1]
    if severity in SEVERITY_MAP:
        return SEVERITY_MAP[severity]

    try:
        numeric_score = float(score)
    except (TypeError, ValueError):
        return SEVERITY_MAP["UNKNOWN"]

    if numeric_score >= 9:
        return SEVERITY_MAP["CRITICAL"]
    if numeric_score >= 7:
        return SEVERITY_MAP["HIGH"]
    if numeric_score >= 4:
        return SEVERITY_MAP["MEDIUM"]
    if numeric_score > 0:
        return SEVERITY_MAP["LOW"]
    return SEVERITY_MAP["UNKNOWN"]


def _extract_records(data):
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []

    for key in ("vulnerabilities", "results", "findings", "data"):
        value = data.get(key)
        if isinstance(value, list):
            return value
    if _first_value(data, "cve_number", "cve_id", "cve"):
        return [data]
    return []


def _build_evidence(record):
    product = _first_value(record, "product", "package_name", "component")
    version = _first_value(record, "version", "package_version")
    source = _first_value(record, "source")
    description = _first_value(record, "description", "comments")

    parts = []
    if product or version:
        parts.append("组件 " + " ".join(str(item) for item in (product, version) if item))
    if source:
        parts.append(f"数据来源 {source}")
    if description:
        parts.append(str(description))
    return "；".join(parts) or "cve-bin-tool 检出已知组件漏洞"


def convert_cve_records(data, target):
    """Convert cve-bin-tool JSON records into Camellia result dictionaries."""
    grouped = {}

    for record in _extract_records(data):
        if not isinstance(record, dict):
            continue

        cve_number = _first_value(record, "cve_number", "cve_id", "cve")
        if not cve_number:
            continue

        vendor = _first_value(record, "vendor")
        product = _first_value(
            record,
            "product",
            "package_name",
            "component",
        )
        version = _first_value(record, "version", "package_version")
        locations = _as_list(_first_value(record, "paths", "path", "locations"))
        cve_number = str(cve_number).strip().upper()
        product_label = str(product or vendor or "未知组件")
        version_label = str(version or "未知版本")
        key = (cve_number, product_label.lower(), version_label.lower())

        existing = grouped.get(key)
        if existing:
            existing["locations"] = list(
                dict.fromkeys(existing["locations"] + locations)
            )
            continue

        score = _first_value(record, "score", "cvss_score")
        cvss_version = _first_value(record, "cvss_version")
        vulnerability = {
            "type": "组件漏洞",
            "risk_level": _normalize_severity(
                _first_value(record, "severity", "risk_level"),
                score,
            ),
            "confirmed": True,
            "url": target,
            "test_url": target,
            "cve_id": cve_number,
            "component": product_label,
            "vendor": vendor,
            "version": version_label,
            "locations": locations,
            "cvss_score": score,
            "cvss_version": cvss_version,
            "cvss_vector": _first_value(record, "cvss_vector"),
            "description": _first_value(
                record,
                "description",
                "comments",
                "remarks",
            ),
            "source": _first_value(record, "source"),
            "detection_method": "cve-bin-tool",
            "evidence": _build_evidence(record),
        }
        grouped[key] = vulnerability

    return list(grouped.values())


def _validate_target(target):
    if not target:
        raise CVEScanError("缺少本地扫描目标")

    resolved = os.path.abspath(os.path.expanduser(str(target)))
    if not os.path.exists(resolved):
        raise CVEScanError(f"CVE 扫描目标不存在：{resolved}")
    return resolved


def is_http_url(target):
    """Return whether a CVE source uses an HTTP(S) URL."""
    if not target:
        return False
    return urlparse(str(target)).scheme.lower() in {"http", "https"}


def _resolve_tool(tool_path):
    if not tool_path:
        raise CVEScanError("未配置 cve-bin-tool 路径")

    expanded = os.path.expanduser(str(tool_path))
    if os.path.isfile(expanded):
        return os.path.abspath(expanded)

    resolved = shutil.which(expanded)
    if resolved:
        return resolved

    raise CVEScanError(
        "未找到 cve-bin-tool。\n"
        f"官方仓库：{CVE_BIN_TOOL_GITHUB_URL}\n"
        f"GitHub下载：{CVE_BIN_TOOL_RELEASES_URL}\n"
        "推荐安装：python -m pip install cve-bin-tool\n"
        "GitHub安装：python -m pip install "
        "\"git+https://github.com/ossf/cve-bin-tool.git\"\n"
        "也可下载后通过 --cve-bin-tool-path 指定可执行文件。"
    )


def build_cve_command(executable, target, report_path, offline=False):
    """Build a shell-free cve-bin-tool command."""
    command = [
        executable,
        target,
        "-f",
        "json",
        "-o",
        report_path,
        "--detailed",
        "--disable-version-check",
        "--no-0-cve-report",
    ]
    if offline:
        command.append("--offline")
    return command


def _load_report(report_path, stdout):
    if report_path.exists() and report_path.stat().st_size > 0:
        try:
            return json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CVEScanError(f"无法解析 cve-bin-tool JSON 报告：{exc}") from exc

    stripped = (stdout or "").strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise CVEScanError(f"无法解析 cve-bin-tool 输出：{exc}") from exc
    return []


def scan_cve_target(
    target,
    tool_path="cve-bin-tool",
    offline=False,
    display_target=None,
):
    """Run cve-bin-tool locally and return normalized component findings."""
    resolved_target = _validate_target(target)
    executable = _resolve_tool(tool_path)

    with tempfile.TemporaryDirectory(prefix="camellia-cve-") as temp_dir:
        report_path = Path(temp_dir) / "cve-report.json"
        command = build_cve_command(
            executable,
            resolved_target,
            str(report_path),
            offline=offline,
        )

        try:
            # 使用参数列表且不启用 shell，避免目标路径被解释为系统命令。
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except OSError as exc:
            raise CVEScanError(f"无法启动 cve-bin-tool：{exc}") from exc

        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            if len(detail) > 800:
                detail = detail[-800:]
            suffix = f"：{detail}" if detail else ""
            raise CVEScanError(
                f"cve-bin-tool 执行失败，退出码 {completed.returncode}{suffix}"
            )

        data = _load_report(report_path, completed.stdout)
        return convert_cve_records(
            data,
            str(display_target or resolved_target),
        )


def _download_filename(url, content_type):
    parsed = urlparse(url)
    filename = unquote(Path(parsed.path).name)
    filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", filename).strip(" .")
    if not filename:
        filename = "download"
    if len(filename) > 120:
        filename = filename[-120:]

    if not Path(filename).suffix:
        mime_type = (content_type or "").split(";", 1)[0].strip().lower()
        extensions = {
            "application/json": ".json",
            "application/xml": ".xml",
            "text/xml": ".xml",
            "text/csv": ".csv",
            "text/plain": ".txt",
            "application/zip": ".zip",
            "application/java-archive": ".jar",
            "application/x-gzip": ".gz",
            "application/gzip": ".gz",
        }
        filename += extensions.get(mime_type, ".bin")
    return filename


def scan_cve_url(
    url,
    tool_path="cve-bin-tool",
    offline=False,
    headers=None,
    proxy=None,
    timeout=15,
    retries=3,
    max_download_bytes=200 * 1024 * 1024,
):
    """Download one HTTP(S) artifact to a temporary file and scan it locally."""
    if not is_http_url(url):
        raise CVEScanError(f"不是有效的HTTP(S) URL：{url}")

    # 缺少扫描器时先报错，避免无意义地下载远程文件。
    _resolve_tool(tool_path)

    from .network import request_with_retry

    request_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/74.0.3729.108 Safari/537.36"
        )
    }
    request_headers.update(headers or {})
    response = request_with_retry(
        url,
        request_headers,
        timeout,
        proxy,
        retries,
    )
    if response is None:
        raise CVEScanError(f"无法下载CVE扫描目标：{url}")
    if response.status_code >= 400:
        raise CVEScanError(
            f"下载CVE扫描目标失败，HTTP状态码 {response.status_code}：{url}"
        )

    content = response.content
    if not content:
        raise CVEScanError(f"下载的CVE扫描目标为空：{url}")
    if max_download_bytes and len(content) > max_download_bytes:
        limit_mb = max_download_bytes // (1024 * 1024)
        raise CVEScanError(
            f"URL目标超过下载上限 {limit_mb} MB，请提高 "
            "--cve-max-download-mb 或改用本地文件"
        )

    with tempfile.TemporaryDirectory(prefix="camellia-cve-url-") as temp_dir:
        filename = _download_filename(
            url,
            response.headers.get("Content-Type", ""),
        )
        local_target = Path(temp_dir) / filename
        local_target.write_bytes(content)
        vulnerabilities = scan_cve_target(
            str(local_target),
            tool_path=tool_path,
            offline=offline,
            display_target=url,
        )

        local_prefix = str(local_target)
        for vulnerability in vulnerabilities:
            locations = vulnerability.get("locations") or []
            vulnerability["locations"] = [
                (
                    url
                    if str(location) == local_prefix
                    else str(location).replace(local_prefix, url)
                )
                for location in locations
            ]
        return vulnerabilities


def scan_cve_source(
    source,
    tool_path="cve-bin-tool",
    offline=False,
    headers=None,
    proxy=None,
    timeout=15,
    retries=3,
    max_download_bytes=200 * 1024 * 1024,
):
    """Scan a local CVE source or one downloadable HTTP(S) artifact."""
    if is_http_url(source):
        return scan_cve_url(
            source,
            tool_path=tool_path,
            offline=offline,
            headers=headers,
            proxy=proxy,
            timeout=timeout,
            retries=retries,
            max_download_bytes=max_download_bytes,
        )
    return scan_cve_target(
        source,
        tool_path=tool_path,
        offline=offline,
    )
