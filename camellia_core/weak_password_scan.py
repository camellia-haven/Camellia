"""Controlled default-credential checks for POST login forms."""

import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from . import runtime
from .runtime import (
    print_info,
    print_verbose,
    print_vulnerability,
    print_warning,
    tagged_output,
)


args = None

DEFAULT_CREDENTIALS = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("test", "test"),
)

FAILURE_PATTERN = re.compile(
    r"登录失败|用户名或密码|账号或密码|密码错误|认证失败|凭据无效|"
    r"invalid\s+(?:username|password|credentials)|"
    r"incorrect\s+(?:username|password)|login\s+failed|"
    r"authentication\s+failed|access\s+denied|unauthorized",
    re.IGNORECASE,
)

SUCCESS_PATTERN = re.compile(
    r"退出登录|注销登录|退出系统|控制台|管理后台|欢迎回来|"
    r"sign\s*out|log\s*out|logout|dashboard|welcome\s+back",
    re.IGNORECASE,
)


def _request_options():
    timeout = max(0.1, float(getattr(args, "timeout", 3)))
    proxy = getattr(args, "proxy", None)
    proxies = {"http": proxy, "https": proxy} if proxy else None
    return timeout, proxies


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


def _session_request(session, method, url, header, timeout, proxies, data=None):
    kwargs = {
        "headers": header,
        "timeout": timeout,
        "verify": False,
        "allow_redirects": True,
    }
    if proxies:
        kwargs["proxies"] = proxies
    if method.upper() == "POST":
        kwargs["data"] = data or {}
    return session.request(method, url, **kwargs)


def _same_origin(reference_url, candidate_url):
    reference = urlparse(reference_url)
    candidate = urlparse(candidate_url)
    return (
        reference.scheme.lower(),
        reference.netloc.lower(),
    ) == (
        candidate.scheme.lower(),
        candidate.netloc.lower(),
    )


def _input_type(field):
    return (field.get("type") or "text").strip().lower()


def _find_username_field(form, password_field):
    candidates = []
    for field in form.find_all(["input", "textarea"]):
        field_type = _input_type(field)
        if field in (password_field, None):
            continue
        if field_type in {"hidden", "password", "submit", "button", "reset"}:
            continue
        name = (field.get("name") or "").strip()
        if name:
            candidates.append(field)

    preferred_markers = ("user", "email", "login", "account", "name")
    for field in candidates:
        identity = " ".join(
            (
                field.get("name") or "",
                field.get("id") or "",
                field.get("autocomplete") or "",
            )
        ).lower()
        if any(marker in identity for marker in preferred_markers):
            return field
    return candidates[0] if candidates else None


def _find_login_forms(html, page_url, reference_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        password_field = next(
            (
                field
                for field in form.find_all("input")
                if _input_type(field) == "password"
            ),
            None,
        )
        if password_field is None:
            continue

        method = (form.get("method") or "get").strip().upper()
        if method != "POST":
            continue

        username_field = _find_username_field(form, password_field)
        if username_field is None:
            continue

        action_url = urljoin(page_url, form.get("action") or page_url)
        if not _same_origin(reference_url, action_url):
            continue

        hidden_fields = {}
        submit_fields = {}
        for field in form.find_all(["input", "button"]):
            name = (field.get("name") or "").strip()
            if not name:
                continue
            field_type = _input_type(field)
            value = field.get("value") or ""
            if field_type == "hidden":
                hidden_fields[name] = value
            elif field_type in {"submit", "button"} and name not in submit_fields:
                submit_fields[name] = value

        forms.append(
            {
                "action": action_url,
                "username_field": username_field.get("name"),
                "password_field": password_field.get("name"),
                "hidden_fields": hidden_fields,
                "submit_fields": submit_fields,
            }
        )
    return forms


def _has_password_field(html):
    return bool(
        re.search(
            r"<input\b[^>]*\btype\s*=\s*[\"']?password\b",
            html,
            re.IGNORECASE,
        )
    )


def _success_evidence(response, login_page_url):
    content = response.text or ""
    if response.status_code in {401, 403}:
        return None
    if _has_password_field(content) or FAILURE_PATTERN.search(content):
        return None

    success_match = SUCCESS_PATTERN.search(content)
    if success_match:
        start = max(0, success_match.start() - 40)
        end = min(len(content), success_match.end() + 80)
        evidence = " ".join(content[start:end].split())
        return evidence[:180]

    final_url = urlparse(response.url)
    page_url = urlparse(login_page_url)
    final_path = final_url.path.rstrip("/").lower()
    page_path = page_url.path.rstrip("/").lower()
    login_words = ("login", "signin", "sign-in", "auth")
    if (
        response.history
        and _same_origin(login_page_url, response.url)
        and final_path != page_path
        and not any(word in final_path for word in login_words)
    ):
        return f"登录后重定向: {final_url.path or '/'}"
    return None


def _credentials_for_scan():
    if getattr(args, "fast_mode", False):
        return DEFAULT_CREDENTIALS[:3]
    return DEFAULT_CREDENTIALS


@tagged_output("弱口令")
def test_weak_passwords(url):
    """Test a small fixed set of default credentials against POST login forms."""
    vulnerabilities = []
    print_info("开始弱口令检测（仅测试内置默认凭据）")
    header = _build_header()
    timeout, proxies = _request_options()

    try:
        with requests.Session() as discovery_session:
            discovery_response = _session_request(
                discovery_session,
                "GET",
                url,
                header,
                timeout,
                proxies,
            )
    except requests.RequestException as exc:
        if getattr(args, "verbose", False):
            print_verbose(f"登录页面请求失败：{type(exc).__name__}")
        return vulnerabilities

    forms = _find_login_forms(
        discovery_response.text or "",
        discovery_response.url,
        discovery_response.url,
    )
    if not forms:
        print_verbose("未发现可测试的POST登录表单")
        return vulnerabilities

    for username, password in _credentials_for_scan():
        if runtime.should_stop():
            print_warning("收到中断信号，停止弱口令检测")
            break

        with requests.Session() as session:
            try:
                login_response = _session_request(
                    session,
                    "GET",
                    url,
                    header,
                    timeout,
                    proxies,
                )
                current_forms = _find_login_forms(
                    login_response.text or "",
                    login_response.url,
                    login_response.url,
                )
                if not current_forms:
                    break

                form = current_forms[0]
                # 保留 CSRF token 等隐藏字段，否则登录请求可能被服务端拒绝。
                form_data = dict(form["hidden_fields"])
                form_data.update(form["submit_fields"])
                form_data[form["username_field"]] = username
                form_data[form["password_field"]] = password

                response = _session_request(
                    session,
                    "POST",
                    form["action"],
                    header,
                    timeout,
                    proxies,
                    data=form_data,
                )
            except requests.RequestException as exc:
                if getattr(args, "verbose", False):
                    print_verbose(f"登录请求失败：{type(exc).__name__}")
                continue

        evidence = _success_evidence(response, login_response.url)
        if not evidence:
            continue

        vulnerability = {
            "type": "弱口令",
            "url": url,
            "parameter": (
                f"{form['username_field']} / {form['password_field']}"
            ),
            "payload": f"{username} / {password}",
            "test_url": form["action"],
            "risk_level": "严重",
            "confirmed": True,
            "auto_verified": True,
            "description": (
                "登录表单接受了内置默认凭据，请立即修改密码并检查登录策略。"
            ),
            "evidence": evidence,
        }
        vulnerabilities.append(vulnerability)
        print_vulnerability(vulnerability)
        break

    if not vulnerabilities:
        print_verbose("未发现内置默认弱口令")
    return vulnerabilities
