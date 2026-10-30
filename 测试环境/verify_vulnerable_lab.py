"""Start the Node.js lab and verify the Camellia detectors end to end."""

import argparse
import contextlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests


LAB_DIR = Path(__file__).resolve().parent
PROJECT_DIR = LAB_DIR.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

import camellia as sql  # noqa: E402


def reserve_local_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def start_lab():
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Node.js was not found in PATH")

    port = reserve_local_port()
    env = os.environ.copy()
    env["NODE_NO_WARNINGS"] = "1"
    process = subprocess.Popen(
        [node, "server.js", "--port", str(port)],
        cwd=LAB_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            detail = (process.stderr.read() or "").strip()
            raise RuntimeError(
                f"Node.js lab exited with code {process.returncode}: {detail}"
            )
        try:
            response = requests.get(f"{base_url}/healthz", timeout=0.3)
            if response.status_code == 200 and response.text == "ok":
                return process, base_url
        except requests.RequestException:
            pass
        time.sleep(0.1)

    process.terminate()
    raise RuntimeError("Timed out waiting for the Node.js lab to become ready")


def stop_lab(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def make_args():
    return argparse.Namespace(
        cookie=None,
        threads=1,
        timeout=1,
        retries=1,
        proxy=None,
        fast_mode=True,
        smart_param_discovery=False,
        concat_param_detection=False,
        param_similarity_threshold=0,
        custom_param_wordlist=None,
        max_param_combinations=3,
        enable_param_variants=False,
        detect_hidden_params=False,
        param_encoding_test=False,
        waf_bypass=False,
        custom_sql=None,
        custom_xss=None,
        verbose=False,
        verify_injection=False,
        auto_sqlmap=False,
        continue_after_found=False,
        sql_delay=1,
        sql_scan=True,
        xss_scan=False,
        vuln_scan=False,
        advanced_sql=False,
        enhanced_xss=False,
        path_traversal_scan=False,
        file_inclusion_scan=False,
        command_injection_scan=False,
        weak_password_scan=False,
        sql_type="all",
        sql_threads=1,
        sql_level=1,
        multi_target=False,
        no_color=True,
    )


def quiet_call(function, *function_args):
    output = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        result = function(*function_args)
    return result, output.getvalue()


def run_detector(checks, name, function, url):
    vulnerabilities, output = quiet_call(function, url)
    detail = ""
    if vulnerabilities:
        first = vulnerabilities[0]
        detail = (
            f"parameter={first.get('parameter', '-')} "
            f"payload={first.get('payload', '-')}"
        )
    elif output.strip():
        detail = output.strip().splitlines()[-1][:140]
    checks.append((name, bool(vulnerabilities), len(vulnerabilities), detail))


def run_boolean_check(base_url):
    target = f"{base_url}/catalog"
    true_payload = "fiction' AND 1=1--"
    false_payload = "fiction' AND 1=2--"
    true_response = requests.get(
        target,
        params={"genre": true_payload},
        timeout=2,
    )
    false_response = requests.get(
        target,
        params={"genre": false_payload},
        timeout=2,
    )
    true_body = true_response.text
    false_body = false_response.text
    passed = (
        true_response.status_code == 200
        and false_response.status_code == 200
        and "The Quiet Harbor" in true_body
        and "The Quiet Harbor" not in false_body
        and abs(len(true_body) - len(false_body)) > 100
    )
    detail = (
        f"status={true_response.status_code}/{false_response.status_code} "
        f"length={len(true_body)}/{len(false_body)}"
    )
    return ("SQL boolean differential", passed, int(passed), detail)


def run_safe_page_checks(base_url):
    safe_url = (
        f"{base_url}/about?"
        "id=1&q=test&genre=fiction&file=guide.txt&"
        "page=home&host=127.0.0.1&username=admin"
    )
    functions = (
        sql.test_sql_injection,
        sql.test_xss_vulnerability,
        sql.test_path_traversal,
        sql.test_file_inclusion,
        sql.test_command_injection,
        sql.test_weak_passwords,
    )
    counts = []
    for function in functions:
        vulnerabilities, _ = quiet_call(function, safe_url)
        counts.append(len(vulnerabilities))
    passed = sum(counts) == 0
    return (
        "Safe-page false-positive check",
        passed,
        sum(counts),
        f"counts={counts}",
    )


def run_cli_weak_password_check(base_url):
    with tempfile.TemporaryDirectory(prefix="camellia-lab-") as temp_dir:
        report_path = Path(temp_dir) / "report.json"
        command = [
            sys.executable,
            str(PROJECT_DIR / "camellia.py"),
            "-u",
            f"{base_url}/login",
            "--weak-password-scan",
            "--fast-mode",
            "--no-color",
            "--timeout",
            "1",
            "--retries",
            "1",
            "-t",
            "1",
            "-oj",
            str(report_path),
        ]
        completed = subprocess.run(
            command,
            cwd=PROJECT_DIR,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        if completed.returncode != 0 or not report_path.exists():
            detail = (completed.stderr or completed.stdout or "").strip()
            return (
                "CLI weak-password path",
                False,
                0,
                f"exit={completed.returncode} {detail[-180:]}",
            )

        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            return (
                "CLI weak-password path",
                False,
                0,
                f"invalid report: {type(error).__name__}",
            )

        findings = report.get("vulnerabilities") or []
        credential = findings[0].get("payload", "-") if findings else "-"
        return (
            "CLI weak-password path",
            bool(findings),
            len(findings),
            f"findings={len(findings)} credential={credential}",
        )


def run_checks(base_url):
    args = make_args()
    sql.set_args(args)
    checks = []

    run_detector(
        checks,
        "SQL error injection",
        sql.test_sql_injection,
        f"{base_url}/catalog?genre=fiction",
    )
    checks.append(run_boolean_check(base_url))
    run_detector(
        checks,
        "Reflected XSS",
        sql.test_xss_vulnerability,
        f"{base_url}/search?q=books",
    )
    run_detector(
        checks,
        "Directory traversal",
        sql.test_path_traversal,
        f"{base_url}/download?file=guide.txt",
    )
    run_detector(
        checks,
        "Local file inclusion",
        sql.test_file_inclusion,
        f"{base_url}/download?file=guide.txt",
    )
    run_detector(
        checks,
        "Command-string injection",
        sql.test_command_injection,
        f"{base_url}/status/host?host=127.0.0.1",
    )
    run_detector(
        checks,
        "Default weak password",
        sql.test_weak_passwords,
        f"{base_url}/login",
    )
    checks.append(run_safe_page_checks(base_url))
    checks.append(run_cli_weak_password_check(base_url))
    return checks


def main():
    parser = argparse.ArgumentParser(
        description="Verify Camellia against the local Node.js bookstore lab"
    )
    parser.parse_args()

    process = None
    try:
        process, base_url = start_lab()
        print("=" * 78)
        print("Camellia / Northstar Books end-to-end verification")
        print(f"Lab URL: {base_url}")
        print("=" * 78)
        checks = run_checks(base_url)
    finally:
        if process is not None:
            stop_lab(process)

    print(f"{'RESULT':<9}{'CHECK':<30}{'COUNT':<8}DETAIL")
    print("-" * 78)
    normalized = []
    for name, passed, count, detail in checks:
        normalized.append((name, passed, count, detail))
        status = "PASS" if passed else "FAIL"
        print(f"{status:<9}{name:<30}{count:<8}{detail}")
    print("-" * 78)

    passed_count = sum(1 for _, passed, _, _ in normalized if passed)
    print(f"Summary: {passed_count}/{len(normalized)} checks passed")
    if passed_count != len(normalized):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
