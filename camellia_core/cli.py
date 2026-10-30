"""CLI orchestration, endpoint testing, and report output."""

import concurrent.futures
import json
import sys
import urllib3
from datetime import datetime

from . import core as sql_core
from . import command_scan as sql_command_scan
from . import cve_scan as sql_cve_scan
from . import file_scan as sql_file_scan
from . import network as sql_network
from . import runtime
from . import scan as sql_scan
from . import weak_password_scan as sql_weak_password_scan
from . import xss as sql_xss
from tqdm import tqdm

from .args import parse_args, validate_arguments
from .core import AdvancedSQLInjector, ThreadedSQLInjector, advanced_sql_injection_test
from .network import (
    detect_sensitive_info,
    display_cookies,
    find_by_file,
    find_by_url,
    find_by_url_deep,
    find_subdomain,
    get_website_cookies,
    is_api_url,
    print_sensitive_findings,
    request_with_retry,
    scan_admin_pages,
)
from .runtime import (
    print_banner,
    print_cool,
    print_debug,
    print_error,
    print_info,
    print_legal_warning,
    print_success,
    print_verbose,
    print_warning,
)
from .scan import test_sql_injection
from .xss import test_xss_vulnerability


args = None
stop_scanning = False
CVE_SCAN_CANCELLED = object()


def configure_runtime_args(value):
    global args
    args = value
    runtime.configure_output(
        getattr(value, "no_color", False),
        getattr(value, "verbose", False),
    )
    sql_core.args = value
    sql_command_scan.args = value
    sql_file_scan.args = value
    sql_network.args = value
    sql_scan.args = value
    sql_weak_password_scan.args = value
    sql_xss.args = value


def test_endpoints(urls):
    global args

    results = []
    all_findings = []
    all_vulnerabilities = []
    seen_values = set()

    api_urls = [url for url in urls if is_api_url(url)]
    print_info(
        f"正在扫描 {len(api_urls)} 个URL"
        f"（工作线程：{args.threads}）"
    )

    def process_url(url):
        try:
            header = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36"
            }
            if args.cookie:
                header["Cookie"] = args.cookie
            response = request_with_retry(url, header, args.timeout, args.proxy, args.retries)

            result = {
                "url": url,
                "status_code": 0,
                "content_length": 0,
                "findings": [],
                "vulnerabilities": []
            }

            if response:
                content = response.content.decode("utf-8", "ignore")
                result["status_code"] = response.status_code
                result["content_length"] = len(content)

                # 检测敏感信息
                findings = detect_sensitive_info(content, url)
                if findings:
                    # 过滤重复的发现
                    new_findings = []
                    for finding in findings:
                        if finding['value'] not in seen_values:
                            seen_values.add(finding['value'])
                            new_findings.append(finding)
                            all_findings.append(finding)

                    result["findings"] = new_findings
                    if new_findings:
                        print_sensitive_findings(new_findings)

                # 漏洞扫描 - 传统SQL注入检测 (优化版)
                if args.sql_scan or args.vuln_scan or args.advanced_sql:
                    sql_vulns = test_sql_injection(url)
                    result["vulnerabilities"].extend(sql_vulns)
                    all_vulnerabilities.extend(sql_vulns)
                    if sql_vulns:
                        print_verbose(
                            f"{url} 的SQL注入发现：{len(sql_vulns)} 个"
                        )

                # 高级SQL注入检测（基于sqli-detector逻辑）
                if args.advanced_sql or args.vuln_scan:
                    advanced_sql_vulns = advanced_sql_injection_test(url, header)
                    result["vulnerabilities"].extend(advanced_sql_vulns)
                    all_vulnerabilities.extend(advanced_sql_vulns)
                    if advanced_sql_vulns:
                        print_verbose(
                            f"{url} 的高级SQL注入发现："
                            f"{len(advanced_sql_vulns)} 个"
                        )

                    # 新增：来自hama_sqlnb.py的高级SQL注入检测
                    if args.advanced_sql or args.vuln_scan:
                        try:

                            injection_types = []
                            if args.sql_type == "all":
                                injection_types = ["boolean", "time", "error", "union"]
                            else:
                                injection_types = [args.sql_type]

                            # 单URL检测
                            if not args.multi_target:
                                for injection_type in injection_types:
                                    advanced_injector = AdvancedSQLInjector(
                                        url=url,
                                        threads=args.sql_threads,
                                        timeout=args.timeout,
                                        proxy=args.proxy,
                                        verbose=args.verbose,
                                        injection_type=injection_type,
                                        delay_threshold=args.sql_delay,
                                        level=args.sql_level
                                    )

                                    master_vulns = advanced_injector.run_detection()
                                    if master_vulns:
                                        result["vulnerabilities"].extend(master_vulns)
                                        all_vulnerabilities.extend(master_vulns)
                                        print_verbose(
                                            f"{url} 的高级SQL注入发现："
                                            f"{len(master_vulns)} 个"
                                        )

                        except Exception as e:
                            if args.verbose:
                                print_error(
                                    f"{url} 的高级SQL扫描失败："
                                    f"{type(e).__name__}"
                                )

                if args.xss_scan or args.vuln_scan:
                    xss_vulns = test_xss_vulnerability(url)
                    result["vulnerabilities"].extend(xss_vulns)
                    all_vulnerabilities.extend(xss_vulns)

                if args.path_traversal_scan or args.vuln_scan:
                    traversal_vulns = sql_file_scan.test_path_traversal(url)
                    result["vulnerabilities"].extend(traversal_vulns)
                    all_vulnerabilities.extend(traversal_vulns)

                if args.file_inclusion_scan or args.vuln_scan:
                    inclusion_vulns = sql_file_scan.test_file_inclusion(url)
                    result["vulnerabilities"].extend(inclusion_vulns)
                    all_vulnerabilities.extend(inclusion_vulns)

                if args.command_injection_scan or args.vuln_scan:
                    command_vulns = sql_command_scan.test_command_injection(url)
                    result["vulnerabilities"].extend(command_vulns)
                    all_vulnerabilities.extend(command_vulns)

                if args.weak_password_scan or args.vuln_scan:
                    weak_password_vulns = (
                        sql_weak_password_scan.test_weak_passwords(url)
                    )
                    result["vulnerabilities"].extend(weak_password_vulns)
                    all_vulnerabilities.extend(weak_password_vulns)

            return result

        except Exception as e:
            print_error(f"扫描 {url} 失败：{type(e).__name__}")
            return None

    # 使用线程池进行并发扫描
    tqdm.set_lock(runtime.output_lock)
    with tqdm(
        total=len(api_urls),
        desc="扫描",
        unit="个URL",
        file=sys.stdout,
        leave=False,
        dynamic_ncols=True,
    ) as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:

            future_to_url = {executor.submit(process_url, url): url for url in api_urls}


            for future in concurrent.futures.as_completed(future_to_url):
                # 检查是否需要停止扫描
                if runtime.should_stop():
                    print_warning("收到中断信号，正在取消剩余任务")
                    for remaining_future in future_to_url:
                        remaining_future.cancel()
                    break

                url = future_to_url[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    print_error(f"扫描 {url} 失败：{type(e).__name__}")
                pbar.update(1)

    if all_vulnerabilities:
        print_success(
            f"漏洞扫描完成：发现 {len(all_vulnerabilities)} 个问题"
        )
    else:
        print_info("漏洞扫描完成：未发现问题")

    return results, all_findings, all_vulnerabilities

def save_results(urls, subdomains, findings, vulnerabilities, admin_pages):
    """保存所有扫描结果"""
    global args

    # 保存URL结果
    if args.outputurl and urls:
        try:
            with open(args.outputurl, 'w', encoding='utf-8') as f:
                for url in urls:
                    f.write(url + '\n')
            print_success(f"URL结果已保存到 {args.outputurl}")
        except Exception as e:
            print_error("无法写入URL结果文件")

    # 保存子域名结果
    if args.outputsubdomain and subdomains:
        try:
            with open(args.outputsubdomain, 'w', encoding='utf-8') as f:
                for subdomain in subdomains:
                    f.write(subdomain + '\n')
            print_success(f"子域名结果已保存到 {args.outputsubdomain}")
        except Exception as e:
            print_error("无法写入子域名结果文件")

    # 保存JSON格式结果
    if args.outputjson:
        try:
            json_data = {
                "scan_time": datetime.now().isoformat(),
                "target": args.url,
                "urls": urls,
                "subdomains": subdomains,
                "sensitive_findings": findings,
                "vulnerabilities": vulnerabilities,
                "admin_pages": admin_pages,
                "statistics": {
                    "total_urls": len(urls),
                    "total_subdomains": len(subdomains),
                    "total_findings": len(findings),
                    "total_vulnerabilities": len(vulnerabilities),
                    "total_admin_pages": len(admin_pages)
                }
            }

            with open(args.outputjson, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, ensure_ascii=False, indent=2)
            print_success(f"JSON结果已保存到 {args.outputjson}")
        except Exception as e:
            print_error("无法写入JSON结果文件")


    if args.outputvuln and (vulnerabilities or findings):
        try:
            with open(args.outputvuln, 'w', encoding='utf-8') as f:
                f.write("Camellia 漏洞报告\n")
                f.write(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"目标: {args.url}\n")
                f.write("=" * 80 + "\n\n")


                if vulnerabilities:
                    f.write("漏洞:\n")
                    f.write("-" * 40 + "\n")
                    for vuln in vulnerabilities:
                        f.write(
                            f"类型: {runtime.display_text(vuln['type'])}\n"
                        )
                        f.write(
                            "风险: "
                            f"{runtime.display_text(vuln['risk_level'])}\n"
                        )
                        f.write(f"地址: {vuln['url']}\n")
                        f.write(f"参数: {vuln['parameter']}\n")
                        f.write(f"载荷: {vuln['payload']}\n")
                        f.write(
                            "证据: "
                            f"{runtime.display_text(vuln['evidence'])}\n"
                        )
                        f.write("-" * 40 + "\n")


                if findings:
                    f.write("\n敏感信息:\n")
                    f.write("-" * 40 + "\n")
                    for finding in findings:
                        f.write(
                            f"类型: {runtime.display_text(finding['type'])}\n"
                        )
                        f.write(f"地址: {finding['url']}\n")
                        f.write(f"内容: {finding['value']}\n")
                        f.write("-" * 40 + "\n")

            print_success(f"漏洞报告已保存到 {args.outputvuln}")
        except Exception as e:
            print_error("无法写入漏洞报告")


def save_cve_results(vulnerabilities, target):
    """Save CVE findings without depending on web-scan result fields."""
    global args

    if args.outputjson:
        severity_counts = {}
        for vulnerability in vulnerabilities:
            risk_level = vulnerability.get("risk_level", "未知")
            severity_counts[risk_level] = severity_counts.get(risk_level, 0) + 1

        json_data = {
            "scan_time": datetime.now().isoformat(),
            "mode": "cve",
            "target": target,
            "vulnerabilities": vulnerabilities,
            "statistics": {
                "total_vulnerabilities": len(vulnerabilities),
                "by_severity": severity_counts,
            },
        }
        try:
            with open(args.outputjson, "w", encoding="utf-8") as report_file:
                json.dump(json_data, report_file, ensure_ascii=False, indent=2)
            print_success(f"JSON结果已保存到 {args.outputjson}")
        except OSError:
            print_error("无法写入JSON结果文件")

    if args.outputvuln:
        try:
            with open(args.outputvuln, "w", encoding="utf-8") as report_file:
                report_file.write("Camellia CVE 组件漏洞报告\n")
                report_file.write(
                    "扫描时间: "
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                )
                report_file.write(f"目标: {target}\n")
                report_file.write("=" * 80 + "\n\n")

                if not vulnerabilities:
                    report_file.write("未发现已知组件漏洞。\n")
                for vulnerability in vulnerabilities:
                    report_file.write(
                        f"CVE编号: {vulnerability.get('cve_id', '-')}\n"
                    )
                    report_file.write(
                        f"风险: {runtime.display_text(vulnerability.get('risk_level'))}\n"
                    )
                    report_file.write(
                        f"组件: {vulnerability.get('component', '-')}\n"
                    )
                    report_file.write(
                        f"版本: {vulnerability.get('version', '-')}\n"
                    )
                    report_file.write(
                        f"CVSS: {vulnerability.get('cvss_score', '-')}"
                    )
                    if vulnerability.get("cvss_version"):
                        report_file.write(
                            f"（CVSS {vulnerability['cvss_version']}）"
                        )
                    report_file.write("\n")
                    locations = vulnerability.get("locations") or []
                    if locations:
                        report_file.write(
                            "文件位置:\n"
                            + "\n".join(f"  - {item}" for item in locations)
                            + "\n"
                        )
                    if vulnerability.get("description"):
                        report_file.write(
                            f"说明: {vulnerability['description']}\n"
                        )
                    report_file.write(
                        f"检测方式: {vulnerability.get('detection_method', '-')}\n"
                    )
                    report_file.write("-" * 40 + "\n")

            print_success(f"漏洞报告已保存到 {args.outputvuln}")
        except OSError:
            print_error("无法写入漏洞报告")


def confirm_cve_url_scan(target, assume_yes=False):
    """Ask once for authorization before downloading a remote CVE artifact."""
    if assume_yes:
        print_info("已通过 --yes 确认授权，跳过交互确认")
        return True

    runtime.print_section(
        "授权确认",
        (
            ("扫描目标", target),
            ("扫描方式", "下载一个构件到临时目录后本地分析"),
        ),
    )
    print_warning("仅可扫描您拥有或已获得明确授权的目标，未经授权扫描可能违法。")
    print_info(
        "URL模式适合安装包、JAR、依赖锁文件或SBOM，不适合普通网页指纹扫描。"
    )
    print_info("下载的构件仅在本机分析，不会上传到第三方，也不会执行其中的内容。")

    try:
        answer = input("确认已获得合法授权并继续？[y/N]: ")
    except (EOFError, KeyboardInterrupt):
        answer = ""

    if answer.strip().lower() in {"y", "yes"}:
        print_success("已确认授权，继续CVE扫描")
        return True

    print_warning("未确认授权，已取消CVE扫描")
    return False


def run_cve_scan(scan_args):
    """Run a local CVE scan or a confirmed one-artifact URL download."""
    target = scan_args.cve_scan
    remote_source = sql_cve_scan.is_http_url(target)
    runtime.print_section(
        "CVE 组件扫描",
        (
            ("目标", target),
            ("来源", "远程文件下载" if remote_source else "本地路径"),
            ("检测工具", scan_args.cve_bin_tool_path),
            ("数据库", "仅本地" if scan_args.cve_offline else "允许联网更新"),
        ),
    )

    with runtime.output_tag("CVE"):
        if remote_source and not confirm_cve_url_scan(
            target,
            assume_yes=getattr(scan_args, "yes", False),
        ):
            return CVE_SCAN_CANCELLED

        print_info("扫描内容只在本机分析，不会上传目标文件")
        try:
            headers = {}
            if getattr(scan_args, "cookie", None):
                headers["Cookie"] = scan_args.cookie

            vulnerabilities = sql_cve_scan.scan_cve_source(
                target,
                tool_path=scan_args.cve_bin_tool_path,
                offline=scan_args.cve_offline,
                headers=headers,
                proxy=getattr(scan_args, "proxy", None),
                timeout=getattr(scan_args, "timeout", 15),
                retries=getattr(scan_args, "retries", 3),
                max_download_bytes=(
                    scan_args.cve_max_download_mb * 1024 * 1024
                ),
            )
        except sql_cve_scan.CVEScanError as exc:
            print_error(str(exc))
            return None
        except Exception as exc:
            print_error(f"CVE扫描失败：{type(exc).__name__}")
            if scan_args.verbose:
                print_debug(str(exc))
            return None

        for vulnerability in vulnerabilities:
            runtime.print_vulnerability(vulnerability)

        if vulnerabilities:
            print_success(f"发现 {len(vulnerabilities)} 个组件漏洞")
        else:
            print_info("未发现已知组件漏洞")

    runtime.print_summary(
        "CVE 扫描摘要",
        (
            ("组件漏洞", len(vulnerabilities)),
            ("扫描目标", target),
        ),
    )
    save_cve_results(vulnerabilities, target)
    print_success("CVE 扫描完成")
    return vulnerabilities


def print_scan_statistics(urls, subdomains, findings, vulnerabilities, admin_pages):
    """Print the final scan totals in a compact aligned layout."""
    runtime.print_summary(
        "扫描摘要",
        (
            ("URL数量", len(urls)),
            ("子域名", len(subdomains)),
            ("发现", len(findings)),
            ("漏洞", len(vulnerabilities)),
            ("后台页面", len(admin_pages)),
        ),
    )

    if findings:
        findings_by_type = {}
        for finding in findings:
            finding_type = finding["type"]
            findings_by_type[finding_type] = findings_by_type.get(finding_type, 0) + 1

        runtime.print_section("敏感信息")
        for finding_type, count in findings_by_type.items():
            runtime.print_kv(runtime.display_text(finding_type), count)

    if vulnerabilities:
        vulnerabilities_by_type = {}
        for vulnerability in vulnerabilities:
            vulnerability_type = vulnerability["type"]
            vulnerabilities_by_type[vulnerability_type] = (
                vulnerabilities_by_type.get(vulnerability_type, 0) + 1
            )

        runtime.print_section("按类型统计的漏洞")
        for vulnerability_type, count in vulnerabilities_by_type.items():
            runtime.print_kv(
                runtime.display_text(vulnerability_type),
                count,
            )


def main():
    global args

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # argparse 会在 --help 时直接退出，因此先展示 Camellia 横幅。
    if any(argument in ("-h", "--help") for argument in sys.argv[1:]):
        print_banner()

    args = parse_args()
    configure_runtime_args(args)

    validate_arguments(args)

    # CVE 扫描单独处理本地路径或经确认的单文件下载
    if args.cve_scan:
        print_banner()
        print_legal_warning()
        cve_result = run_cve_scan(args)
        if cve_result is CVE_SCAN_CANCELLED:
            return
        if cve_result is None:
            raise SystemExit(1)
        return

    if hasattr(args, 'get_cookies') and args.get_cookies:
        print_info(f"正在获取 {args.url} 的Cookie")
        cookies_info = get_website_cookies(args.url)
        display_cookies(cookies_info, args.url)
        return

    print_banner()
    print_legal_warning()

    runtime.print_section(
        "扫描配置",
        (
            ("目标", args.url),
            ("线程", args.threads),
            ("超时", f"{args.timeout}秒"),
        ),
    )

    urls = []
    subdomains = []
    all_findings = []
    all_vulnerabilities = []
    admin_pages = []

    try:
        if args.file:
            print_verbose("正在从文件加载目标")
            if args.js:
                urls = find_by_file(args.file, js=True)
            else:
                urls = find_by_file(args.file, js=False)
        else:
            if args.deep:
                print_verbose("已启用深度目标发现")
                urls = find_by_url_deep(args.url)
            else:
                print_verbose("已启用标准目标发现")
                urls = find_by_url(args.url, js=args.js)

        if urls is None:
            urls = []


        if not urls:
            print_warning("未发现可用URL")
            if (
                args.sql_scan
                or args.xss_scan
                or args.vuln_scan
                or args.advanced_sql
                or args.path_traversal_scan
                or args.file_inclusion_scan
                or args.command_injection_scan
                or args.weak_password_scan
            ):
                print_info("将扫描原始目标URL")
                urls = [args.url]
            else:
                print_error("没有可扫描的URL")
                return

        print_success(f"发现 {len(urls)} 个URL")


        subdomains = find_subdomain(urls, args.url)
        if subdomains:
            print_success(f"发现 {len(subdomains)} 个子域名")
            for subdomain in subdomains:
                print_verbose(f"子域名：{subdomain}")


        if args.admin_scan or args.vuln_scan:
            admin_pages = scan_admin_pages(args.url)


        if args.multi_target and args.advanced_sql:
            print_info("开始多目标高级SQL注入扫描")

            injection_types = []
            if args.sql_type == "all":
                injection_types = ["boolean", "time", "error", "union"]
            else:
                injection_types = [args.sql_type]


            threaded_injector = ThreadedSQLInjector(
                urls=urls,
                max_workers=args.sql_threads,
                timeout=args.timeout,
                proxy=args.proxy
            )

            multi_target_results = threaded_injector.run_threaded_scan(injection_types)

            for result in multi_target_results:
                all_vulnerabilities.extend(result['vulnerabilities'])

            print_success(
                "多目标SQL注入扫描完成；"
                f"发现 {len(all_vulnerabilities)} 个问题"
            )

        # 端点测试和漏洞扫描
        if (
            args.sql_scan
            or args.xss_scan
            or args.vuln_scan
            or args.path_traversal_scan
            or args.file_inclusion_scan
            or args.command_injection_scan
            or args.weak_password_scan
            or (args.advanced_sql and not args.multi_target)
        ):
            print_verbose("开始漏洞检测")
            results, endpoint_findings, endpoint_vulnerabilities = test_endpoints(urls)
            all_findings.extend(endpoint_findings)
            all_vulnerabilities.extend(endpoint_vulnerabilities)

        print_scan_statistics(
            urls,
            subdomains,
            all_findings,
            all_vulnerabilities,
            admin_pages,
        )

        save_results(urls, subdomains, all_findings, all_vulnerabilities, admin_pages)

        print_success("扫描完成")

    except KeyboardInterrupt:
        print_warning("收到中断信号，扫描已取消")
    except Exception as e:
        print_error(f"扫描失败：{type(e).__name__}")
        if args.verbose:
            # 简化错误信息显示，避免乱码
            error_msg = str(e).strip()
            if len(error_msg) > 200:
                error_msg = error_msg[:200] + "..."
            print_debug(f"详情：{error_msg}")
