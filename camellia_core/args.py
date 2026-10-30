"""Command-line argument parsing and validation."""

import argparse
import os
import sys

from .runtime import print_error, print_info, print_warning


_SCAN_MODE_ATTRIBUTES = (
    "admin_scan",
    "sql_scan",
    "xss_scan",
    "vuln_scan",
    "path_traversal_scan",
    "file_inclusion_scan",
    "command_injection_scan",
    "weak_password_scan",
    "advanced_sql",
)


def _apply_default_scan_mode(args):
    """Use the full read-only scan when no module was selected explicitly."""
    if not args.url or args.cve_scan or args.get_cookies:
        return args

    if not any(getattr(args, name, False) for name in _SCAN_MODE_ATTRIBUTES):
        args.vuln_scan = True

    return args


def _localize_argparse_text(text):
    replacements = (
        ("usage: ", "用法: "),
        ("options:", "选项:"),
        ("optional arguments:", "选项:"),
        ("positional arguments:", "位置参数:"),
        ("show this help message and exit", "显示帮助信息并退出"),
        ("the following arguments are required:", "缺少必需参数:"),
        ("unrecognized arguments:", "无法识别的参数:"),
        ("invalid choice:", "无效选项:"),
        ("invalid int value:", "无效整数:"),
        ("invalid float value:", "无效小数:"),
        ("expected one argument", "需要提供一个值"),
    )
    for source, target in replacements:
        text = text.replace(source, target)
    return text


class ChineseArgumentParser(argparse.ArgumentParser):
    """Localize argparse's built-in help and argument error headings."""

    def __init__(self, *args, **kwargs):
        kwargs["add_help"] = False
        super().__init__(*args, **kwargs)
        self.add_argument(
            "-h",
            "--help",
            action="help",
            help="显示帮助信息并退出",
        )

    def format_help(self):
        return _localize_argparse_text(super().format_help())

    def format_usage(self):
        return _localize_argparse_text(super().format_usage())

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(
            2,
            f"{self.prog}: 错误: {_localize_argparse_text(message)}\n",
        )


class ChineseHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Keep Chinese option descriptions aligned and easy to scan."""

    def __init__(self, prog):
        super().__init__(
            prog,
            width=100,
            max_help_position=32,
        )


def parse_args():
    parser = ChineseArgumentParser(
        description='Camellia - 授权Web漏洞扫描器',
        usage=(
            "camellia.py -u URL [扫描选项] | "
            "camellia.py --cve-scan 路径 [CVE选项]"
        ),
        formatter_class=ChineseHelpFormatter,
        epilog='''
示例:
  python camellia.py -u http://www.example.com
  python camellia.py -u http://www.example.com --sql-scan --xss-scan
  python camellia.py -u http://www.example.com --vuln-scan --auto-sqlmap
  python camellia.py -u http://www.example.com --advanced-sql --auto-sqlmap
  python camellia.py -f urls.txt -j --vuln-scan -t 10
  python camellia.py -u http://www.example.com/login --weak-password-scan
  python camellia.py --cve-scan ./application
  python camellia.py --cve-scan ./application --cve-offline -oj cve.json
  python camellia.py --cve-scan https://example.com/app.jar --yes
        '''
    )

    basic = parser.add_argument_group("基本目标")
    basic.add_argument("-u", "--url", help="目标URL")
    basic.add_argument("-c", "--cookie", help="HTTP Cookie 请求头")
    basic.add_argument(
        "--get-cookies",
        help="获取并显示目标Cookie",
        action="store_true",
    )
    basic.add_argument(
        "--yes",
        action="store_true",
        help="确认已获得授权，跳过远程扫描前的交互确认",
    )
    basic.add_argument("-f", "--file", help="包含URL或JavaScript的文件")

    local = parser.add_argument_group("本地组件漏洞（CVE）")
    local.add_argument(
        "--cve-scan",
        metavar="来源",
        help="扫描本地目录、文件、SBOM，或下载HTTP(S)文件后扫描",
    )
    local.add_argument(
        "--cve-bin-tool-path",
        default="cve-bin-tool",
        help="cve-bin-tool可执行文件路径（默认从PATH查找）",
    )
    local.add_argument(
        "--cve-offline",
        action="store_true",
        help="仅使用本地漏洞数据库，不联网更新",
    )
    local.add_argument(
        "--cve-max-download-mb",
        type=int,
        default=200,
        help="URL模式单个文件下载上限（默认：200 MB）",
    )

    discovery = parser.add_argument_group("目标发现与过滤")
    discovery.add_argument(
        "-j",
        "--js",
        help="搜索关联的JavaScript文件",
        action="store_true",
    )
    discovery.add_argument(
        "-d",
        "--deep",
        help="启用深度目标发现",
        action="store_true",
    )
    discovery.add_argument(
        "--filter-status",
        help="仅包含指定HTTP状态码，例如200,301,302",
        default="",
    )
    discovery.add_argument(
        "--exclude",
        help="排除匹配正则表达式的URL",
        default="",
    )
    discovery.add_argument(
        "--include",
        help="仅包含匹配正则表达式的URL",
        default="",
    )

    detection = parser.add_argument_group("漏洞检测")
    detection.add_argument(
        "--admin-scan",
        help="扫描后台管理页面",
        action="store_true",
    )
    detection.add_argument(
        "--sql-scan",
        help="启用SQL注入扫描",
        action="store_true",
    )
    detection.add_argument(
        "--xss-scan",
        help="启用反射型XSS扫描",
        action="store_true",
    )
    detection.add_argument(
        "--vuln-scan",
        help=(
            "全面扫描SQL、XSS、目录遍历、LFI、命令注入、"
            "弱口令和后台路径（未指定扫描模块时默认启用）"
        ),
        action="store_true",
    )
    detection.add_argument(
        "--path-traversal-scan",
        help="检测只读目录遍历漏洞",
        action="store_true",
    )
    detection.add_argument(
        "--file-inclusion-scan",
        help="检测只读本地文件包含漏洞",
        action="store_true",
    )
    detection.add_argument(
        "--command-injection-scan",
        help="使用固定的id命令检测命令注入",
        action="store_true",
    )
    detection.add_argument(
        "--weak-password-scan",
        help="测试登录表单中的少量内置默认口令",
        action="store_true",
    )
    detection.add_argument("--custom-admin", help="自定义后台路径字典")

    advanced = parser.add_argument_group("SQL高级扫描")
    advanced.add_argument(
        "--advanced-sql",
        help="启用基于响应差异的高级SQL注入扫描",
        action="store_true",
    )
    advanced.add_argument(
        "--sql-type",
        help="SQL注入类型：boolean、time、error、union或all",
        default="all",
    )
    advanced.add_argument(
        "--sql-threads",
        type=int,
        default=10,
        help="SQL注入工作线程数（默认：10）",
    )
    advanced.add_argument(
        "--sql-delay",
        type=int,
        default=5,
        help="基于时间的SQL注入延迟阈值（秒）",
    )
    advanced.add_argument(
        "--sql-level",
        type=int,
        default=1,
        help="SQL注入扫描等级，1-5",
    )
    advanced.add_argument(
        "--waf-bypass",
        help="启用WAF绕过载荷",
        action="store_true",
    )
    advanced.add_argument(
        "--multi-target",
        help="使用高级SQL检测扫描多个目标",
        action="store_true",
    )
    advanced.add_argument(
        "--auto-sqlmap",
        help="枚举数据库、当前用户和DBA权限，不导出数据",
        action="store_true",
    )
    advanced.add_argument(
        "--sqlmap-path",
        help="sqlmap可执行文件路径",
        default="sqlmap",
    )
    advanced.add_argument(
        "--sqlmap-options",
        help="附加sqlmap参数",
        default="--batch --threads=5",
    )
    advanced.add_argument("--custom-sql", help="自定义SQL注入载荷文件")

    tuning = parser.add_argument_group("XSS与验证增强")
    tuning.add_argument(
        "--enhanced-xss",
        help="启用上下文感知的XSS验证",
        action="store_true",
    )
    tuning.add_argument("--custom-xss", help="自定义XSS载荷文件")
    tuning.add_argument(
        "--verify-injection",
        help="使用高级验证确认注入结果",
        action="store_true",
        default=True,
    )

    parameter = parser.add_argument_group("参数发现")
    parameter.add_argument(
        "--smart-param-discovery",
        help="从页面内容中发现参数",
        action="store_true",
        default=True,
    )
    parameter.add_argument(
        "--param-similarity-threshold",
        type=float,
        default=0.7,
        help="参数相似度阈值（默认：0.7）",
    )
    parameter.add_argument(
        "--concat-param-detection",
        help="检测JavaScript中的URL拼接模式",
        action="store_true",
        default=True,
    )
    parameter.add_argument("--custom-param-wordlist", help="自定义参数字典")
    parameter.add_argument(
        "--param-fuzzing-depth",
        type=int,
        default=3,
        help="参数模糊测试深度，1-5",
    )
    parameter.add_argument(
        "--enable-param-variants",
        help="生成常见参数变体",
        action="store_true",
        default=True,
    )
    parameter.add_argument(
        "--detect-hidden-params",
        help="发现HTML和JavaScript中的隐藏参数",
        action="store_true",
        default=True,
    )
    parameter.add_argument(
        "--param-encoding-test",
        help="测试参数编码绕过",
        action="store_true",
    )
    parameter.add_argument(
        "--max-param-combinations",
        type=int,
        default=20,
        help="每个目标最多测试的参数数（默认：20）",
    )
    parameter.add_argument(
        "--param-discovery-sources",
        help="参数发现来源",
        default="html,js,api,comments",
    )

    runtime_group = parser.add_argument_group("网络与运行")
    runtime_group.add_argument(
        "-t",
        "--threads",
        type=int,
        default=5,
        help="工作线程数（默认：5）",
    )
    runtime_group.add_argument(
        "-p",
        "--proxy",
        help="代理地址，例如 http://127.0.0.1:8080",
    )
    runtime_group.add_argument(
        "-to",
        "--timeout",
        type=float,
        default=3,
        help="请求超时秒数（默认：3）",
    )
    runtime_group.add_argument(
        "-r",
        "--retries",
        type=int,
        default=3,
        help="请求重试次数（默认：3）",
    )
    runtime_group.add_argument(
        "--fast-mode",
        help="减少参数和载荷以加快扫描",
        action="store_true",
    )
    runtime_group.add_argument(
        "--continue-after-found",
        help="发现漏洞后继续测试其余参数",
        action="store_true",
    )
    runtime_group.add_argument(
        "--verbose",
        help="显示参数发现和扫描阶段详情",
        action="store_true",
    )
    runtime_group.add_argument(
        "--no-color",
        help="禁用彩色输出",
        action="store_true",
    )

    output = parser.add_argument_group("输出与报告")
    output.add_argument("-ou", "--outputurl", help="将发现的URL写入文件")
    output.add_argument("-os", "--outputsubdomain", help="将发现的子域名写入文件")
    output.add_argument("-oj", "--outputjson", help="将JSON结果写入文件")
    output.add_argument("-ov", "--outputvuln", help="将漏洞报告写入文件")
    output.add_argument("-s", "--screenshot", help="网页截图保存目录")
    output.add_argument(
        "--save-response",
        help="保存HTTP响应正文",
        action="store_true",
    )

    return _apply_default_scan_mode(parser.parse_args())

def validate_arguments(args):
    """Validate command-line argument combinations."""

    if not args.url and not args.cve_scan:
        print_error("必须指定目标URL（-u/--url）或CVE扫描路径（--cve-scan）")
        sys.exit(1)

    cve_source_is_url = (
        args.cve_scan
        and args.cve_scan.lower().startswith(("http://", "https://"))
    )
    if args.cve_scan and not cve_source_is_url and not os.path.exists(args.cve_scan):
        print_error(f"CVE扫描目标不存在或不是有效URL：{args.cve_scan}")
        sys.exit(1)

    if args.get_cookies and not args.url:
        print_error("--get-cookies 需要同时指定目标URL")
        sys.exit(1)

    if args.cve_max_download_mb < 1:
        print_error("--cve-max-download-mb 必须大于0")
        sys.exit(1)

    if args.auto_sqlmap and not (args.sql_scan or args.vuln_scan or args.advanced_sql):
        print_error("--auto-sqlmap 需要同时启用SQL扫描")
        print_info("请使用 --sql-scan、--vuln-scan 或 --advanced-sql")
        sys.exit(1)

    if args.sqlmap_path != "sqlmap":
        if not os.path.exists(args.sqlmap_path) and not os.path.isfile(args.sqlmap_path):
            print_warning(f"配置的sqlmap路径不存在：{args.sqlmap_path}")
            print_info("如果sqlmap已加入PATH，可以忽略此警告")

    # 检查自定义文件路径
    custom_files = {
        '后台路径': args.custom_admin,
        'SQL载荷': args.custom_sql,
        'XSS载荷': args.custom_xss
    }

    for file_type, file_path in custom_files.items():
        if file_path and not os.path.exists(file_path):
            print_error(f"自定义{file_type}文件不存在：{file_path}")
            sys.exit(1)

    if args.threads > 50:
        print_warning(f"线程数较高（{args.threads}），可能导致目标过载")
        print_info("建议将工作线程数设置为5到20")

    if args.sql_threads > 50:
        print_warning(f"SQL线程数较高（{args.sql_threads}），可能导致目标过载")
        print_info("建议将工作线程数设置为5到20")

    if args.timeout < 1:
        print_warning("请求超时时间过短，可能导致结果不稳定")
    elif args.timeout > 30:
        print_warning("请求超时时间较长，可能降低扫描速度")

    if args.sql_delay < 1:
        print_warning("SQL延迟阈值过低，可能导致结果不稳定")
    elif args.sql_delay > 10:
        print_warning("SQL延迟阈值较高，可能降低时间盲注检测速度")

    return True
