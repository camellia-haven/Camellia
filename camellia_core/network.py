"""HTTP requests, target discovery, cookies, and sensitive data checks."""

import concurrent.futures
import re

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from urllib.parse import urljoin, urlparse

from .config import ADMIN_PATHS, load_custom_payloads
from .runtime import (
    print_cool,
    print_debug,
    print_error,
    print_finding,
    print_info,
    print_kv,
    print_section,
    print_success,
    print_verbose,
    print_warning,
)


args = None


def _request_error_label(error):
    """Return a short, stable label instead of a verbose urllib3 traceback."""
    if isinstance(error, requests.ConnectTimeout):
        return "连接超时"
    if isinstance(error, requests.ReadTimeout):
        return "读取超时"
    if isinstance(error, requests.Timeout):
        return "请求超时"
    if isinstance(error, requests.ProxyError):
        return "代理错误"
    if isinstance(error, requests.SSLError):
        return "TLS错误"
    if isinstance(error, requests.ConnectionError):
        return "网络异常"
    if isinstance(error, requests.TooManyRedirects):
        return "重定向过多"
    if isinstance(error, (requests.InvalidURL, requests.MissingSchema)):
        return "URL无效"
    return "请求错误"


def request_with_retry(url, headers, timeout, proxy, retries, method='GET', data=None):
    for attempt in range(retries):
        try:
            if proxy:
                proxies = {
                    'http': proxy,
                    'https': proxy
                }
                if method.upper() == 'POST':
                    response = requests.post(url, headers=headers, timeout=timeout, verify=False,
                                           proxies=proxies, allow_redirects=True, data=data)
                else:
                    response = requests.get(url, headers=headers, timeout=timeout, verify=False,
                                          proxies=proxies, allow_redirects=True)
            else:
                if method.upper() == 'POST':
                    response = requests.post(url, headers=headers, timeout=timeout, verify=False,
                                           allow_redirects=True, data=data)
                else:
                    response = requests.get(url, headers=headers, timeout=timeout, verify=False,
                                          allow_redirects=True)
            return response
        except requests.RequestException as e:
            error_label = _request_error_label(e)
            if attempt < retries - 1:
                print_info(
                    f"请求失败，正在重试 {attempt + 1}/{retries}："
                    f"{url}（{error_label}）"
                )
            else:
                print_error(
                    f"请求失败，已达到最大重试次数："
                    f"{url}（{error_label}）"
                )
    return None

def get_website_cookies(url):
    """获取网站的Cookie信息"""
    global args
    try:
        import requests
        from urllib.parse import urlparse

        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36"
        }

        # 如果用户提供了cookie，也添加到请求中
        if args.cookie:
            header["Cookie"] = args.cookie

        response = request_with_retry(url, header, args.timeout, args.proxy, args.retries)

        if response:
            cookies_info = []

            # 获取响应中的Set-Cookie头
            if 'Set-Cookie' in response.headers:
                # 处理单个或多个Set-Cookie头
                set_cookie_value = response.headers.get('Set-Cookie')
                if set_cookie_value:
                    cookies_info.append({
                        'type': 'Set-Cookie',
                        'value': set_cookie_value
                    })

                # 如果有多个Set-Cookie头，尝试获取所有
                if hasattr(response.headers, 'get_list'):
                    set_cookies = response.headers.get_list('Set-Cookie')
                    for cookie in set_cookies[1:]:  # 跳过第一个，已经添加过了
                        cookies_info.append({
                            'type': 'Set-Cookie',
                            'value': cookie
                        })

            # 获取请求中发送的Cookie
            if 'Cookie' in response.request.headers:
                cookies_info.append({
                    'type': 'Request-Cookie',
                    'value': response.request.headers['Cookie']
                })

            # 使用requests.Session来获取更详细的cookie信息
            session = requests.Session()
            if args.proxy:
                session.proxies = {'http': args.proxy, 'https': args.proxy}

            session_response = session.get(url, headers=header, timeout=args.timeout, verify=False)

            if session.cookies:
                for cookie in session.cookies:
                    cookies_info.append({
                        'type': 'Session-Cookie',
                        'name': cookie.name,
                        'value': cookie.value,
                        'domain': cookie.domain,
                        'path': cookie.path,
                        'secure': cookie.secure,
                        'httponly': hasattr(cookie, 'has_nonstandard_attr') and cookie.has_nonstandard_attr('HttpOnly')
                    })

            return cookies_info

    except Exception as e:
        print_error(f"无法获取Cookie：{type(e).__name__}: {e}")
        return []

    return []

def display_cookies(cookies_info, url):
    """显示Cookie信息"""
    if not cookies_info:
        print_warning(f"{url} 未发现Cookie")
        return

    print_section("Cookie信息", (("地址", url), ("数量", len(cookies_info))))
    for i, cookie in enumerate(cookies_info, 1):
        if cookie['type'] == 'Set-Cookie':
            print_kv(f"Set-Cookie #{i}", cookie['value'])
        elif cookie['type'] == 'Request-Cookie':
            print_kv(f"请求Cookie #{i}", cookie['value'])
        elif cookie['type'] == 'Session-Cookie':
            print_kv(f"会话Cookie #{i}", cookie['name'])
            print_kv("值", cookie['value'])
            print_kv("域名", cookie['domain'])
            print_kv("路径", cookie['path'])
            print_kv("安全", cookie['secure'])
            print_kv("HttpOnly", cookie['httponly'])
        print()

def extract_URL(JS):
    pattern_raw = r"""
      (?:"|')                               # 开始换行分隔符
      (
        ((?:[a-zA-Z]{1,10}://|//)           # 匹配协议 [a-Z]*1-10 或 //
        [^"'/]{1,}\.                        # 匹配域名 (任意字符 + 点)
        [a-zA-Z]{2,}[^"']{0,})              # 域名扩展名和/或路径
        |
        ((?:/|\.\./)                    # 以 /,../,./ 开头
        [^"'><,;| *()(%%$^/\\\[\]]          # 下一个字符不能是...
        [^"'><,;|()]{1,})                   # 其余字符不能是...
        |
        ([a-zA-Z0-9_\-/]{1,}/               # 带 / 的相对端点
        [a-zA-Z0-9_\-/]{1,}                 # 资源名称
        \.(?:[a-zA-Z]{1,4}|action)          # 其余部分 + 扩展名 (长度 1-4 或 action)
        (?:[\?|/][^"|']{0,}|))              # 带参数的 ? 标记
        |
        ([a-zA-Z0-9_\-]{1,}                 # 文件名
        \.(?:php|asp|aspx|jsp|json|
             action|html|js|txt|xml)             # . + 扩展名
        (?:\?[^"|']{0,}|))                  # 带参数的 ? 标记
      )
      (?:"|')                               # 结束换行分隔符
    """
    pattern = re.compile(pattern_raw, re.VERBOSE)
    result = re.finditer(pattern, str(JS))
    js_url = []
    matches = [match.group().strip('"').strip("'") for match in result if match.group() not in js_url]
    return matches if matches else []

def Extract_html(URL):
    global args
    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36"
    }
    if args.cookie:
        header["Cookie"] = args.cookie
    response = request_with_retry(URL, header, args.timeout, args.proxy, args.retries)
    if response:
        return response.content.decode("utf-8", "ignore")
    return None

def process_url(URL, re_URL):
    black_url = ["javascript:"]  # 添加一些过滤 URL 的关键字
    URL_raw = urlparse(URL)
    ab_URL = URL_raw.netloc
    host_URL = URL_raw.scheme
    if re_URL[:2] == "//":
        result = host_URL + ":" + re_URL
    elif re_URL[:4] == "http":
        result = re_URL
    elif re_URL[:2] != "//" and re_URL not in black_url:
        if re_URL[0] == "/":
            result = host_URL + "://" + ab_URL + re_URL
        else:
            if re_URL[0] == ".":
                if re_URL[:2] == "..":
                    result = host_URL + "://" + ab_URL + re_URL[2:]
                else:
                    result = host_URL + "://" + ab_URL + re_URL[1:]
            else:
                result = host_URL + "://" + ab_URL + "/" + re_URL
    else:
        result = URL
    return result

def find_last(string, substr):
    positions = []
    last_position = -1
    while True:
        position = string.find(substr, last_position + 1)
        if position == -1:
            break
        last_position = position
        positions.append(position)
    return positions

def find_by_url(url, js=True):
    if not js:
        try:
            print_verbose(f"正在处理URL：{url}")
        except Exception as e:
            print_error("请提供有效URL，例如 https://www.example.com")
    html_raw = Extract_html(url)
    if html_raw is None:
        print_error(f"无法访问 {url}")
        return None
    html = BeautifulSoup(html_raw, "html.parser")
    html_scripts = html.find_all("script")
    script_array = {}
    script_temp = ""
    for html_script in html_scripts:
        script_src = html_script.get("src")
        if script_src is None:
            script_temp += html_script.get_text() + "\n"
        else:
            purl = process_url(url, script_src)
            script_array[purl] = Extract_html(purl)
    script_array[url] = script_temp
    allurls = []
    for script in script_array:
        temp_urls = extract_URL(script_array[script])
        if not temp_urls:
            continue
        for temp_url in temp_urls:
            allurls.append(process_url(script, temp_url))
    result = []
    for singerurl in allurls:
        url_raw = urlparse(url)
        domain = url_raw.netloc
        positions = find_last(domain, ".")
        miandomain = domain
        if len(positions) > 1:
            miandomain = domain[positions[-2] + 1:]
        suburl = urlparse(singerurl)
        subdomain = suburl.netloc
        if miandomain in subdomain or not subdomain.strip():
            if singerurl.strip() not in result:
                result.append(singerurl)
    return result

def find_by_url_deep(url):
    html_raw = Extract_html(url)
    if html_raw is None:
        print_error(f"无法访问 {url}")
        return None
    html = BeautifulSoup(html_raw, "html.parser")
    html_as = html.find_all("a")
    links = []
    for html_a in html_as:
        src = html_a.get("href")
        if not src:
            continue
        link = process_url(url, src)
        if link not in links:
            links.append(link)
    if not links:
        return None
    print_success(f"发现 {len(links)} 个链接")
    urls = []

    def process_link(link):
        temp_urls = find_by_url(link)
        if temp_urls is not None:
            print_verbose(f"在 {link} 发现 {len(temp_urls)} 个URL")
            return temp_urls
        return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = executor.map(process_link, links)
        for temp_urls in results:
            for temp_url in temp_urls:
                if temp_url not in urls:
                    urls.append(temp_url)

    return urls

def find_by_file(file_path, js=True):
    try:
        with open(file_path, "r") as fobject:
            links = fobject.read().split("\n")
    except FileNotFoundError:
        print_error(f"文件不存在：{file_path}")
        return None
    if not links:
        return None
    print_success(f"已加载 {len(links)} 个链接")
    urls = []

    def process_file_link(link):
        if not js:
            temp_urls = find_by_url(link)
        else:
            temp_urls = find_by_url(link, js=True)
        if temp_urls is not None:
            print_verbose(f"在 {link} 发现 {len(temp_urls)} 个URL")
            return temp_urls
        return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = executor.map(process_file_link, links)
        for temp_urls in results:
            for temp_url in temp_urls:
                if temp_url not in urls:
                    urls.append(temp_url)

    return urls

def find_subdomain(urls, mainurl):
    url_raw = urlparse(mainurl)
    domain = url_raw.netloc
    positions = find_last(domain, ".")
    miandomain = domain
    if positions and len(positions) > 1:
        miandomain = domain[positions[-2] + 1:]
    subdomains = []
    for url in urls:
        suburl = urlparse(url)
        subdomain = suburl.netloc
        if not subdomain.strip():
            continue
        if miandomain in subdomain:
            if subdomain not in subdomains:
                subdomains.append(subdomain)
    return subdomains

SENSITIVE_PATTERNS = {
    "身份证号": re.compile(r'[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}(?:\d|X|x)'),
    "手机号": re.compile(r'1[3-9]\d{9}'),
    "邮箱": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "API密钥": re.compile(r'(?i)(api[_-]?key|access[_-]?key|secret[_-]?key)[_-]?(key)?["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{32,}'),
    "AWS密钥": re.compile(r'AKIA[0-9A-Z]{16}'),
    "Google API密钥": re.compile(r'AIza[0-9A-Za-z\\-_]{35}'),
    "GitHub Token": re.compile(r'ghp_[0-9a-zA-Z]{36}'),
    "密码": re.compile(r'(?i)(password|passwd|pwd)[_-]?(key)?["\']?\s*[:=]\s*["\']?[^"\']\s]{8,}'),
    "数据库连接": re.compile(r'(?i)(mongodb|mysql|postgresql)://[^"\']\s]+'),
    "JWT Token": re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'),
    "私钥": re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
    "云存储URL": re.compile(r'(?i)(s3|oss|cos)://[^"\']\s]+'),
    "IP地址": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "SQL语句": re.compile(r'(?i)(select|insert|update|delete|drop|create|alter|grant|revoke)\s+.*(from|into|set|table|database|schema)', re.MULTILINE),
    "数据库表名": re.compile(r'(?i)(from|join|into|table)\s+([a-zA-Z_][a-zA-Z0-9_]*)', re.MULTILINE),
    "SQL注入特征": re.compile(r"(?i)(union\s+select|or\s+1=1|and\s+1=1|'\s*or\s*'|\"\s*or\s*\"|sleep\(|benchmark\(|waitfor\s+delay)", re.MULTILINE),
    "XSS特征": re.compile(r'(?i)(<script|javascript:|onerror=|onload=|onclick=|onfocus=|onmouseover=|alert\(|document\.cookie)', re.MULTILINE),
    "文件包含特征": re.compile(r'(?i)(include|require|file_get_contents|fopen|readfile)\s*\([^)]*\$', re.MULTILINE),
    "命令执行特征": re.compile(r'(?i)(exec|system|shell_exec|passthru|eval|assert)\s*\(', re.MULTILINE)
}

def detect_sensitive_info(content, url):
    findings = []
    seen_values = set()

    for info_type, pattern in SENSITIVE_PATTERNS.items():
        matches = pattern.finditer(content)
        for match in matches:
            value = match.group()


            if value not in seen_values:
                seen_values.add(value)
                findings.append({
                    "type": info_type,
                    "value": value,
                    "url": url,
                    "position": match.span()
                })

    return findings

def print_sensitive_findings(findings):
    if not findings:
        return

    print_section("敏感信息", (("发现数量", len(findings)),))
    for finding in findings:
        print_finding(finding)

def save_findings_to_file(findings, filename):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for finding in findings:
                f.write(f"类型: {finding['type']}\n")
                f.write(f"URL: {finding['url']}\n")
                f.write(f"值: {finding['value']}\n")
                f.write(f"位置: {finding['position']}\n")
                f.write("-" * 80 + "\n")
        print_success(f"敏感信息结果已保存到 {filename}")
    except Exception as e:
        print_error(f"无法保存敏感信息结果：{type(e).__name__}")

def is_api_url(url):

    api_keywords = [
        'api', 'v1', 'v2', 'v3', 'rest', 'graphql', 'service', 'gateway',
        'auth', 'oauth', 'token', 'login', 'register', 'user', 'admin',
        'data', 'query', 'search', 'upload', 'download', 'export', 'import'
    ]


    api_extensions = ['.json', '.xml', '.api', '.rpc', '.soap', '.wsdl']


    non_api_extensions = ['.js', '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot']

    url_lower = url.lower()


    if any(url_lower.endswith(ext) for ext in non_api_extensions):
        return False


    if any(keyword in url_lower for keyword in api_keywords):
        return True


    if any(url_lower.endswith(ext) for ext in api_extensions):
        return True


    path_depth = url_lower.count('/')
    if path_depth >= 2:
        return True

    return False

def scan_admin_pages(base_url):
    global args
    print_cool("开始后台管理页面发现")

    admin_paths = ADMIN_PATHS
    if args.custom_admin:
        custom_paths = load_custom_payloads(args.custom_admin)
        if custom_paths:
            admin_paths.extend(custom_paths)
            print_verbose(f"已加载 {len(custom_paths)} 个自定义后台路径")

    found_admin_pages = []

    def check_admin_path(path):
        try:
            test_url = urljoin(base_url, path)
            header = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36"
            }
            if args.cookie:
                header["Cookie"] = args.cookie
            response = request_with_retry(test_url, header, args.timeout, args.proxy, args.retries)

            if response and response.status_code in [200, 301, 302, 403]:
                content = response.content.decode("utf-8", "ignore").lower()
                # 检查是否包含后台特征
                admin_keywords = ['login', 'admin', 'password', 'username', 'dashboard', 'control panel', 'management']
                if any(keyword in content for keyword in admin_keywords):
                    result = {
                        "url": test_url,
                        "status_code": response.status_code,
                        "title": "",
                        "keywords_found": []
                    }

                    # 提取页面标题
                    try:
                        soup = BeautifulSoup(response.content, 'html.parser')
                        title_tag = soup.find('title')
                        if title_tag:
                            result["title"] = title_tag.get_text().strip()
                    except:
                        pass

                    # 记录找到的关键词
                    result["keywords_found"] = [kw for kw in admin_keywords if kw in content]

                    print_success(
                        f"发现后台页面：{test_url} "
                        f"（状态码：{response.status_code}）"
                    )
                    if result["title"]:
                        print_info(f"页面标题：{result['title']}")

                    return result
        except Exception as e:
                if args.verbose:
                    print_debug(
                        f"后台页面检测失败 {path}："
                        f"{type(e).__name__}"
                    )
        return None


    with tqdm(total=len(admin_paths), desc="后台扫描", unit="个路径") as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_path = {executor.submit(check_admin_path, path): path for path in admin_paths}

            for future in concurrent.futures.as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                        found_admin_pages.append(result)
                except Exception as e:
                    if args.verbose:
                        print_error(
                            f"后台页面检测失败 {path}："
                            f"{type(e).__name__}"
                        )
                pbar.update(1)

    print_success(
        "后台管理页面发现完成；"
        f"发现 {len(found_admin_pages)} 个可能的页面"
    )
    return found_admin_pages
