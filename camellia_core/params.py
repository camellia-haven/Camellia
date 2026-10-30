"""Parameter discovery and URL construction helpers for the SQL scanner."""

import re
import urllib.parse
from urllib.parse import parse_qsl, urlencode, urlparse, urlunsplit

from .runtime import print_verbose, print_warning


def discover_parameters_from_content(url, content):
    """从页面内容中发现候选参数。"""
    discovered_params = set()
    import re

    # 表单
    form_inputs = re.findall(r'<input[^>]*name=["\']([^"\'>]+)["\'][^>]*>', content, re.IGNORECASE)
    discovered_params.update(form_inputs)

    select_params = re.findall(r'<select[^>]*name=["\']([^"\'>]+)["\'][^>]*>', content, re.IGNORECASE)
    discovered_params.update(select_params)

    textarea_params = re.findall(r'<textarea[^>]*name=["\']([^"\'>]+)["\'][^>]*>', content, re.IGNORECASE)
    discovered_params.update(textarea_params)

    button_params = re.findall(r'<button[^>]*name=["\']([^"\'>]+)["\'][^>]*>', content, re.IGNORECASE)
    discovered_params.update(button_params)

    # URL 和 JavaScript
    link_params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)[=]', content)
    discovered_params.update(link_params)

    href_params = re.findall(r'href=["\'][^"\'>]*[?&]([a-zA-Z_][a-zA-Z0-9_]*)[=][^"\'>]*["\']', content, re.IGNORECASE)
    discovered_params.update(href_params)

    js_params = re.findall(r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\s*:', content)
    discovered_params.update([p for p in js_params if len(p) < 20 and len(p) > 2])

    js_var_params = re.findall(r'var\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=', content, re.IGNORECASE)
    discovered_params.update([p for p in js_var_params if len(p) < 15 and len(p) > 2])

    ajax_params = re.findall(r'data\s*:\s*{[^}]*["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\s*:', content)
    discovered_params.update(ajax_params)

    jquery_params = re.findall(r'\$\.(?:post|get|ajax)\([^,]*,\s*{[^}]*["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\s*:', content)
    discovered_params.update(jquery_params)

    # API、JSON 和服务端代码
    api_params = re.findall(r'/api/[^\s"\'>]*[?&]([a-zA-Z_][a-zA-Z0-9_]*)[=]', content, re.IGNORECASE)
    discovered_params.update(api_params)

    rest_params = re.findall(r'/(?:api|rest)/[^/\s"\'>]*/{([a-zA-Z_][a-zA-Z0-9_]*)}', content, re.IGNORECASE)
    discovered_params.update(rest_params)

    json_params = re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:\s*["\'{\[]', content)
    discovered_params.update([p for p in json_params if len(p) < 20 and len(p) > 2])

    php_get_params = re.findall(r'\$_(?:GET|POST|REQUEST)\[["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\]', content)
    discovered_params.update(php_get_params)

    asp_params = re.findall(r'Request\[["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\]', content, re.IGNORECASE)
    discovered_params.update(asp_params)

    # HTML 属性和元数据
    data_attrs = re.findall(r'data-([a-zA-Z_][a-zA-Z0-9_-]*)', content, re.IGNORECASE)
    discovered_params.update([p.replace('-', '_') for p in data_attrs if len(p) > 2])

    hidden_params = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\'>]+)["\']', content, re.IGNORECASE)
    discovered_params.update(hidden_params)

    meta_params = re.findall(r'<meta[^>]*name=["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']', content, re.IGNORECASE)
    discovered_params.update(meta_params)

    # 拼接参数
    concat_params = re.findall(r'["\']([a-zA-Z_][a-zA-Z0-9_]*)=["\']\s*\+', content)
    discovered_params.update(concat_params)

    url_concat_params = re.findall(r'["\'][^"\'>]*[?&]([a-zA-Z_][a-zA-Z0-9_]*)=["\']\s*\+', content)
    discovered_params.update(url_concat_params)

    template_params = re.findall(r'`[^`]*[?&]([a-zA-Z_][a-zA-Z0-9_]*)=\${', content)
    discovered_params.update(template_params)

    # 数据库、配置与框架路由
    sql_params = re.findall(r'WHERE\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=', content, re.IGNORECASE)
    discovered_params.update(sql_params)

    orm_params = re.findall(r'\.filter\(["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']', content)
    discovered_params.update(orm_params)

    config_params = re.findall(r'config\[["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\]', content, re.IGNORECASE)
    discovered_params.update(config_params)

    env_params = re.findall(r'process\.env\.([a-zA-Z_][a-zA-Z0-9_]*)', content)
    discovered_params.update(env_params)

    django_params = re.findall(r'<(?:int|str|slug):([a-zA-Z_][a-zA-Z0-9_]*)>', content)
    discovered_params.update(django_params)

    flask_params = re.findall(r'<(?:int|string|float):([a-zA-Z_][a-zA-Z0-9_]*)>', content)
    discovered_params.update(flask_params)

    express_params = re.findall(r'/:([a-zA-Z_][a-zA-Z0-9_]*)', content)
    discovered_params.update(express_params)

    # 注释、Cookie、WebSocket 与 GraphQL
    comment_params = re.findall(r'//.*?参数[：:]\s*([a-zA-Z_][a-zA-Z0-9_]*)', content)
    discovered_params.update(comment_params)

    jsdoc_params = re.findall(r'@param\s+{[^}]*}\s+([a-zA-Z_][a-zA-Z0-9_]*)', content)
    discovered_params.update(jsdoc_params)

    cookie_params = re.findall(r'document\.cookie\s*=\s*["\']([a-zA-Z_][a-zA-Z0-9_]*)=', content)
    discovered_params.update(cookie_params)

    session_params = re.findall(r'session\[["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\]', content, re.IGNORECASE)
    discovered_params.update(session_params)

    ws_params = re.findall(r'send\([^)]*["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\s*:', content)
    discovered_params.update(ws_params)

    socketio_params = re.findall(r'emit\([^,]*,\s*{[^}]*["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\s*:', content)
    discovered_params.update(socketio_params)

    graphql_params = re.findall(r'\$([a-zA-Z_][a-zA-Z0-9_]*)\s*:', content)
    discovered_params.update(graphql_params)

    graphql_field_params = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\$', content)
    discovered_params.update(graphql_field_params)

    # 常见测试字段
    extended_test_params = {
        'table', 'column', 'field', 'record', 'row', 'index', 'key_id', 'primary_key',
        'filepath', 'dirname', 'basename', 'extension', 'upload', 'download',
        'timestamp', 'datetime', 'date', 'time', 'year', 'month', 'day', 'hour', 'minute',
        'latitude', 'longitude', 'location', 'address', 'city', 'country', 'region',
        'price', 'quantity', 'discount', 'coupon', 'cart', 'order', 'payment', 'shipping',
        'post', 'comment', 'like', 'share', 'follow', 'friend', 'message', 'notification',
        'role', 'permission', 'access', 'token', 'auth', 'session_id', 'csrf_token',
        'filter', 'sort', 'order_by', 'group_by', 'having', 'where', 'condition',
        'api_key', 'version', 'format', 'callback', 'jsonp', 'cors', 'origin',
        'debug', 'verbose', 'trace', 'log_level', 'test_mode', 'dev_mode'
    }

    # 常见非参数词汇
    filter_words = {
        'type', 'class', 'style', 'src', 'href', 'alt', 'title', 'width', 'height', 'border',
        'id', 'name', 'value', 'placeholder', 'required', 'disabled', 'readonly', 'checked',
        'function', 'var', 'let', 'const', 'if', 'else', 'for', 'while', 'return', 'true', 'false',
        'null', 'undefined', 'this', 'window', 'document', 'console', 'alert', 'confirm',
        'text', 'html', 'body', 'head', 'meta', 'link', 'script', 'div', 'span', 'img',
        'form', 'input', 'button', 'select', 'option', 'textarea', 'label', 'table', 'tr', 'td',
        'jquery', 'bootstrap', 'angular', 'react', 'vue', 'ajax', 'json', 'xml', 'http', 'https',
        'get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'status', 'code', 'error'
    }

    discovered_params = {
        p for p in discovered_params
        if p.lower() not in filter_words
        and len(p) >= 2
        and len(p) <= 30
        and not p.isdigit()
        and not p.startswith('_')
        and not p.startswith('$')
    }

    if discovered_params:
        similar_params = find_similar_test_parameters(discovered_params, extended_test_params)
        discovered_params.update(similar_params)

    return list(discovered_params)

def find_similar_test_parameters(discovered_params, extended_test_params):
    """根据发现的参数找到相似的测试参数"""
    similar_params = set()

    similarity_map = {
        'id': ['uid', 'pid', 'oid', 'gid', 'tid', 'aid', 'bid', 'cid', 'did', 'eid'],
        'user': ['username', 'userid', 'user_id', 'account', 'login', 'member'],
        'page': ['p', 'pg', 'pagenum', 'page_num', 'current_page', 'offset'],
        'search': ['q', 'query', 'keyword', 'term', 'find', 's'],
        'category': ['cat', 'type', 'kind', 'class', 'group'],
        'action': ['act', 'do', 'cmd', 'command', 'operation'],
        'file': ['filename', 'filepath', 'path', 'dir', 'folder'],
        'data': ['info', 'content', 'text', 'value', 'val'],
        'time': ['timestamp', 'date', 'datetime', 'created', 'updated'],
        'status': ['state', 'condition', 'flag', 'active', 'enabled']
    }

    reverse_map = {}
    for key, values in similarity_map.items():
        for value in values:
            if value not in reverse_map:
                reverse_map[value] = []
            reverse_map[value].append(key)
        reverse_map[key] = values

    for param in discovered_params:
        param_lower = param.lower()

        if param_lower in reverse_map:
            similar_params.update(reverse_map[param_lower])

        for base_param, variants in similarity_map.items():
            if any(variant in param_lower or param_lower in variant for variant in variants):
                similar_params.update(variants)
                similar_params.add(base_param)

        # 词根匹配用于覆盖 id/user_id 一类的变体。
        for test_param in extended_test_params:
            if len(param_lower) >= 3 and len(test_param) >= 3:
                if (param_lower[:3] == test_param[:3] or
                    param_lower[-3:] == test_param[-3:] or
                    param_lower in test_param or test_param in param_lower):
                    similar_params.add(test_param)

    similar_params = similar_params - discovered_params

    return similar_params

def generate_parameter_variants(base_param):
    """生成参数变体（如id->user_id, uid等）- 优化版本"""
    variants = set([base_param])

    common_prefixes = ['user_', 'admin_']
    common_suffixes = ['_id', '_key', '_code']

    if len(base_param) <= 4:
        for prefix in common_prefixes:
            variants.add(prefix + base_param)

    if len(base_param) <= 4:
        for suffix in common_suffixes:
            variants.add(base_param + suffix)

    abbreviations = {
        'id': ['uid', 'user_id'],
        'name': ['username', 'uname'],
        'pass': ['password', 'pwd'],
        'email': ['mail'],
        'num': ['number', 'no']
    }

    for abbr, full_forms in abbreviations.items():
        if base_param.lower() == abbr:
            variants.update(full_forms[:2])  # 只取前2个变体
        elif base_param.lower() in full_forms:
            variants.add(abbr)

    variants.add(base_param.lower())

    return list(variants)[:8]

def calculate_parameter_similarity(param1, param2):
    """计算两个参数的相似度"""
    import difflib

    similarity = difflib.SequenceMatcher(None, param1.lower(), param2.lower()).ratio()

    semantic_groups = [
        ['id', 'uid', 'user_id', 'userid', 'identifier'],
        ['name', 'username', 'uname', 'user_name'],
        ['pass', 'password', 'passwd', 'pwd'],
        ['email', 'mail', 'e_mail', 'email_address'],
        ['phone', 'tel', 'telephone', 'mobile', 'cell'],
        ['search', 'query', 'q', 'keyword', 'term'],
        ['page', 'p', 'pagenum', 'page_number'],
        ['limit', 'size', 'count', 'num', 'number']
    ]

    # 同一语义组至少按 0.8 计分。
    for group in semantic_groups:
        if param1.lower() in group and param2.lower() in group:
            similarity = max(similarity, 0.8)  # 语义相似加权

    return similarity

def detect_concatenated_parameters(url, content):
    """检测拼接参数模式"""
    import re

    concat_patterns = [
        r'["\'][^"\'>]*[?&][a-zA-Z_][a-zA-Z0-9_]*=["\']\s*\+',  # "url?param=" +
        r'\+\s*["\'][&]?[a-zA-Z_][a-zA-Z0-9_]*=["\']',  # + "&param="
        r'\$\{[^}]*[?&][a-zA-Z_][a-zA-Z0-9_]*\}',  # ${...?param}
        r'`[^`]*[?&][a-zA-Z_][a-zA-Z0-9_]*=\${',  # `url?param=${}
        r'location\.href\s*\+=',  # location.href +=
        r'window\.location\s*\+=',  # window.location +=
        r'document\.location\s*\+=',  # document.location +=
    ]

    for pattern in concat_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True

    special_chars = ['#', ';', '|', '%']
    for char in special_chars:
        if char in url and '=' in url:
            return True

    return False

def generate_enhanced_test_parameters(discovered_params, base_params):
    """生成增强的测试参数列表"""
    enhanced_params = set(base_params)

    enhanced_params.update(discovered_params)

    for param in discovered_params:
        variants = [
            f"{param}_id",
            f"{param}Id",
            f"{param}_key",
            f"{param}Key",
            f"{param}_value",
            f"{param}Value",
            f"{param}_name",
            f"{param}Name",
            f"get_{param}",
            f"set_{param}",
            f"{param}_data",
            f"{param}Data"
        ]
        enhanced_params.update(variants)

    # 常见上下文参数
    context_params = {
        'admin', 'administrator', 'root', 'superuser', 'manager', 'owner',
        'moderator', 'editor', 'author', 'contributor', 'subscriber',
        'config', 'settings', 'options', 'preferences', 'properties',
        'configuration', 'setup', 'init', 'initialize', 'install',
        'database', 'db', 'sql', 'query', 'table', 'schema', 'index',
        'connection', 'driver', 'engine', 'pool', 'transaction',
        'session', 'cookie', 'token', 'auth', 'login', 'logout',
        'register', 'signup', 'signin', 'password', 'credential',
        'oauth', 'jwt', 'api_key', 'access_token', 'refresh_token',
        'upload', 'download', 'file_upload', 'file_download', 'attachment',
        'media', 'asset', 'resource', 'static', 'public', 'private',
        'redirect', 'return', 'callback', 'next', 'prev', 'back',
        'forward', 'goto', 'navigate', 'route', 'path', 'url',
        'sort', 'order', 'filter', 'group', 'limit', 'offset',
        'search', 'find', 'lookup', 'match', 'compare', 'validate',
        'debug', 'test', 'dev', 'development', 'prod', 'production',
        'staging', 'beta', 'alpha', 'demo', 'sandbox', 'local',
        'api', 'endpoint', 'service', 'method', 'action', 'operation',
        'request', 'response', 'payload', 'data', 'json', 'xml',
        'cache', 'redis', 'memcache', 'storage', 'temp', 'temporary',
        'session_id', 'cache_key', 'expire', 'ttl', 'timeout',
        'log', 'logger', 'audit', 'trace', 'monitor', 'track',
        'event', 'activity', 'history', 'record', 'report',
        'security', 'permission', 'role', 'privilege', 'access',
        'authorize', 'authenticate', 'encrypt', 'decrypt', 'hash',
        'business', 'company', 'organization', 'department', 'team',
        'project', 'task', 'workflow', 'process', 'status'
    }
    enhanced_params.update(context_params)

    return list(enhanced_params)

def smart_parameter_discovery(url, content, args):
    """智能参数发现主函数"""
    all_params = set()

    basic_params = discover_parameters_from_content(url, content)
    all_params.update(basic_params)

    if args.concat_param_detection:
        concat_detected = detect_concatenated_parameters(url, content)
        if concat_detected:
            print_verbose("检测到拼接参数模式")
            concat_params = ['id', 'user', 'page', 'action', 'cmd', 'file', 'path']
            all_params.update(concat_params)

    if args.enable_param_variants:
        variant_params = set()
        for param in list(all_params):
            variants = generate_parameter_variants(param)
            variant_params.update(variants)
        all_params.update(variant_params)
        if variant_params:
            print_verbose(f"已生成 {len(variant_params)} 个参数变体")

    if args.custom_param_wordlist:
        try:
            with open(args.custom_param_wordlist, 'r', encoding='utf-8') as f:
                custom_params = [line.strip() for line in f if line.strip()]
                all_params.update(custom_params)
                print_verbose(f"已加载 {len(custom_params)} 个自定义参数")
        except Exception as e:
            print_warning(f"无法读取自定义参数字典：{e}")

    if args.param_similarity_threshold > 0:
        similar_params = set()
        common_params = ['id', 'name', 'user', 'pass', 'email', 'search', 'query', 'page', 'limit', 'action', 'cmd']

        for discovered_param in all_params:
            for common_param in common_params:
                similarity = calculate_parameter_similarity(discovered_param, common_param)
                if similarity >= args.param_similarity_threshold:
                    similar_params.add(common_param)

        all_params.update(similar_params)
        if similar_params:
            print_verbose(
                f"相似性匹配新增参数：{', '.join(sorted(similar_params))}"
            )

    if args.detect_hidden_params:
        hidden_params = detect_hidden_parameters(content)
        all_params.update(hidden_params)
        if hidden_params:
            print_verbose(
                f"发现隐藏参数：{', '.join(sorted(hidden_params))}"
            )

    max_params = args.max_param_combinations
    if args.fast_mode:
        max_params = min(10, args.max_param_combinations)

    final_params = list(all_params)[:max_params]

    if len(all_params) > max_params:
        mode_info = "快速模式" if args.fast_mode else "标准模式"
        print_verbose(
            f"{mode_info}参数数量已达上限，将测试前 {max_params} 个"
        )

    return final_params

def detect_hidden_parameters(content):
    """检测隐藏参数"""
    import re
    hidden_params = set()

    hidden_inputs = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\'>]+)["\']', content, re.IGNORECASE)
    hidden_params.update(hidden_inputs)

    js_vars = re.findall(r'var\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\'][^"\'>]*["\']', content)
    hidden_params.update([p for p in js_vars if len(p) > 2 and len(p) < 20])

    data_attrs = re.findall(r'data-([a-zA-Z_][a-zA-Z0-9_-]*)', content)
    hidden_params.update([p.replace('-', '_') for p in data_attrs])

    comment_hints = re.findall(r'<!--[^>]*参数[：:]\s*([a-zA-Z_][a-zA-Z0-9_,\s]*)', content)
    for hint in comment_hints:
        params = [p.strip() for p in hint.split(',') if p.strip()]
        hidden_params.update(params)

    return list(hidden_params)

def build_url_with_parameter(url, param, payload):
    """替换指定查询参数，同时保留URL中的其他参数。"""
    parsed = urlparse(url)
    query_params = parse_qsl(parsed.query, keep_blank_values=True)
    updated_params = []
    replaced = False

    for name, value in query_params:
        if name == param and not replaced:
            updated_params.append((name, payload))
            replaced = True
        else:
            updated_params.append((name, value))

    if not replaced:
        updated_params.append((param, payload))

    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        urlencode(updated_params, doseq=True),
        parsed.fragment
    ))

def enhanced_concatenated_parameter_test(url, param, payload, args):
    """增强的拼接参数测试"""
    standard_url = build_url_with_parameter(url, param, payload)
    test_urls = [standard_url]

    if args.concat_param_detection:
        test_urls.append(standard_url.replace('?', ';', 1))

        if args.param_encoding_test:
            encoded_payload = urllib.parse.quote(payload)
            test_urls.append(build_url_with_parameter(url, param, encoded_payload))
            test_urls.append(
                build_url_with_parameter(url, param, encoded_payload).replace('?', ';', 1)
            )

    return list(dict.fromkeys(test_urls))
