#!/usr/bin/env python
# coding: utf-8
"""Main command-line entry point for Camellia."""

from camellia_core import cli as sql_cli
from camellia_core import scan as sql_scan

from camellia_core.args import *
from camellia_core.cli import *
from camellia_core.command_scan import *
from camellia_core.config import *
from camellia_core.core import *
from camellia_core.cve_scan import *
from camellia_core.file_scan import *
from camellia_core.network import *
from camellia_core.params import *
from camellia_core.runtime import *
from camellia_core.scan import *
from camellia_core.weak_password_scan import *
from camellia_core.xss import *


args = None


def set_args(value):
    global args
    args = value
    sql_cli.configure_runtime_args(value)


def test_sql_injection(url):
    if args is not None:
        sql_scan.args = args
    return sql_scan.test_sql_injection(url)


if __name__ == "__main__":
    main()
