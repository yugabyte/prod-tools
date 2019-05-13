#!/usr/bin/env python
from __future__ import print_function

import subprocess
import sys
import re
import argparse

IP_RE = re.compile(r' [a-z]+@(\d+([.]\d+){3}) -p')
TS_CLI_PATH = '/home/yugabyte/tserver/bin/yb-ts-cli'
CMD_TEMPLATE = '{cmd} {ts_cli_path} -server_address {ip}:{rpc_port} set_flag -force {flag_name} {flag_value}'

if __name__ == '__main__':
    connect_cmds = []
    with open('connect.txt') as connect_file:
        for line in connect_file:
            line = line.strip()
            if line:
                connect_cmds.append(line)

    for cmd in connect_cmds:
        m = IP_RE.search(cmd)
        if not m:
            raise ValueError("Could not get IP from line: %s" % cmd)
        ip = m.group(1)
        print('Updating tablet server %s' % ip)
        for server_type, http_port in (('master', 7000), ('tserver', 9000)):
            rpc_port = http_port + 100
            ssh_cmd = CMD_TEMPLATE.format(
                cmd=cmd,
                ts_cli_path=TS_CLI_PATH,
                ip=ip,
                rpc_port=rpc_port)
            subprocess.check_call(['/bin/bash', '-c', ssh_cmd])
            print('Updated %s flag, web UI page: %s' % (
                server_type,
                'http://%s:%d/varz' % (ip, http_port)))

