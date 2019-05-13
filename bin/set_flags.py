#!/usr/bin/env python
from __future__ import print_function

import subprocess
import sys
import re
import argparse
import os


IP_RE = re.compile(r' [a-z]+@(\d+([.]\d+){3}) ')
TS_CLI_PATH = '/home/yugabyte/tserver/bin/yb-ts-cli'
CMD_TEMPLATE = (
    '{cmd} {ts_cli_path} -server_address {ip}:{rpc_port} set_flag -force {flag_name} {flag_value}'
)
DEFAULT_CONNECT_CMDS_PATH = os.path.expanduser('~/yb_ssh_cmds.txt')
HOW_TO_CREATE_CONNECT_FILE = (
    'To create this file, go to YugaWare, click on a '
    "universe's Nodes tab, then click Connect, and copy-and-paste the list of SSH "
    "commands from the section where it says \"From Admin host\" into this file."
)


def get_ip_from_ssh_cmd(ssh_cmd):
    m = IP_RE.search(ssh_cmd)
    if not m:
        raise ValueError("Could not get IP from SSH line: %s" % ssh_cmd)
    return m.group(1)


def read_ssh_cmds(file_path):
    connect_cmds = []
    with open(file_path) as connect_file:
        for line in connect_file:
            line = line.strip()
            if line:
                # Ensure that every line contains a valid IP address.
                get_ip_from_ssh_cmd(line)
                connect_cmds.append(line)
    return connect_cmds


def parse_args():
    parser = argparse.ArgumentParser(
        description='Set flags of masters and tablet servers at run time')
    parser.add_argument(
        '--connect_cmds_file', 
        help='File with SSH connection commands (from command line). Default: ' +
             DEFAULT_CONNECT_CMDS_PATH + '. ' + HOW_TO_CREATE_CONNECT_FILE,
        default=DEFAULT_CONNECT_CMDS_PATH)
    parser.add_argument('--flag_name', required=True)
    parser.add_argument('--flag_value', required=True)
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    if not os.path.exists(args.connect_cmds_file):
        sys.stderr.write("File specified for --connect_cmds_file does not exist: %s.\n%s\n" % (
            args.connect_cmds_file,
            HOW_TO_CREATE_CONNECT_FILE))
        sys.exit(1)
    connect_cmds = read_ssh_cmds(args.connect_cmds_file)
    if not connect_cmds:
        sys.stderr.write(
            "Failed to read any connection commands from file: %s\n" % args.connect_cmds_file)
        sys.exit(1)

    num_successes = 0
    num_failures = 0
    total_attempts = 0
    ips = set()
    for cmd in connect_cmds:
        ip = get_ip_from_ssh_cmd(cmd)
        ips.add(ip)
        for server_type, http_port in (('master', 7000), ('tserver', 9000)):
            total_attempts += 1
            print('Updating flag for %s on %s' % (server_type, ip))
            rpc_port = http_port + 100
            ssh_cmd = CMD_TEMPLATE.format(
                cmd=cmd,
                ts_cli_path=TS_CLI_PATH,
                ip=ip,
                rpc_port=rpc_port,
                flag_name=args.flag_name,
                flag_value=args.flag_value)
            sys.stderr.write("Running command: %s\n" % ssh_cmd)

            try:
                subprocess.check_call(['/bin/bash', '-c', ssh_cmd])
                what_did_we_do = "Updated"
                num_successes += 1
            except subprocess.CalledProcessError as ex:
                sys.stderr.write("Error: %s\n" % str(ex))
                what_did_we_do = "Failed updating"
                num_failures += 1

            print('%s %s flag, web UI page: %s' % (
                what_did_we_do,
                server_type,
                'http://%s:%d/varz' % (ip, http_port)))

    sys.stderr.write(
        "Finished connecting to %d nodes (from %d commands)\n"
        "Total connection attempts: %d (separate for masters/tservers)\n"
        "Total successes: %d\n"
        "Total failures: %d\n" % (
            len(ips),
            len(connect_cmds),
            total_attempts,
            num_successes,
            num_failures))
