#!/usr/bin/env python

# Copyright (c) YugaByte, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied.  See the License for the specific language governing permissions and limitations
# under the License.
#
# This script generates a header file which contains definitions
# for the current YugaByte build (e.g. timestamp, git hash, etc)


from __future__ import print_function

import subprocess
import sys
import re
import argparse
import os
import hashlib
import json
import base64
import logging
import socket

IP_RE = re.compile(r' [a-z]+@(\d+([.]\d+){3}) ')
YUGABYTE_HOME = '/home/yugabyte'
TS_CLI_PATH = YUGABYTE_HOME + '/tserver/bin/yb-ts-cli'
SERVER_CONF_PATH_TEMPLATE = YUGABYTE_HOME + '/{server_type}/conf/server.conf'
DEFAULT_CONNECT_CMDS_PATH = os.path.expanduser('~/yb_ssh_cmds.txt')
HOW_TO_CREATE_CONNECT_FILE = (
    'To create this file, go to YugaWare, click on a '
    "universe's Nodes tab, then click Connect, and copy-and-paste the list of SSH "
    "commands from the section where it says \"From Admin host\" into this file."
)
HOST_NAME = socket.gethostname()

SERVER_TYPE_INFO = [
    dict(
        server_type='master',
        http_port=7000,
        rpc_port=7100
    ),
    dict(
        server_type='tserver',
        http_port=9000,
        rpc_port=9100
    )
]


class AppError(Exception):
    pass


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


def validate_and_read_ssh_cmds(connect_cmds_file_path):
    if not os.path.exists(connect_cmds_file_path):
        raise ValueError("File specified for --connect_cmds_file does not exist: %s. %s" % (
            connect_cmds_file_path,
            HOW_TO_CREATE_CONNECT_FILE))
    connect_cmds = read_ssh_cmds(connect_cmds_file_path)
    if not connect_cmds:
        raise ValueError(
            "Failed to read any connection commands from file: %s" % connect_cmds_file_path)
    return connect_cmds


def parse_args(arg_list):
    parser = argparse.ArgumentParser(
        description='Set flags of masters and tablet servers at run time')
    parser.add_argument(
        '--connect_cmds_file', 
        help='File with SSH connection commands (from command line). Default: ' +
             DEFAULT_CONNECT_CMDS_PATH + '. ' + HOW_TO_CREATE_CONNECT_FILE,
        default=DEFAULT_CONNECT_CMDS_PATH)
    parser.add_argument('--flag_name', required=True)
    parser.add_argument('--flag_value', required=True)
    parser.add_argument(
        '--persist',
        action='store_true',
        help='Persist flag changes in master/tserver configuration files on each node')
    parser.add_argument('--local', action='store_true',
        help='Perform the requested changes locally instead of SSH-ing to cluster servers.')
    parser.add_argument('--master_only', action='store_true',
        help='Perform master flag changes only.')
    parser.add_argument('--tserver_only', action='store_true',
        help='Perform tablet server flag changes only.')
    parser.add_argument('--verbose', action='store_true',
        help='Output extra details about what the script is doing.')
    parser.add_argument('--ip',
        help='Used with --local. Specifies the IP address of server to connect to.')
    args = parser.parse_args(arg_list)
    if args.master_only and args.tserver_only:
        raise ValueError("--master_only and --tserver_only are incompatible")
    if args.ip and not args.local:
        raise ValueError("--ip is only valid with --local")
    return args


def gzip_and_base64_encode(value):
    import StringIO
    import gzip
    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
        f.write(value)
    gzipped_value = out.getvalue()
    out.close()
    return base64.b64encode(gzipped_value)


class ScriptInstaller:
    """
    Allows installing this script on remote nodes so we can e.g. modify configuration files.
    """

    def __init__(self):
        with open(__file__) as this_script_file:
            self.base64_gzipped_script = gzip_and_base64_encode(this_script_file.read())

    def get_script_cmd(self):
        return 'python -c "$( echo %s | base64 -d | gzip -d )"' % self.base64_gzipped_script


def get_valid_flag_types_for_binary(server_binary):
    import xml.etree.ElementTree as ET

    list_flags_proc = subprocess.Popen([server_binary, '--helpxml'], stdout=subprocess.PIPE)
    list_flags_out, list_flags_err = list_flags_proc.communicate()
    if list_flags_proc.returncode != 1:
        raise IOError("Expected %s --helpxml to return exit code 1" % server_binary)

    valid_flags_et = ET.fromstring(list_flags_out)
    # Example flag XML format:
    # https://gist.githubusercontent.com/mbautin/bf79d4fc956f56fddf11ffdce76d1fb2/raw
    flag_types = {}
    for flag in valid_flags_et.iter('flag'):
        flag_types[flag.find('name').text] = flag.find('type').text
    return flag_types


def modify_conf_file(server_type, flag_name, flag_value, msg_common):
    conf_path = SERVER_CONF_PATH_TEMPLATE.format(server_type=server_type)
    if not os.path.exists(conf_path):
        raise AppError("File %s does not exist" % conf_path)
    existing_lines = []
    with open(conf_path) as conf_file:
        for line in conf_file:
            line = line.strip()
            if not line:
                continue
            if '=' not in line and not line.startswith('--'):
                raise AppError("Unexpected line in conf file, expected --key=value: %s" % line)
            existing_lines.append(line)

    line_prefix = "--%s=" % flag_name
    line_to_add = line_prefix + flag_value
    relevant_lines = []
    for line in existing_lines:
        if line.startswith(line_prefix):
            relevant_lines.append(line)
    if len(relevant_lines) > 1:
        raise AppError("Multiple lines starting with '%s' found in %s" % (line_prefix, conf_path))
    if line_to_add in existing_lines:
        logging.info("No need to %s. Line already found in %s: %s",
                     msg_common, conf_path, line_to_add)
        return
    new_lines = []

    new_lines = []
    added = False
    for line in existing_lines:
        if line in relevant_lines:
            # Insert the new flag at the point where the old flag used to be.
            if not added:
                new_lines.append(line_to_add)
                added = True
        else:
            new_lines.append(line)
    if not added:
        new_lines.append(line_to_add)
        added = True

    import shutil
    tmp_path = conf_path + '.tmp'
    with open(tmp_path, 'w') as conf_file:
        conf_file.write("\n".join(new_lines) + "\n")
    shutil.move(tmp_path, conf_path)
    with open(conf_path) as conf_file:
        new_conf_str = conf_file.read()
    logging.info("Wrote conf file %s:\n%s" % (conf_path, new_conf_str))


class LocalFlagUpdater:
    def __init__(self, args):
        self.args = args
        import socket
        self.host_name = socket.gethostname()
        self.success = True
        assert self.args.ip is not None
        self.common_msg_part = "set flag '%s' to '%s' on host %s (%s)" % (
            args.flag_name, args.flag_value, self.host_name, self.args.ip)

    def update_for_server_type(self, server_type_info):
        server_type = server_type_info['server_type']
        if server_type == 'master' and self.args.tserver_only:
            return
        if server_type == 'tserver' and self.args.master_only:
            return
        msg_common = self.common_msg_part + " for " + server_type

        rpc_port = server_type_info['rpc_port']
        server_binary = os.path.join(YUGABYTE_HOME, server_type, 'bin', 'yb-%s' % server_type)
        if not os.path.exists(server_binary):
            raise AppError("Server binary not found at %s" % server_binary)
        flag_types = get_valid_flag_types_for_binary(server_binary)
        if not self.args.flag_name in flag_types:
            raise AppError("Flag %s is invalid for server type %s" % (
                self.args.flag_name, server_type))
        flag_type = flag_types[self.args.flag_name]

        if flag_type == 'string':
            logging.info("Not attempting to set a flag of type %s in memory" % flag_type)
        else:
            ts_cli_cmd = [
                TS_CLI_PATH,
                '-server_address',
                "%s:%s" % (self.args.ip, rpc_port),
                'set_flag',
                '-force',
                self.args.flag_name,
                self.args.flag_value
            ]
            logging.info("Running command on %s: %s" % (self.host_name, ts_cli_cmd))

            try:
                subprocess.check_call(ts_cli_cmd)
                logging.info("Successfully %s in memory\n" % msg_common)
            except subprocess.CalledProcessError as ex:
                raise AppError(str(ex))

        if self.args.persist:
            modify_conf_file(
                server_type,
                self.args.flag_name,
                self.args.flag_value,
                msg_common)
            logging.info("Successfully %s in conf file", msg_common)

    def update(self):
        for server_type_info in SERVER_TYPE_INFO:
            try:
                self.update_for_server_type(server_type_info)
            except AppError as ex:
                logging.error("Failed to %s for server type %s: %s" % (
                    self.common_msg_part, server_type_info['server_type'], str(ex)))
                self.success = False

def main():
    arg_list = sys.argv[1:]
    if len(sys.argv) == 2:
        # A mechanism allowing to bypass Bash escaping and run the script over SSH.
        try:
            arg_list = json.loads(base64.b64decode(sys.argv[1]))
        except TypeError as ex:
            # Intentional -- we'll parse the arguments in the usual way.
            pass
        except ValueError as ex:
            # Ditto.
            pass

    args = parse_args(arg_list)

    if args.local:
        updater = LocalFlagUpdater(args)
        updater.update()
        sys.exit(0 if updater.success else 1)

    installer = ScriptInstaller()
    connect_cmds = validate_and_read_ssh_cmds(args.connect_cmds_file)

    num_successes = 0
    num_failures = 0
    ips = set()

    remote_args = arg_list + ['--local']

    for ssh_cmd in connect_cmds:
        ip = get_ip_from_ssh_cmd(ssh_cmd)
        ips.add(ip)

        logging.info('Processing node %s', ip)
        full_cmd = ssh_cmd + " '%s' %s" % (
            installer.get_script_cmd(),
            base64.b64encode(json.dumps(remote_args + ['--ip', ip])))

        if args.verbose:
            logging.info("Running command: %s", full_cmd)

        update_succeeded = False
        try:
            subprocess.check_call(['/bin/bash', '-c', full_cmd])
            what_did_we_do = "Updated"
            num_successes += 1
            update_succeeded = True
        except subprocess.CalledProcessError as ex:
            sys.stderr.write("Error: exit code %d from host %s%s" % (
                ex.returncode, ip, str(ex) if args.verbose else ''))
            what_did_we_do = "Failed updating"
            num_failures += 1

    sys.stderr.write(
        "Finished connecting to %d nodes (from %d commands)\n"
        "Total successes: %d\n"
        "Total failures: %d\n" % (
            len(ips),
            len(connect_cmds),
            num_successes,
            num_failures))


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s set_flags.py:%(lineno)d] %(message)s")

    main()
