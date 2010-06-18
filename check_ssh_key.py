#!/usr/bin/python

import os
import sys
import optparse
import paramiko
import socket
import errno

from nagios import nagios

class Result (Exception):
    def __init__ (self, status, msg):
        super(Result, self).__init__()
        self.status = status
        self.msg = msg

def parse_args():
    p = optparse.OptionParser()

    p.add_option('-f', '--known-hosts-file')
    p.add_option('-p', '--port', default='22')
    p.add_option('-t', '--timeout')
    p.add_option('-s', '--strict', action='store_true')
    p.add_option('-v', '--verbose', action='store_true')

    return p.parse_args()

def connect(server_name, port):
    s = socket.socket(socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP)
    s.connect((server_name, int(port)))
    return s

def ssh_connect(server_name, opts):
    try:
        s = connect(server_name, opts.port)
        t = paramiko.Transport(s)
        t.start_client()
        key = t.get_remote_server_key()
        t.close()
    except paramiko.SSHException, detail:
        raise Result(nagios.NAGIOS_STATUS_CRIT,
                '%s: protocol error: %s' % (server_name, detail))
    except socket.error, detail:
        raise Result(nagios.NAGIOS_STATUS_CRIT,
                '%s: %s' % (server_name, detail.strerror))

    return (key, t.remote_version)

def check_ssh(opts, args):
    try:
        server_name = args.pop(0)
    except IndexError:
        raise Result(nagios.NAGIOS_STATUS_WTF,
                'You must provide a hostname.')

    try:
        hosts = paramiko.HostKeys(filename=opts.known_hosts_file)
    except IOError, detail:
        raise Result(nagios.NAGIOS_STATUS_WTF,
                '%s: %s' % (opts.known_hosts_file, detail.strerror))

    key,remote_version = ssh_connect(server_name, opts)

    if opts.verbose:
        print '%s host key fingerprint:' % server_name, \
                ':'.join(['%02X' % ord(x) for x in
                    key.get_fingerprint()])

    try:
        hostent = hosts.lookup(server_name)
        if hostent is None and not opts.strict:
            hosts.add(server_name, key.get_name(), key)
            if opts.known_hosts_file:
                if opts.verbose:
                    print 'Adding %s to %s.' % (server_name,
                            opts.known_hosts_file)
                hosts.save(opts.known_hosts_file)
    except IOError, detail:
        raise Result(nagios.NAGIOS_STATUS_WTF,
                '%s: %s' % (opts.known_hosts_file, detail.strerror))

    if not hosts.check(server_name, key):
        raise Result(nagios.NAGIOS_STATUS_CRIT,
                '%s: host key verification failed' % server_name)
    else:
        raise Result(nagios.NAGIOS_STATUS_OKAY,
                '%s: %s' % (server_name, remote_version))

def main():
    opts, args = parse_args()

    try:
        check_ssh(opts, args)
    except Result, detail:
        nagios.result('SSH',
                detail.status,
                detail.msg)
    except Exception, detail:
        nagios.result('SSH',
                nagios.NAGIOS_STATUS_WTF,
                'unexpected error: %s' % detail)

if __name__ == '__main__':
    x = main()

