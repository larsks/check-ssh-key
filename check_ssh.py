#!/usr/bin/python

import os
import sys
import optparse
import paramiko
import socket
import errno

from nagios import nagios

def parse_args():
    p = optparse.OptionParser()

    p.add_option('-f', '--known-hosts-file')
    p.add_option('-p', '--port', default='22')
    p.add_option('-t', '--timeout')
    p.add_option('-s', '--strict', action='store_true')
    p.add_option('-v', '--verbose', action='store_true')

    return p.parse_args()

def main():
    opts, args = parse_args()

    try:
        server_name = args.pop(0)
    except IndexError:
        nagios.result('SSH',
                nagios.NAGIOS_STATUS_WTF,
                'You must provide a hostname.')

    try:
        hosts = paramiko.HostKeys(filename=opts.known_hosts_file)
    except IOError, detail:
        nagios.result('SSH',
                nagios.NAGIOS_STATUS_WTF,
                '%s: %s' % (opts.known_hosts_file, detail.strerror))

    try:
        s = socket.socket(socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP)
        s.connect((server_name, int(opts.port)))
    except socket.error, detail:
        nagios.result('SSH',
                nagios.NAGIOS_STATUS_CRIT,
                '%s: %s' % (server_name, detail.strerror))

    try:
        t = paramiko.Transport(s)
        t.start_client()
        key = t.get_remote_server_key()
    except paramiko.SSHException:
        nagios.result('SSH',
                nagios.NAGIOS_STATUS_CRIT,
                '%s: protocol error' % server_name)

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
        nagios.result('SSH',
                nagios.NAGIOS_STATUS_WTF,
                '%s: %s' % (opts.known_hosts_file, detail.strerror))

    if not hosts.check(server_name, key):
        nagios.result('SSH',
                nagios.NAGIOS_STATUS_CRIT,
                '%s: host key verification failed' % server_name)
    else:
        nagios.result('SSH',
                nagios.NAGIOS_STATUS_OKAY,
                '%s: %s' % (server_name, t.remote_version))

if __name__ == '__main__':
    x = main()

