#!/usr/bin/python3

import argparse
import atexit
import json
import logging
import requests
import socket
import subprocess
import threading
import time

from bcc import BPF
from pyroute2 import IPRoute


HANDSHAKE_TIMEOUT = 10  # An handshake with a SYN_ACK is considered incomplete
                        # this number of seconds after the reception of the
                        # first SYN

HANDSHAKES_THRESHOLD = 5  # Number of incomplete handshakes after which a
                          # source is considered malicious

MONITORING_TIME = 60  # Number of seconds over which the number of incomplete 
                      # handshakes is computed

# MONITORING_TIME is split in windows of HANDSHAKE_TIMEOUT seconds
WINDOWS_COUNT = int(MONITORING_TIME / HANDSHAKE_TIMEOUT)

HANDSHAKE_PURGE_TIME = 60  # An handshake that didn't receive a SYN_ACK is
                           # removed from the map after this time


def cleanup():
    LOGGER.info('Removing filters from devices')
    for ifindex in ifindexes:
        if args.action == 'mitigate':
            subprocess.run(['polycubectl', 'ddosmitigator', 'del',
                            'dm' + str(ifindex)],
                           stdout=subprocess.DEVNULL)

        ip.tc('del', 'clsact', ifindex)

def get_uptime_ms():
    with open('/proc/uptime', 'r') as f:
        return float(f.readline().split()[0]) * 1000

def mitigate_attack(malicious_sources):
    """
    Add malicious addresses to source blacklist of DDoS Mitigator cubes on
    configured interfaces
    """
    payload = [{'ip': socket.inet_ntoa(addr.to_bytes(4, 'little'))}
               for addr in malicious_sources]
    for i, ifindex in enumerate(ifindexes):
        r = requests.post('http://localhost:9000/polycube/v1/ddosmitigator/dm' +
                          str(ifindex) + '/blacklist-src',
                          data=json.dumps(payload))
        if r.status_code == 201:
            LOGGER.info('Addresses blacklisted on interface %s', 
                        args.interfaces[i])
        else:
            LOGGER.error('Error adding addresses to blacklist on interface ' +
                         '%s: %s', args.interfaces[i], r.text)


parser = argparse.ArgumentParser()
parser.add_argument('interfaces', help='Network interfaces to monitor',
                    nargs="+", type=str)
parser.add_argument('-a --action', help='Action to perform on malicious ' +
                    'addresses: mitigate: drop packets with Polycube DDoS ' +
                    'Mitigator; print: print addresses; none', dest='action',
                    choices=['mitigate', 'print', 'none'], default='none',
                    type=str)
parser.add_argument('-l --logfile', help='File to print log to', dest='logfile',
                    type=str)
args = parser.parse_args()

# Configure logger
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('[%(levelname)s] [%(created)f] %(message)s')
ch.setFormatter(formatter)
LOGGER.addHandler(ch)
if args.logfile:
    fh = logging.FileHandler(args.logfile)
    fh.setFormatter(formatter)
    LOGGER.addHandler(fh)

atexit.register(cleanup)

if args.action == 'mitigate':
    # Check polycube is running
    if subprocess.run('polycubectl', stdout=subprocess.DEVNULL).returncode != 0:
        LOGGER.error('Polycube not running')
        exit(1)

# Load eBPF programs
b = BPF(src_file='detector.c', debug=0)
ingress_fn = b.load_func('monitor_ingress', BPF.SCHED_CLS)
egress_fn = b.load_func('monitor_egress', BPF.SCHED_CLS)
pending_handshakes = b.get_table('pending_handshakes')

ip = IPRoute()

ifindexes = []
for iface in args.interfaces:
    ifindexes.append(ip.link_lookup(ifname=iface)[0])

    if args.action == 'mitigate':
        # Add DDoS Mitigator cube to interface in XDP_DRV mode
        cube_name = 'dm' + str(ifindexes[-1])
        subprocess.run(['polycubectl', 'ddosmitigator', 'add', cube_name,
                        'type=xdp_drv'],
                       stdout=subprocess.DEVNULL, check=True)
        subprocess.run(['polycubectl', 'attach', cube_name, iface],
                       stdout=subprocess.DEVNULL, check=True)

    # Create TC qdisc and attach programs
    ip.tc('add', 'clsact', ifindexes[-1])
    ip.tc('add-filter', 'bpf', ifindexes[-1], ':1', fd=ingress_fn.fd,
        name=ingress_fn.name, parent='ffff:fff2', classid=1, direct_action=True)
    ip.tc('add-filter', 'bpf', ifindexes[-1], ':1', fd=egress_fn.fd,
          name=egress_fn.name, parent='ffff:fff3', classid=1,
          direct_action=True)

incomplete_handshakes = {}  # Count of incomplete handshakes for every src
                            # address over the whole MONITORING_TIME

# Circular buffer containing, for every window, the number of incomplete
# handshakes of every source address
monitoring_windows = [{}] * WINDOWS_COUNT
current_window = 0

global_malicious_source = set()  # Potentially malicius sources found during all
                                 # the execution of the detector

sleep_until = time.time()

LOGGER.info('Monitoring interfaces, hit CTRL+C to stop')
while 1:
    try:
        sleep_until += HANDSHAKE_TIMEOUT
        try:
            time.sleep(sleep_until - time.time())
        except ValueError:
            # If sleep time is negative don't sleep
            pass

        LOGGER.info('Checking handshakes')

        # Remove handshakes of the oldest window
        for saddr, handshakes in monitoring_windows[current_window].items():
            incomplete_handshakes[saddr] -= handshakes
        monitoring_windows[current_window] = {}

        active_sources = set()  # Source addresses that have incomplete
                                # handshakes in the current window

        # Look for incomplete handshakes
        for session, handshake in pending_handshakes.items():
            if handshake.synack_sent:
                if (get_uptime_ms() - handshake.begin_time/1000000 >=
                    HANDSHAKE_TIMEOUT * 1000):
                    active_sources.add(session.saddr)

                    # Add handshake to the current window
                    if session.saddr in monitoring_windows[current_window]:
                        monitoring_windows[current_window][session.saddr] += 1
                    else:
                        monitoring_windows[current_window][session.saddr] = 1

                    # Add handshake to the global counter
                    if session.saddr in incomplete_handshakes:
                        incomplete_handshakes[session.saddr] += 1
                    else:
                        incomplete_handshakes[session.saddr] = 1

                    del pending_handshakes[session]

            elif (get_uptime_ms() - handshake.begin_time/1000000 >=
                  HANDSHAKE_PURGE_TIME * 1000):
                del pending_handshakes[session]

        # Look for potentially malicious sources
        malicious_sources = []
        for saddr in active_sources:
            if (incomplete_handshakes[saddr] > HANDSHAKES_THRESHOLD):
                malicious_sources.append(saddr)
                global_malicious_source.add(saddr)

        if len(malicious_sources) > 0:
            LOGGER.info('Detected %d new potentially malicious source ' +
                        'addresses. Total %d', len(malicious_sources),
                        len(global_malicious_source))

            if args.action == 'mitigate':
                mitigate_attack(malicious_sources)
            elif args.action == 'print':
                for saddr in malicious_sources:
                    print(socket.inet_ntoa(saddr.to_bytes(4, 'little')))

        else:
            LOGGER.info('No new potentially malicious source addresses ' +
                        'detected. Total %d', len(global_malicious_source))

        current_window = (current_window + 1) % WINDOWS_COUNT

    except KeyboardInterrupt:
      break