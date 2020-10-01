#!/usr/bin/python3

import argparse
import requests
import time


def get_requests():
    r = s.get('http://localhost/nginx_status')
    if r.status_code != 200:
        print('Error contacting NGINX')
        exit(1)

    return int(r.text.split('\n')[2].split(' ')[3])


parser = argparse.ArgumentParser(description='Monitors the average number of ' +
                                 'requests per second handled by the NGINX ' +
                                 'web server.')
parser.add_argument('interval', help='Query interval of NGINX metrics',
                    type=int)
parser.add_argument('-l --logfile', help='File to print log to', dest='logfile',
                    type=str)
args = parser.parse_args()


if args.logfile:
    log = open(args.logfile, 'w')

s = requests.Session()

old_reqs = get_requests()
last_check = time.time()

print('Monitoring NGINX, hit CTRL+C to stop')
sleep_until = time.time()
while True:
    try:
        sleep_until += args.interval
        try:
            time.sleep(sleep_until - time.time())
        except ValueError:
            # If sleep time is negative don't sleep
            pass

        reqs = get_requests()
        now = time.time()
        rate = (reqs - old_reqs - 1) / (now - last_check)
        print('%.3f: %.2f' % (now, rate))
        if args.logfile:
            log.write('%.3f,%.2f\n' % (now, rate))
        old_reqs = reqs
        last_check = now

    except KeyboardInterrupt:
        break

if args.logfile:
    log.close()