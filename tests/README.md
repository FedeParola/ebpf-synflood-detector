# Testing
A possible testing scenario is composed by two machines connected back-to-back with two links. One machine operates as *Device Under Test (DUT)* running an *NGINX* web server and the detection tool, while the other one generates both the SYN Flood attack and legitimate requests to the server.

The `tcp-syn-flood.lua` [*MoonGen*](https://github.com/emmericp/MoonGen) script is provided to generate a high rate attack from different source IP addresses.

The [weighttp](https://github.com/lighttpd/weighttp) tool can be used to perform HTTP requests to the Nginx server and benchmark its performance.

The `monitor-nginx.py` script is provided to monitor the number of requests handled by *NGINX* in real time.

Since *MoonGen* relies on *DPDK* and takes full control of a NIC two devices are needed to concurrently send both the attack and legitimate traffic.

Testing scenario:
```
       Tester                        DUT
 +---------------+      +--------------------------+
 |               |      |       TC                 |
 |  +---------+  |      |  +----------+  +-------+ |
 |  | MoonGen |--|------|--|          |--|       | |
 |  +---------+  |      |  |          |  |       | |
 |               |      |  | Detector |  | NGINX | |
 | +----------+  |      |  |          |  |       | |
 | | weighttp |--|------|--|          |--|       | |
 | +----------+  |      |  +----------+  +-------+ |
 |               |      |                          |
 +---------------+      +--------------------------+
```

## tcp-syn-flood.lua
```
Usage: MoonGen tcp-syn-flood.lua [-r <rate>] [-c <core>] [-s <src>] [-d <dst>] [--dmac <dmac>]
       [--sport <sport>] [--dport <dport>] [--ipsnum <ipsnum>] [--portsnum <portsnum>] [-l <len>] [-h] <dev>

Generates TCP SYN flood from varying source IPs and ports.

Arguments:
   dev                                  Device to transmit from.

Options:
   -r <rate>, --rate <rate>             Transmit rate in Mbit/s. (default: 0)
   -c <core>, --core <core>             Number of cores. (default: 1)
   -s <src>, --src <src>                Source IP address. (default: 10.0.0.1)
   -d <dst>, --dst <dst>                Destination IP address.
   --dmac <dmac>                        Destination MAC address.
   --sport <sport>                      Source port. (default: 1000)
   --dport <dport>                      Destination port. (default: 80)
   --ipsnum <ipsnum>                    Number of different source IPs to use. (default: 100)
   --portsnum <portsnum>                Number of different source ports to use. (default: 100)
   -l <len>, --len <len>                Length of the ethernet frame containing the SYN packet (including CRC) (default: 64)
   -h, --help                           Show this help message and exit.
```

## monitor-nginx.py
```
usage: monitor-nginx.py [-h] [-l --logfile LOGFILE] interval

Monitors the average number of requests per second handled by the NGINX web
server.

positional arguments:
  interval              Query interval of NGINX metrics

optional arguments:
  -h, --help            show this help message and exit
  -l --logfile LOGFILE  File to print log to
```
For this tool to work the **stub_status** module of *NGINX* must be enabled and accessible at path `/nginx_status`. To do this:
1. Check if the module is available: `nginx -V 2>&1 | grep --color -- --with-http_stub_status_module`.
2. Add the following lines to the server block of yout NGINX configuration file (usually `/etc/nginx/sites-enabled/default`):
```
listen 127.0.0.1:80;
server_name 127.0.0.1;

location /nginx_status {
    stub_status;
}
```
3. Restart NGINX: `sudo systemctl restart nginx`