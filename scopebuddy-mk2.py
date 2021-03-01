# Credit to https://github.com/kronicd/scopebuddy.py
# This is a rewritten version with increased support.

# Something to note, censys is free for non-commercial use, unsure if this violates that clause.
# Censys is also limited to 250 queries a month so this attempts to be very liberal on it's use.
# It is possible to use multiple burner accounts however not ideal.

# Note the crt.sh function does not utilise an official API and may be patched.

# Lastly, this is the version prior to full subdomain enumeration and discovery.

import argparse
import os
import socket
import shodan
import json
import requests
import sys
from ipwhois import IPWhois

parser = argparse.ArgumentParser()
parser.add_argument("-l", "--dnslist", default=f"{os.path.dirname(os.path.realpath(__file__))}/dnslist.txt", help="A file containing a list of domain names separated by newlines. Default: dnslist.txt")
parser.add_argument("-s", "--shodan", default=False, action="store_false", help="Disable the Shodan Search engine portion. Default: False")
parser.add_argument("-t", "--crtsh", default=True, action="store_false", help="Disable the crt.sh search engine. Default: True")
parser.add_argument("-te", "--crtsh_expired", default=True, action="store_false", help="Whether to include expired certificates. Default: False")
parser.add_argument("-c", "--config", default=f"{os.path.dirname(os.path.realpath(__file__))}/config.json", help="Provide a custom configuration file containing API keys and credentials. Default: config.json")
parser.add_argument("-d", "--delim", default="\n", help="Delimeter for the output file. Default is newline.")

args = parser.parse_args()

SHODAN_APIKEY = None

SHODAN_LOADED = False

try:
    with open(args.config, "r") as f:
        conf = json.load(f)
        SHODAN_APIKEY = conf["shodan_api_key"]

        SHODAN_LOADED = bool(SHODAN_APIKEY)
except FileNotFoundError:
    print("Configuration file does not exist, please create one in order to fully utilise this tool.")
except KeyError:
    print("Malformed configuration file. Please check the JSON formatting.")
except ValueError:
    print("Configuration file is empty. Skipping Shodan function.")

class target:
    def __init__(self, domain_name = None, v4 = None,):
        self.v4 = v4
        self.v4_addresses = None
        self.domain_name = domain_name
        self.dns_info = ["None", None]
        self.rdap = None
        self.shodan = None
        self.shodan_ports = None
        self.crt = None
        self.crt_json = None

    def get_shodan(self):
        if SHODAN_LOADED and args.shodan:
            if not self.shodan:
                try:
                    api = shodan.Shodan(SHODAN_APIKEY)
                    self.shodan = api.host(self.get_ipv4())
                except shodan.APIError:
                    print("Shodan API returned an error. Possibly an invalid API key or a rate limit?")
        return self.shodan

    def get_shodan_ports(self):
        if SHODAN_LOADED and args.shodan:
            if not self.shodan_ports:
                ports = (f'{item["port"]}({item["_shodan"]["module"]})' for item in self.get_shodan()["data"])
                self.shodan_ports = ','.join(ports)
        return self.shodan_ports

    def get_rdap(self):
        if not self.rdap:
            try:
                self.rdap = IPWhois(self.get_ipv4()).lookup_rdap(depth=1)
            except Exception:
                pass
        
        return self.rdap

    def get_ipv4(self, full = False):
        if not self.v4:
            try:
                v4 = socket.gethostbyname_ex(self.domain_name)
                self.v4 = v4[2][0]
                self.v4_addresses = v4[2] # All responding IP addresses.
            except Exception as e:
                pass

        return self.v4_addresses if full else self.v4

    def get_dns_info(self):
        rdns = "None"
        cname = {}

        if not self.dns_info or self.dns_info == ["None", None]:
            try:
                ret_rdns = socket.gethostbyaddr(self.get_ipv4())
                rdns = ret_rdns[0]
                try:
                    ret_cname = socket.gethostbyname_ex(rdns)
                    cname = ret_cname[1] # Only grab the aliases.
                except Exception:
                    pass
            except Exception as e:
                #print(f"Error occured returning RDNS. {e}")
                pass

            self.dns_info = [rdns, cname]

        return self.dns_info

def get_crtsh_domains(domains):
    base_url = "https://crt.sh/?q={}&output=json" if args.crtsh_expired else "https://crt.sh/?q={}&output=json&exclude=expired"

    new_domains = []

    for domain in domains:
        req = requests.get(base_url.format(domain), headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36"})

        crtsh = None
        if req.ok:
            try:
                content = req.content.decode("utf-8")
                crtsh = json.loads(content)
            except Exception as e:
                #print("Error occured reading content. {}".format(e))
                pass
        else:
            print("Get CRT request returned non 200")
        
        if crtsh:
            for cert in crtsh:
                found = cert["name_value"].split("\n") # Sometimes cert names have newlines in them. Idk why.
                for domain in found:
                    if not domain in new_domains and not domain in domains:
                        new_domains.append(domain)

    return domains + new_domains

def csv_escape(str):
    return f"\"{str}\""

domains = None

try:
    domains = [line.rstrip("\n") for line in open(args.dnslist, "r")]
except FileNotFoundError:
    print("dnslist.txt file does not exist, please create it before running this again.")
except ValueError:
    print("DNSList file is empty. Please add to it before running this again.")

if not domains:
    print("Error occurred when collecting domains.")
    sys.exit(1)

domains = get_crtsh_domains(domains) if args.crtsh else domains

first_line = True
output = ""

for domain in domains:
    obj = target(domain_name=domain)
    addresses = obj.get_ipv4(True)
    if addresses:
        for ip in addresses:
            # Note the IP Host parameter contains a comma by default, messing up CSV formatting.

            data = {}
            data["IP"] = ip
            data["Domain"] = domain
            data["RDNS"] = obj.get_dns_info()[0] or "N/A"
            data["ASN"] = obj.get_rdap()["asn"] or "N/A"
            data["IP Host"] = obj.get_rdap()['asn_description'] or "N/A"
            data["BGP CIDR"] = obj.get_rdap()["network"]["cidr"] or "N/A"
            data["Whois CIDR"] = obj.get_rdap()["asn_cidr"] or "N/A"
            data["Shodan Ports"] = obj.get_shodan_ports() or "N/A"

            line = ""

            if first_line:
                first_line = False
                for column in data:
                    line = f"{line}{column},"
                output = f"{output}{line.rstrip(',')}\n"
                line = ""

            for column in data:
                line = f"{line}{csv_escape(data[column])},"

            output = f"{output}{line.rstrip(',')}\n"

with open("out.csv", "w", encoding="utf-8") as f:
    f.write(output)