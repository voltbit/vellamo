#!/usr/bin/python3
from __future__ import print_function
import sys
import subprocess
import re
from colorama import init, Fore, Back, Style
init(autoreset=True)

try:
    import colorama
except:
    print("Missing one of the packages, please see requirements.txt")

class Generators(object):
    mapping = {
        "cert": "ssl.handshake.certificate",
        "sni": "ssl.handshake.extensions_server_name"
    }

class Settings(object):
    ''' Class that defines profiles (what the shark should fetch for you). '''
    ATIP = ['cert', 'sni']

class Shark(object):
    ''' Class used to extract data from pcap files. '''
    tshark_filter_root = ['tshark', '-r', '', '-Y', '', '-V']
    def __init__(self, profile, filename):
        self.profile = profile
        self.filename = filename

    def fetch_cert(self):
        print(Fore.GREEN + Style.BRIGHT + "---[ Id at common name ]---")
        cert_filter = self.tshark_filter_root
        cert_filter[2] = self.filename
        cert_filter[4] = Generators.mapping['cert']
        cert_filter = " ".join(cert_filter)
        cert_data = subprocess.Popen(cert_filter + " | grep 'Certificate:'", shell=True, stdout=subprocess.PIPE).stdout.read()
        cert_data = cert_data.decode("utf-8").split('\n')
        cert_data = [re.search('id-at-commonName=(.*)', x) for x in cert_data]
        cert_data = set([x.group(1).split(',')[0] for x in cert_data if x])
        cert_data = [x for x in cert_data if not ' ' in x]
        # print(cert_data)
        for x in cert_data:
            print(x)

    def fetch_sni(self):
        print(Fore.GREEN + Style.BRIGHT + "---[ Server name indication ]---")
        cert_filter = self.tshark_filter_root
        cert_filter[2] = self.filename
        cert_filter[4] = Generators.mapping['sni']
        cert_filter = " ".join(cert_filter)
        sni_data = subprocess.Popen(cert_filter + " | grep 'Server Name:'", shell=True, stdout=subprocess.PIPE).stdout.read()
        sni_data = sni_data.decode("utf-8").split('\n')
        sni_data = set([x.split(' ')[-1] for x in sni_data if x])
        # print(sni_data)
        for x in sni_data:
            print(x)

    def fetch(self):
        self.fetch_cert()
        self.fetch_sni()

def main():
    if len(sys.argv) != 2:
        print("Use: agwe.py <pcap_file_name>")
        sys.exit(1)
    shark = Shark(Settings.ATIP, sys.argv[1])
    shark.fetch()

if __name__ == "__main__":
    main()
