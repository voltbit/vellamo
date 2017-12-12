#!/usr/bin/python3
from __future__ import print_function
import sys
import subprocess
import re
import argparse
from multiprocessing import Process, Lock
from colorama import init, Fore, Back, Style
init(autoreset=True)

class Generators(object):
    mapping = {
        "cert": "ssl.handshake.certificate",
        "sni": "ssl.handshake.extensions_server_name",
        "http": "'http.response || http.request'",
    }

class Filters(object):
	greps = {
        "cert": " | grep 'Certificate:\|Certificate '",
		"sni": " | grep 'Server Name:'",
		"http": " | grep 'Host\|Referer\|X-Requested-With\|URI Path\|URI Query'",
		# "http": " | grep 'Host\|Referer\|X-Requested-With'",
	}

class Settings(object):
    ''' Class that defines profiles (what the shark should fetch for you). '''
    ATIP = ['cert', 'sni', 'http']

class Shark(object):
    ''' Class used to extract data from pcap files. '''

    tshark_filter_root = ['tshark', '-V', '-r', '', '-Y', '']

    def __init__(self, profile, filename, keywords):
        self.profile = profile
        self.filename = filename
        self.keywords = keywords

    def fetch_cert(self, iolock):
        cert_cmd = self.tshark_filter_root
        cert_cmd[3] = self.filename
        cert_cmd[5] = Generators.mapping['cert']
        cert_cmd = " ".join(cert_cmd) + Filters.greps['cert']
        cert_data = subprocess.Popen(cert_cmd, shell=True,
            stdout=subprocess.PIPE).stdout.read()
        cert_data = cert_data.decode("utf-8").split('\n')
        cert_data = [re.search('id-at-commonName=(.*)', x) for x in cert_data]
        cert_data = set([x.group(1).split(',')[0] for x in cert_data if x])
        cert_data = [x for x in cert_data if not ' ' in x]
        iolock.acquire()
        print(Fore.GREEN + Style.BRIGHT + "\n---[ Cert Id at common name ]---")
        if self.keywords:
            for x in sorted([x[::-1] for x in cert_data]):
                if any(keyword in x[::-1] for keyword in self.keywords):
                    print(x[::-1])
        else:
            for x in sorted([x[::-1] for x in cert_data]):
                print(x[::-1])
        iolock.release()

    def fetch_sni(self, iolock):
        sni_cmd = self.tshark_filter_root
        sni_cmd[3] = self.filename
        sni_cmd[5] = Generators.mapping['sni']
        sni_cmd = " ".join(sni_cmd) + Filters.greps['sni']
        sni_data = subprocess.Popen(sni_cmd, shell=True,
            stdout=subprocess.PIPE).stdout.read()
        sni_data = sni_data.decode("utf-8").split('\n')
        sni_data = set([x.split(' ')[-1] for x in sni_data if x])
        iolock.acquire()
        print(Fore.GREEN + Style.BRIGHT + "\n---[ SNI - Server name indication ]---")
        if self.keywords:
            for x in sorted([x[::-1] for x in sni_data]):
                if any(keyword in x[::-1] for keyword in self.keywords):
                    print(x[::-1])
        else:
            for x in sorted([x[::-1] for x in sni_data]):
                print(x[::-1])
        iolock.release()

    def fetch_http(self, iolock):
        http_cmd = self.tshark_filter_root
        http_cmd[3] = self.filename
        http_cmd[5] = Generators.mapping['http']
        http_cmd = " ".join(http_cmd) + Filters.greps['http']
        http_data = subprocess.Popen(http_cmd, shell=True,
            stdout=subprocess.PIPE).stdout.read()
        http_data = http_data.decode("utf-8").split('\n')
        http_data = [x.split(' ')[-2:] for x in http_data if x]
        http_data = sorted(set([x for x in zip([x[0] for x in http_data], [x[1].replace('\\r\\n', "") for x in http_data])])) # why doesn't strip/rstrip work?
        print(Fore.GREEN + Style.BRIGHT + "\n---[ HTTP fields ]---")
        iolock.acquire()
        if self.keywords:
            for x in sorted(http_data):
                if any(keyword in x[1] for keyword in self.keywords):
                    print(x[0], x[1])
        else:
            for x in sorted(http_data):
                print(x[0], x[1])
        iolock.release()

    def fetch(self):
        '''
        Send the shark to bring something useful.
        '''
        ioclock = Lock()
        cert_p = Process(target=self.fetch_cert, args=(ioclock,))
        sni_p = Process(target=self.fetch_sni, args=(ioclock,))
        http_p = Process(target=self.fetch_http, args=(ioclock,))

        cert_p.start()
        sni_p.start()
        http_p.start()

        cert_p.join()
        sni_p.join()
        http_p.join()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', type=str, help="name of target pcap file")
    parser.add_argument('-k', '--keywords',  nargs='+', type=str, default=None,
        help="specify one or more keywords - only entries containg the keywords will be displayed")
    args = parser.parse_args()

    # if len(sys.argv) != 2:
    #     print("Use: vellamo.py <pcap_file_name>")
    #     sys.exit(1)
    shark = Shark(Settings.ATIP, args.filename, args.keywords)
    shark.fetch()

if __name__ == "__main__":
    main()
