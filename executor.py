"""
The executor sends received packets to the parser and act according to its
response.

This is the place where fragmentation support can be implemented to store
 fragments in a buffer and assemble them before sending to the parser.
"""

from scapy.sendrecv import send

from parser import parse
from scapy.layers.inet import IP, TCP
from scapy.all import conf
import time
RST_FLAG = 0x04


def execute(packet):
    """
    Pass packet to the parser for disassembly and act according to its return
    value. The packet is dropped if the parser returns True, else it is allowed.
    :param packet: the received packet.
    :return: None.
    """
    current_packet = IP(packet.get_payload())
    if parse(current_packet):
        print 'Verdict: DROP'
        # send reset to both sides to terminate connection.
        send_reset(current_packet)
        packet.drop()
    else:
    	print current_packet.show()
        packet.accept()


def send_reset(original_packet):
    """
    sends a reset message to both parties of a connection
    :param original_packet: the packet that the reset replies to
    :return: None
    """
    dst_port = original_packet['TCP'].dport
    src_port = original_packet['TCP'].sport
    src_ip = original_packet['IP'].src
    dst_ip = original_packet['IP'].dst

    send(IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port,
                                          flags=RST_FLAG,
                                          seq=original_packet['TCP'].ack),
         verbose=False)
    send(IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port,
                                          flags=RST_FLAG,
                                          seq=original_packet['TCP'].seq),
         verbose=False)
