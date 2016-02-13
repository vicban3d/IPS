from scapy.sendrecv import send

from parser import parse
from scapy.layers.inet import IP, TCP
from scapy.all import conf
RST_FLAG = 0x04


def execute(packet):
    current_packet = IP(packet.get_payload())
    if parse(current_packet):
        print 'Verdict: DROP'
        send_reset(current_packet)
        packet.drop()
    else:
        packet.accept()


# returns a reset to the sender.
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
