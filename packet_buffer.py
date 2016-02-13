import os
from netfilterqueue import NetfilterQueue

from executor import execute


def start():
    # place all packets marked for forwarding in queue
    os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')

    # start catching packets
    NFQUEUE = NetfilterQueue()
    NFQUEUE.bind(1, execute)
    try:
        NFQUEUE.run()
    except KeyboardInterrupt:
        os.system('iptables -F')
        os.system('iptables -X')
