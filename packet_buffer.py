"""
The packet buffer receives packets from the network interface and passes those
 meant for forwarding to the executor for processing.
"""

import os
from netfilterqueue import NetfilterQueue

from executor import execute


def start():
    """
    Start the netfilterqueue and binds it to the executor.
    :return: None.
    """
    # place all packets marked for forwarding in queue
    os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')

    # start catching packets
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, execute)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        os.system('iptables -F')
        os.system('iptables -X')
