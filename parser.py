from scapy.layers.inet import IP, TCP
from driver import *


def parse(packet):
    if IP in packet and TCP in packet and packet[TCP].dport == 80:
        return parse_http_request(packet)
    elif IP in packet and TCP in packet and packet[TCP].sport == 80:
        return parse_http_response(packet)
    else:
        return False


def parse_http_request(packet):
    body = str(packet[TCP].payload)
    if body is None or body == '':
        return False
    lines = body.split('\r\n')
    method = lines[0].split(' ')[0]
    path = lines[0].split(' ')[1]
    version = lines[0].split(' ')[2]
    struct = {}
    for header in lines[1:-2]:
        struct[header.split(': ')[0]] = header.split(': ')[1]

    struct['Method'] = method
    struct['Path'] = path
    struct['Version'] = version
    struct['Body'] = lines[-1]

    return http_request_driver(struct)


def parse_http_response(packet):
    body = str(packet[TCP].payload)
    if body is None or body == '':
        return False
    headers = body.split('\r\n\r\n')[0]
    code = headers.split('\r\n')[0].split(' ')[1]
    message = headers.split('\r\n')[0].split(' ')[2]
    version = headers.split('\r\n')[0].split(' ')[0]
    struct = {}
    for header in headers.split('\r\n')[1:]:
        struct[header.split(': ')[0]] = header.split(': ')[1]

    struct['Code'] = code
    struct['Message'] = message
    struct['Version'] = version
    struct['Body'] = body.split('\r\n\r\n')[1]
    return http_response_driver(struct)
