from blueman.main.PulseAudioUtils import pa_card_info
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Padding

from util import str_to_hex
from driver import *

TCP_ACK = 0x10
HTTP_PORTS = (80, 8080)
DNS_PORTS = 53


def parse(packet):
    if IP in packet and TCP in packet and packet[TCP].dport in HTTP_PORTS:
        return parse_http_request(packet)
    elif IP in packet and TCP in packet and packet[TCP].sport in HTTP_PORTS:
        return parse_http_response(packet)
    elif IP in packet and UDP in packet and packet.sport == DNS_PORTS:
        parse_dns(packet)
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
    if body is None or body == '' or body[:4] != 'HTTP':
        return False
    body_parts = body.split('\r\n\r\n')

    headers = body_parts[0]

    content = (str_to_hex(body_parts[1])) if len(body_parts) > 1 else ''
    code = headers.split('\r\n')[0].split(' ')[1]
    message = headers.split('\r\n')[0].split(' ')[2]
    version = headers.split('\r\n')[0].split(' ')[0]
    struct = {}

    for header in headers.split('\r\n')[1:]:
        struct[header.split(': ')[0]] = header.split(': ')[1]

    struct['Code'] = code
    struct['Message'] = message
    struct['Version'] = version
    struct['Body'] = content

    return http_response_driver(struct)


def parse_dns(packet):
    body = packet['DNS']

    id = body.id
    qr = body.qr
    opcode = body.opcode
    aa = body.aa
    tc = body.tc
    rd = body.rd
    ra = body.ra
    z = body.z
    rcode = body.rcode
    total_questions = body.qdcount
    total_answers = body.ancount
    total_authority = body.nscount
    total_additional = body.arcount
    ns = body.ns
    questions = []
    answers = []
    if body.qd is not None:
        for q in body.qd:
            name = q.qname
            type = q.qtype
            qclass = q.qclass
            question = {
                'Name': name,
                'Type': type,
                'Class': qclass
            }

            questions.append(question)
    if body.an is not None:
        for a in body.an:
            name = a.rrname
            type = a.type
            rclass = a.rclass
            answer = {
                'Name': name,
                'Type': type,
                'Class': rclass
            }

            answers.append(answer)

    from collections import OrderedDict
    struct = OrderedDict()
    struct['Id'] = id
    struct['QR'] = qr
    struct['Opcode'] = opcode
    struct['Authoritative Answer'] = aa
    struct['Truncated'] = tc
    struct['Recursion Desired'] = rd
    struct['Recursion Available'] = ra
    struct['Z'] = z
    struct['Return Code'] = rcode
    struct['Total Questions'] = total_questions
    struct['Total Answers'] = total_answers
    struct['Total Authority'] = total_authority
    struct['Total Additional'] = total_additional
    struct['Questions'] = questions
    struct['Answers'] = answers
    struct['NS'] = ns
    struct['Padding'] = packet['Padding'].load

    return dns_driver(struct)
