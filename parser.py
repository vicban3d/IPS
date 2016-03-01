"""
The parser disassembles packets and distributes them according to protocol in
order to ease the inspection process which takes place later. The parser builds
a struct and calls the appropriate driver on it.
"""

from scapy.layers.inet import IP, TCP, UDP

from driver import http_request_driver, http_response_driver, dns_driver
from util import str_to_hex

TCP_ACK = 0x10
HTTP_PORTS = (80, 8080)
DNS_PORTS = 53


def parse(packet):
    """
    Calls parsing functions according to protocol.
    :param packet: the packet to parse
    :return: The return value of the appropriate parser.
    """
    # HTTP request
    if IP in packet and TCP in packet and packet[TCP].dport in HTTP_PORTS:
        return parse_http_request(packet)
    # HTTP response
    elif IP in packet and TCP in packet and packet[TCP].sport in HTTP_PORTS:
        return parse_http_response(packet)
    # DNS query
    elif IP in packet and UDP in packet and packet.sport == DNS_PORTS:
        parse_dns(packet)
    # Allow anything else.
    else:
        return False


def parse_http_request(packet):
    """
    Parses packets that are regarded as HTTP requests
    :param packet: the packet to parse.
    :return: the return value of the relevant driver.
    """

    # the content of the HTTP request
    body = str(packet[TCP].payload)
    # if the packet had no content, allow it.
    if body is None or body == '':
        return False

    # get all parts of the packet.
    lines = body.split('\r\n')
    # the HTTP method
    method = lines[0].split(' ')[0]
    # the HTTP url
    path = lines[0].split(' ')[1]
    # the HTTP version
    version = lines[0].split(' ')[2]
    struct = {}
    # store all headers
    for header in lines[1:-2]:
        struct[header.split(': ')[0]] = header.split(': ')[1]

    struct['Method'] = method
    struct['Path'] = path
    struct['Version'] = version
    struct['Body'] = lines[-1]
    # call driver on struct
    return http_request_driver(struct)


def parse_http_response(packet):
    """
    Parses packets that are regarded as HTTP response
    :param packet: the packet to parse.
    :return: the return value of the relevant driver.
    """

    # the content of the HTTP response
    body = str(packet[TCP].payload)
    if body is None or body == '' or body[:4] != 'HTTP':
        return False

    # split headers from body
    body_parts = body.split('\r\n\r\n')
    headers = body_parts[0]

    content = (str_to_hex(body_parts[1])) if len(body_parts) > 1 else ''
    # response code
    code = headers.split('\r\n')[0].split(' ')[1]
    # response message
    message = headers.split('\r\n')[0].split(' ')[2]
    # response version
    version = headers.split('\r\n')[0].split(' ')[0]
    struct = {}
    # store all headers
    for header in headers.split('\r\n')[1:]:
        struct[header.split(': ')[0]] = header.split(': ')[1]

    struct['Code'] = code
    struct['Message'] = message
    struct['Version'] = version
    struct['Body'] = content
    # run driver on the HTTP response
    return http_response_driver(struct)


def parse_dns(packet):
    """
    Parses packets that are regarded as DNS queries.
    :param packet: the packet to parse.
    :return: the return value of the relevant driver.
    """
    # the content of the DNS packet
    body = packet['DNS']
    # read all DNS fiends from the packet
    query_id = body.id
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
        # store all questions
        for q in body.qd:
            name = q.qname
            query_type = q.qtype
            qclass = q.qclass
            question = {
                'Name': name,
                'Type': query_type,
                'Class': qclass
            }

            questions.append(question)
    if body.an is not None:
        # store all answers
        for a in body.an:
            name = a.rrname
            query_type = a.type
            rclass = a.rclass
            answer = {
                'Name': name,
                'Type': query_type,
                'Class': rclass
            }

            answers.append(answer)

    from collections import OrderedDict
    struct = OrderedDict()
    struct['Id'] = query_id
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

    # run the driver on the DNS packet
    return dns_driver(struct)
