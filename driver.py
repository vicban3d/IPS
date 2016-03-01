"""
The driver runs all relevant signatures in order to inspect the given structure
filtered by protocol.

Every signature must have a check(struct) method which inspects the given packet
and decides whether it contains an attack.

Each signature must have a prot_id field which identifies the signature uniquely
and must be placed in the relevant package under protections.

Signatures should be documented to better understand their purpose.

"""


def http_request_driver(struct):
    """
    Runs all signatures related to HTTP requests.
    Any new protections must be attached here.
    :param struct: the HTTP request packet.
    :return: True if an exploit was detected, else False.
    """
    from protections.http_request import \
        sig_1,\
        sig_2

    protections = [
        sig_1,
        sig_2
    ]
    return run_all(protections, struct)


def http_response_driver(struct):
    """
    Runs all signatures related to HTTP responses.
    Any new protections must be attached here.
    :param struct: the HTTP response packet.
    :return: True if an exploit was detected, else False.
    """
    from protections.http_response import \
        sig_3,\
        sig_4

    protections = [
        sig_3,
        sig_4
    ]
    return run_all(protections, struct)


def dns_driver(struct):
    """
    Runs all signatures related to DNS queries.
    Any new protections must be attached here.
    :param struct: the DNS packet.
    :return: True if an exploit was detected, else False.
    """
    from protections.dns import \
        sig_5

    protections = [
        sig_5
    ]

    return run_all(protections, struct)


def run_all(protections, struct):
    """
    Runs all given signatures and checks for exploits.
    :param protections: a list of signatures to run.
    :param struct: the packet to run on
    :return: True if an attack was detected, else False.
    """
    verdict = False
    for protection in protections:
        verdict = verdict or protection.check(struct)
        if verdict is True:
            print 'MATCH by protection id', protection.SIGNATURE_ID
            return verdict
    return verdict
