

def http_request_driver(struct):
    from protections.http_request import \
        sig_1,\
        sig_2

    protections = [
        sig_1,
        sig_2
    ]

    return run_all(protections, struct)


def http_response_driver(struct):
    from protections.http_response import \
        sig_3,\
        sig_4

    protections = [
        sig_3,
        sig_4
    ]

    return run_all(protections, struct)


def dns_driver(struct):
    from protections.dns import \
        sig_5

    protections = [
        sig_5
    ]

    return run_all(protections, struct)


def run_all(protections, struct):
    verdict = False
    for protection in protections:
        verdict = verdict or protection.check(struct)
        if verdict is True:
            print 'MATCH by protection id', protection.prot_id
            return verdict
    return verdict
