

def http_request_driver(struct):
    from protections.http_request import \
        prot_1,\
        prot_2

    protections = [
        prot_1,
        prot_2
    ]

    return run_all(protections, struct)


def http_response_driver(struct):
    from protections.http_response import \
        prot_3,\
        prot_4

    protections = [
        prot_3,
        prot_4
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
