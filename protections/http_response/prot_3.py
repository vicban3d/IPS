
prot_id = '3'


def check(buf):
    if 'malicious' in buf['Body']:
        return True
    return False
