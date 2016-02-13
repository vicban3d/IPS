
prot_id = '1'


def check(buf):
    if 'malicious' in buf['Path']:
        return True
    return False
