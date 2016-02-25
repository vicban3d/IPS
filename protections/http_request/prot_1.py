
prot_id = '1'


def check(struct):
    if 'malicious' in struct['Path']:
        return True
    return False
