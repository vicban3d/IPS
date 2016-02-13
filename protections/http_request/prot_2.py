
prot_id = '2'


def check(buf):
    if 'google' in buf['Host']:
        return True
    return False
