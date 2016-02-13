
prot_id = '4'


def check(buf):
    if 'google' in buf['Body']:
        return True
    return False
