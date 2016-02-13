
prot_id = '3'


def check(buf):
    print '\\x'.join('{:02x}'.format(ord(c)) for c in buf['Body'])

    if 'malicious' in buf['Body']:
        return True
    return False
