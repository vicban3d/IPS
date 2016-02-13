
prot_id = '4'


def check(buf):
    print buf['Body']
    if 'google' in buf['Body']:
        return True
    return False
