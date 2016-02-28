
prot_id = '4'


def check(buf):
    if 'virus' in buf['Body']:
        return True
    return False
