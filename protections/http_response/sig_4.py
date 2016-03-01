"""
TEST SIGNATURE
"""
SIGNATURE_ID = '4'


def check(struct):
    """
    Finds above-mentioned exploit.
    :param struct: the packet struct
    :return: True if exploit detected.
    """
    if 'virus' in struct['Body']:
        return True
    return False
