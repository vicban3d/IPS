"""
TEST SIGNATURE
"""

SIGNATURE_ID = '1'


def check(struct):
    """
    Finds above-mentioned exploit.
    :param struct: the packet struct
    :return: True if exploit detected.
    """
    if 'malicious' in struct['Path']:
        return True
    return False
