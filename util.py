"""
Utility functions
"""


def str_to_hex(buf):
    """
    Converts str to HEX.
    :param buf: the string to convert.
    :return: the resulting HEX string.
    """
    return '\\x' + '\\x'.join('{:02x}'.format(ord(c)) for c in buf)


def hex_to_str(buf):
    """
    Converts a HEX string into an ascii string.
    :param buf: the string to convert.
    :return: the resulting string.
    """
    return buf.replace('\\x', '').decode('hex')
