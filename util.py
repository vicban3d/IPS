def str_to_hex(buf):
    return '\\x' + '\\x'.join('{:02x}'.format(ord(c)) for c in buf)