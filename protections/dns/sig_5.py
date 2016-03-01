"""
Description:
Multiple stack-based buffer overflows in the (1) send_dg and (2) send_vc
functions in the libresolv library in the GNU C Library (aka glibc or libc6)
before 2.23 allow remote attackers to cause a denial of service (crash) or
possibly execute arbitrary code via a crafted DNS response that triggers a
call to the getaddrinfo function with the AF_UNSPEC or AF_INET6 address family,
related to performing "dual A/AAAA DNS queries" and the libnss_dns.so.2
NSS module.

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7547

Original SNORT Rule:
# alert udp any 53 -> $HOME_NET any
(msg:"PROTOCOL-DNS glibc getaddrinfo A record stack buffer overflow attempt";
flow:to_client;
dsize:>2000;
byte_test:1,&,2,2;
byte_test:1,&,0x80,2;
byte_test:1,!&,0x78,2;
content:"|00 01|"; depth:6; offset:4;
content:"|00 01 00 01|"; fast_pattern:only;
metadata:policy security-ips drop, ruleset community, service dns;
reference:cve,2015-7547;
reference:url,googleonlinesecurity.blogspot.com
/2016/02/cve-2015-7547-glibc-getaddrinfo-stack.html;
classtype:attempted-user;
sid:37730;
rev:2;)
"""

SIGNATURE_ID = '5'


def check(struct):
    """
    Finds above-mentioned exploit.
    :param struct: the packet struct
    :return: True if exploit detected.
    """
    content = ''
    for part in struct.keys():
        content += str(struct.get(part))

    if '0101' not in content:
        return False

    if struct['Truncated'] == 1 and \
                    struct['QR'] == 1 and \
                    struct['Opcode'] == 0 and \
            (struct['Total Answers'] == 1 or
                     struct['Total Questions'] == 1 or
                     struct['Total Authority'] == 1) and \
                    struct['Total Additional'] == 1:
        return True
    return False
