"""
Description:
malware.dontneedcoffee.com/2014/09/astrum-ek.html

Original SNORT Rule:
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"EXPLOIT-KIT Astrum exploit kit landing page";
 - flow:to_client,established;
file_data; 
content:"{(new Image).src=|22|/"; 
content:"%72%6f%72%72%65%6e%6f"; distance:0;
fast_pattern; 
flowbits:set,file.exploit_kit.jar&file.exploit_kit.pdf&file.exploit_kit.flash&file.exploit_kit.silverlight; 
metadata:policy security-ips drop, ruleset community, service http; 

reference:url,malware.dontneedcoffee.com/2014/09/astrum-ek.html; classtype:trojan-activity; sid:31965; rev:2;)
"""

SIGNATURE_ID = '3'

def check(struct):
    """
    Finds above-mentioned exploit.
    :param struct: the packet struct
    :return: True if exploit detected.
    """

    from util import hex_to_str
    import re

    regex = re.compile('\{\(new Image\)\.src=.*%72%6f%72%72%65%6e%6f')
    if struct['Code'] == '200' and \
        regex.search(hex_to_str(struct['Body'])):
        return True
    return False