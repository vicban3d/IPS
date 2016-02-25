import re
prot_id = '3'

"""

alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"EXPLOIT-KIT Astrum exploit kit landing page";
 flow:to_client,established;
 file_data; 
 content:"{(new Image).src=|22|/"; 
 content:"%72%6f%72%72%65%6e%6f"; 
 distance:0; 
 fast_pattern; 
 flowbits:set,file.exploit_kit.jar&file.exploit_kit.pdf&file.exploit_kit.flash&file.exploit_kit.silverlight; 
 metadata:policy security-ips drop, ruleset community, service http; 

 reference:url,malware.dontneedcoffee.com/2014/09/astrum-ek.html; classtype:trojan-activity; sid:31965; rev:2;)

"""


def check(buf):
	if re.compile('.*\{\(new Image\)\.src=\"/.*%72%6f%72%72%65%6e%6f').match(struct['Body']):
        return True
    return False
