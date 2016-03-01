"""
Description:
 Multiple directory traversal vulnerabilities in Magento Community Edition (CE)
 1.9.1.0 and Enterprise Edition (EE) 1.14.1.0 allow remote authenticated users
 to include and execute certain PHP files via (1) .. (dot dot) sequences in the
 PATH_INFO to index.php or (2) vectors involving a block value in the
 ___directive parameter to the Cms_Wysiwyg controller in the Adminhtml module,
 related to the blockDirective function and the auto loading mechanism.
 NOTE: vector 2 might not cross privilege boundaries, since administrators might
  already have the privileges to execute code and upload files.

 https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-1398

Original SNORT Rule:
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS
(msg:"SERVER-WEBAPP Magento remote code execution attempt";
 flow:to_server,established;

 content:"/Adminhtml_"; http_uri;
 content:"forwarded="; distance:0; http_uri;

 metadata:ruleset community, service http;
 reference:	cve,2015-1398; classtype:attempted-admin; sid:34365; rev:2;)
"""

SIGNATURE_ID = '2'


def check(struct):
    """
    Finds above-mentioned exploit.
    :param struct: the packet struct
    :return: True if exploit detected.
    """
    import re
    if struct['Method'] == 'GET' and \
            re.search('.*/Adminhtml_.*forwarded=', struct['Path']):
        return True
    return False
