import re
import dns.resolver


class DKIM:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.dkim_record = self.get_dkim_record()
        # self.dkim_query = None
        self.combined_txt_records = ''
        self.dkim_result = None

    def get_dkim_record(self):
        """Returns the DKIM record for a given domain."""
        self.combined_txt_records = ''

        selectors = [
            'selector',
            'selector1', 
            'selector2', 
            'default', 
            'dkim', 
            'mail', 
            's1', 
            's2', 
            's3', 
            'key1', 
            'key2', 
            'key3', 
            'k1', 
            'k2', 
            'k3', 
            'zoho', 
            'google', 
            'googlemail',
            'protonmail',
            'fm1',
            'fm2',
            'fm3',
            'mandrill',
            'sendgrid',
            's1024',
            'm1',
            'm2',
            'ms',
            'amazonses',
            'zendesk1',
            'zendesk2',
            'everlytickey1',
            'everlytickey2',
            'litesrv',
            'sig1',
            'sm',
            'ctct1',
            'ctct2',
            'spop1024',
            'dk',
            'a1',
            'aweber_key_a',
            'aweber_key_b',
            'aweber_key_c',
            'cm',
            'clab1',
            'dkim1024',
            'e2ma-k1',
            'e2ma-k2',
            'e2ma-k3',
            'sable',
            'hs1',
            'hs2',
            'kl',
            'kl2',
            'mailjet',
            'mailpoet1',
            'mailpoet2',
            'm101',
            'm102',
            'ecm1',
            'nce2048',
            'smtp',
            'class',
            'smtpapi',
            'domk',
            'smtpout',
            'authsmtp',
            'proddkim',
            'testdkim',
            'primary',
            'ses',
            'yousendit',
            'ed-dkim',
            'publickey',
            'sasl',
            'qcdkim',
            'x',
            'm',
            'mikd',
            'private',
            'ei',
            'spop',
            'spop1024',
            'mxvault',
            'krs',
            'mailo',
            'pic',
            'mta',
            'email',
            'acdkim1'
            ]
        
        for selector in selectors:
            try:    
                resolver = dns.resolver.Resolver()
                
                # set OpenDNS for TXT/CNAME query
                resolver.nameservers = ["208.67.222.222"]
                self.dkim_result = resolver.resolve(f"{selector}._domainkey.{self.domain}", "TXT")
                
                if self.dkim_result != None:
                    if self.dkim_result.response.answer != None: # dkim_result.canonical_name not empty
                        for record in self.dkim_result.chaining_result.answer:
                            trim_record = str(record.strings[0][:128])+"...(trimmed)"
                            self.combined_txt_records += f"[*]    {selector}._domainkey.{self.domain} -> {trim_record}" + "\r\n"
                else:
                    continue
            except:
                continue

        if self.combined_txt_records != '':    
            return self.combined_txt_records
        else:
            return None
