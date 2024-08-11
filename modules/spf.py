# modules/spf.py

import dns.resolver
import re

class SPF:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.spf_record = self.get_spf_record()
        self.all_mechanism = None
        self.num_includes = 0
        self.too_many_includes = False

        if self.spf_record:
            self.all_mechanism = self.get_spf_all_string()
            self.num_includes = self.get_spf_includes()
            self.too_many_includes = self.num_includes > 10

    def get_spf_record(self):
        """Returns the SPF record for a given domain."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server, '1.1.1.1', '8.8.8.8']
            query_result = resolver.resolve(self.domain, 'TXT')
            for record in query_result:
                if 'spf1' in str(record):
                    spf_record = str(record).replace('"', '')
                    return spf_record
            return None
        except Exception:
            return None

    def get_spf_all_string(self):
        """Returns the string value of the 'all' mechanism in the SPF record."""
        if self.spf_record:
            all_matches = re.findall(r'[-~?+]all', self.spf_record)
            if len(all_matches) == 1:
                return all_matches[0]
            elif len(all_matches) > 1:
                return '2many'
        return None
    
    def get_spf_includes(self):
        """Returns the number of includes and other mechanisms in the SPF record for a given domain."""
        def count_includes(spf_record):
            count = 0
            for item in spf_record.split():
                if item.startswith("include:"):
                    url = item.replace('include:', '')
                    count += 1
                    try:
                        # Recursively fetch and count includes in the SPF record of the included domain
                        answers = dns.resolver.resolve(url, 'TXT')
                        for rdata in answers:
                            for txt_string in rdata.strings:
                                txt_record = txt_string.decode('utf-8')
                                if txt_record.startswith('v=spf1'):
                                    count += count_includes(txt_record)
                    except Exception as e:
                        pass
            
            # Count occurrences of 'a', 'mx', 'ptr', and 'exists' mechanisms
            count += len(re.findall(r"[ ,+]a[ ,:]", spf_record))
            count += len(re.findall(r"[ ,+]mx[ ,:]", spf_record))
            count += len(re.findall(r"[ ]ptr[ ]", spf_record))
            count += len(re.findall(r"exists[:]", spf_record))
            
            return count

        return count_includes(self.spf_record)
    
    def __str__(self):
        return (f"SPF Record: {self.spf_record}\n"
                f"All Mechanism: {self.all_mechanism}\n"
                f"Number of Includes: {self.num_includes}\n"
                f"Too Many Includes: {self.too_many_includes}")