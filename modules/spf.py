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
        """Returns the SPF record for the domain."""
        try:
            resolver = dns.resolver.Resolver()
            if self.dns_server:
                resolver.nameservers = [self.dns_server]
            query_result = resolver.resolve(self.domain, 'TXT')
            for record in query_result:
                if 'v=spf1' in str(record):
                    return str(record).replace('"', '')
            return None
        except:
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

    def get_spf_includes(self, count=0):
        """Returns the number of includes in the SPF record for the domain."""
        if count > 10:  # Assuming a maximum of 10 includes as a threshold
            return count
        try:
            if self.spf_record:
                count += self.spf_record.count("include:")
                # Recursively check includes
                for item in self.spf_record.split(' '):
                    if "include:" in item:
                        included_domain = item.replace('include:', '')
                        # Instantiate SPF class for the included domain to get its includes
                        include_spf = SPF(included_domain, self.dns_server)
                        count += include_spf.get_spf_includes(count)
            return count
        except:
            return count

    def __str__(self):
        return (f"SPF Record: {self.spf_record}\n"
                f"All Mechanism: {self.all_mechanism}\n"
                f"Number of Includes: {self.num_includes}\n"
                f"Too Many Includes: {self.too_many_includes}")