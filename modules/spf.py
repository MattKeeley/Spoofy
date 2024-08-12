# modules/spf.py

import dns.resolver
import re


class SPF:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.spf_record = self.get_spf_record()
        self.all_mechanism = None
        self.spf_dns_query_count = 0
        self.too_many_dns_queries = False

        if self.spf_record:
            self.all_mechanism = self.get_spf_all_string()
            self.spf_dns_query_count = self.get_spf_dns_queries()
            self.too_many_dns_queries = self.spf_dns_query_count > 10

    def get_spf_record(self, domain=None):
        """Fetches the SPF record for the specified domain."""
        try:
            if not domain:
                domain = self.domain
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server, "1.1.1.1", "8.8.8.8"]
            query_result = resolver.resolve(domain, "TXT")
            for record in query_result:
                if "spf1" in str(record):
                    spf_record = str(record).replace('"', "")
                    return spf_record
            return None
        except Exception:
            return None

    def get_spf_all_string(self):
        """Returns the string value of the 'all' mechanism in the SPF record."""

        spf_record = self.spf_record
        visited_domains = set()

        while spf_record:
            all_matches = re.findall(r"[-~?+]all", spf_record)
            if len(all_matches) == 1:
                return all_matches[0]
            elif len(all_matches) > 1:
                return "2many"

            redirect_match = re.search(r"redirect=([\w.-]+)", spf_record)
            if redirect_match:
                redirect_domain = redirect_match.group(1)
                if redirect_domain in visited_domains:
                    break  # Prevent infinite loops in case of circular redirects
                visited_domains.add(redirect_domain)
                spf_record = self.get_spf_record(redirect_domain)
            else:
                break

        return None

    def get_spf_dns_queries(self):
        """Returns the number of dns queries, redirects, and other mechanisms in the SPF record for a given domain."""

        def count_dns_queries(spf_record):
            count = 0
            for item in spf_record.split():
                if item.startswith("include:") or item.startswith("redirect="):
                    if item.startswith("include:"):
                        url = item.replace("include:", "")
                    elif item.startswith("redirect="):
                        url = item.replace("redirect=", "")

                    count += 1
                    try:
                        # Recursively fetch and count dns queries or redirects in the SPF record of the referenced domain
                        answers = dns.resolver.resolve(url, "TXT")
                        for rdata in answers:
                            for txt_string in rdata.strings:
                                txt_record = txt_string.decode("utf-8")
                                if txt_record.startswith("v=spf1"):
                                    count += count_dns_queries(txt_record)
                    except Exception:
                        pass

            # Count occurrences of 'a', 'mx', 'ptr', and 'exists' mechanisms
            count += len(re.findall(r"[ ,+]a[ ,:]", spf_record))
            count += len(re.findall(r"[ ,+]mx[ ,:]", spf_record))
            count += len(re.findall(r"[ ]ptr[ ]", spf_record))
            count += len(re.findall(r"exists[:]", spf_record))

            return count

        return count_dns_queries(self.spf_record)

    def __str__(self):
        return (
            f"SPF Record: {self.spf_record}\n"
            f"All Mechanism: {self.all_mechanism}\n"
            f"DNS Query Count: {self.spf_dns_query_count}\n"
            f"Too Many DNS Queries: {self.too_many_dns_queries}"
        )
