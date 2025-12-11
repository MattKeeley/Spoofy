import dns.resolver
import dns.flags

class DNSSEC:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server or "1.1.1.1"
        self.dnssec_enabled = self.check_dnssec()

    def check_dnssec(self):
        """Check if domain has DNSSEC signatures on key records"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            resolver.set_flags(dns.flags.DO)  # Set DNSSEC OK bit
            
            # Check for RRSIG on TXT records (covers SPF/DMARC)
            query = resolver.resolve(self.domain, "TXT")
            return bool(query.response.find_rrset(
                query.response.answer, 
                dns.name.from_text(self.domain),
                dns.rdataclass.IN,
                dns.rdatatype.RRSIG
            ))
        except:
            return False