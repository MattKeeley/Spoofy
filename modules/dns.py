# modules/dns.py

import dns.resolver
import socket
from .spf import SPF
from .dmarc import DMARC
from .bimi import BIMI
from .dkim import DKIM


class DNS:
    def __init__(self, domain):
        self.domain = domain
        self.soa_record = None
        self.dns_server = None
        self.spf_record = None
        self.dmarc_record = None
        self.dkim_record = None
        self.bimi_record = None

        self.get_soa_record()
        self.get_dns_server()

    def get_soa_record(self):
        """Sets the SOA record and DNS server of a given domain."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1"]
        try:
            query = resolver.resolve(self.domain, "SOA")
        except Exception:
            return
        if query:
            for data in query:
                dns_server = str(data.mname)
            try:
                self.soa_record = socket.gethostbyname(dns_server)
                self.dns_server = self.soa_record
            except Exception:
                self.soa_record = None

    def get_dns_server(self):
        """Finds the DNS server that serves the domain and retrieves associated SPF, DMARC, and BIMI records."""
        if self.soa_record:
            self.spf_record = SPF(self.domain, self.soa_record)
            self.dmarc_record = DMARC(self.domain, self.soa_record)
            self.bimi_record = BIMI(self.domain, self.soa_record)
            if self.spf_record.spf_record and self.dmarc_record.dmarc_record:
                return

        for ip_address in ["1.1.1.1", "8.8.8.8", "9.9.9.9"]:
            self.spf_record = SPF(self.domain, ip_address)
            self.dmarc_record = DMARC(self.domain, ip_address)
            self.dkim_record = DKIM(self.domain, ip_address)
            self.bimi_record = BIMI(self.domain, ip_address)
            if self.spf_record.spf_record and self.dmarc_record.dmarc_record:
                self.dns_server = ip_address
                return

        self.dns_server = "1.1.1.1"

    def get_txt_record(self, record_type):
        """Returns the TXT record of a given type for the domain."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.dns_server]
        try:
            query = resolver.query(self.domain, record_type)
            return str(query[0])
        except Exception:
            return None

    def __str__(self):
        return (
            f"Domain: {self.domain}\n"
            f"SOA Record: {self.soa_record}\n"
            f"DNS Server: {self.dns_server}\n"
            f"SPF Record: {self.spf_record.spf_record}\n"
            f"DMARC Record: {self.dmarc_record.dmarc_record}\n"
            f"DKIM Record: {self.dkim_record.dkim_record}\n"
            f"BIMI Record: {self.bimi_record.bimi_record}"
        )
