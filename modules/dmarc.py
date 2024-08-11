# modules/dmarc.py

import dns.resolver
import tldextract


class DMARC:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.dmarc_record = self.get_dmarc_record()
        self.policy = None
        self.pct = None
        self.aspf = None
        self.sp = None
        self.fo = None
        self.rua = None

        if self.dmarc_record:
            self.policy = self.get_dmarc_policy()
            self.pct = self.get_dmarc_pct()
            self.aspf = self.get_dmarc_aspf()
            self.sp = self.get_dmarc_subdomain_policy()
            self.fo = self.get_dmarc_forensic_reports()
            self.rua = self.get_dmarc_aggregate_reports()

    def get_dmarc_record(self):
        """Returns the DMARC record for the domain."""
        subdomain = tldextract.extract(self.domain).registered_domain
        if subdomain != self.domain:
            return self.get_dmarc_record_for_domain(subdomain)

        return self.get_dmarc_record_for_domain(self.domain)

    def get_dmarc_record_for_domain(self, domain):
        try:
            resolver = dns.resolver.Resolver()
            if self.dns_server:
                resolver.nameservers = [self.dns_server]
            dmarc = resolver.resolve(f"_dmarc.{domain}", "TXT")
        except Exception:
            return None

        for dns_data in dmarc:
            if "DMARC1" in str(dns_data):
                return str(dns_data).replace('"', "")
        return None

    def get_dmarc_policy(self):
        """Returns the policy value from a DMARC record."""
        if "p=" in str(self.dmarc_record):
            return str(self.dmarc_record).split("p=")[1].split(";")[0]
        return None

    def get_dmarc_pct(self):
        """Returns the pct value from a DMARC record."""
        if "pct=" in str(self.dmarc_record):
            return str(self.dmarc_record).split("pct=")[1].split(";")[0]
        return None

    def get_dmarc_aspf(self):
        """Returns the aspf value from a DMARC record"""
        if "aspf=" in str(self.dmarc_record):
            return str(self.dmarc_record).split("aspf=")[1].split(";")[0]
        return None

    def get_dmarc_subdomain_policy(self):
        """Returns the policy to apply for subdomains from a DMARC record."""
        if "sp=" in str(self.dmarc_record):
            return str(self.dmarc_record).split("sp=")[1].split(";")[0]
        return None

    def get_dmarc_forensic_reports(self):
        """Returns the email addresses to which forensic reports should be sent."""
        if "ruf=" in str(self.dmarc_record) and "fo=1" in str(self.dmarc_record):
            return str(self.dmarc_record).split("ruf=")[1].split(";")[0]
        return None

    def get_dmarc_aggregate_reports(self):
        """Returns the email addresses to which aggregate reports should be sent."""
        if "rua=" in str(self.dmarc_record):
            return str(self.dmarc_record).split("rua=")[1].split(";")[0]
        return None

    def __str__(self):
        return (
            f"DMARC Record: {self.dmarc_record}\n"
            f"Policy: {self.policy}\n"
            f"Pct: {self.pct}\n"
            f"ASPF: {self.aspf}\n"
            f"Subdomain Policy: {self.sp}\n"
            f"Forensic Report URI: {self.fo}\n"
            f"Aggregate Report URI: {self.rua}"
        )
