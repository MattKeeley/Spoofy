# modules/bimi.py

import dns.resolver

class BIMI:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.bimi_record = self.get_bimi_record()
        self.version = None
        self.location = None
        self.authority = None

        if self.bimi_record:
            self.version = self.get_bimi_version()
            self.location = self.get_bimi_location()
            self.authority = self.get_bimi_authority()

    def get_bimi_record(self):
        """Returns the BIMI record for the domain."""
        try:
            resolver = dns.resolver.Resolver()
            if self.dns_server:
                resolver.nameservers = [self.dns_server]
            bimi = resolver.resolve(f'default._bimi.{self.domain}', 'TXT')
            for record in bimi:
                if 'v=BIMI' in str(record):
                    return record
            return None
        except Exception:
            return None

    def get_bimi_version(self):
        """Returns the version value from a BIMI record."""
        if "v=" in str(self.bimi_record):
            return str(self.bimi_record).split("v=")[1].split(";")[0]
        return None

    def get_bimi_location(self):
        """Returns the location value from a BIMI record."""
        if "l=" in str(self.bimi_record):
            return str(self.bimi_record).split("l=")[1].split(";")[0]
        return None

    def get_bimi_authority(self):
        """Returns the authority value from a BIMI record."""
        if "a=" in str(self.bimi_record):
            return str(self.bimi_record).split("a=")[1].split(";")[0]
        return None

    def get_bimi_details(self):
        """Returns a tuple containing version, location, and authority from a BIMI record."""
        return self.version, self.location, self.authority

    def __str__(self):
        return (f"BIMI Record: {self.bimi_record}\n"
                f"Version: {self.version}\n"
                f"Location: {self.location}\n"
                f"Authority: {self.authority}")
