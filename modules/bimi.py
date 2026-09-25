# modules/bimi.py

import re

from .dmarc import parse_tags
from .resolver import get_resolver

_BIMI_VERSION = re.compile(r"^v\s*=\s*BIMI1\s*(;|$)", re.IGNORECASE)


class BIMI:
    def __init__(self, domain, dns_server=None, resolver=None):
        self.domain = domain.lower().rstrip(".")
        self.resolver = resolver or get_resolver(dns_server)
        self.dns_server = dns_server
        self.version = None
        self.location = None
        self.authority = None
        self.bimi_record = self.get_bimi_record()

        if self.bimi_record:
            tags = parse_tags(self.bimi_record)
            self.version = tags.get("v")
            self.location = tags.get("l") or None
            self.authority = tags.get("a") or None

    def get_bimi_record(self):
        """Returns the BIMI record for the domain."""
        result = self.resolver.txt(f"default._bimi.{self.domain}")
        for record in result.records:
            if _BIMI_VERSION.match(record.strip()):
                return record.strip()
        return None

    def get_bimi_details(self):
        """Returns a tuple containing version, location, and authority from a BIMI record."""
        return self.version, self.location, self.authority

    def __str__(self):
        return (
            f"BIMI Record: {self.bimi_record}\n"
            f"Version: {self.version}\n"
            f"Location: {self.location}\n"
            f"Authority: {self.authority}"
        )
