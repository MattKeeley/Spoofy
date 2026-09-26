# modules/bimi.py

import re

from .dmarc import parse_tags
from .resolver import get_resolver

_BIMI_VERSION = re.compile(r"^v\s*=\s*BIMI1\s*(;|$)", re.IGNORECASE)


class BIMI:
    def __init__(self, domain, resolver=None):
        self.bimi_record = None
        self.version = self.location = self.authority = None
        records = (resolver or get_resolver()).txt(f"default._bimi.{domain}").records
        for record in records:
            if _BIMI_VERSION.match(record.strip()):
                self.bimi_record = record.strip()
                tags = parse_tags(self.bimi_record)
                self.version = tags.get("v")
                self.location = tags.get("l") or None
                self.authority = tags.get("a") or None
                break
