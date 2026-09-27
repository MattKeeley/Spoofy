# spoofy/spf.py

import re
from dataclasses import dataclass

from .domains import registered_domain
from .resolver import get_resolver

LOOKUP_LIMIT = 10  # RFC 7208 4.6.4
VOID_LOOKUP_LIMIT = 2  # RFC 7208 4.6.4
MAX_DEPTH = 10  # hard stop for include/redirect chains
DNS_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}
KNOWN_MECHANISMS = DNS_MECHANISMS | {"all", "ip4", "ip6"}

_SPF_VERSION = re.compile(r"^v=spf1(\s|$)", re.IGNORECASE)
_TERM = re.compile(r"^([+\-~?]?)([^:=/]*)([:=/]?)(.*)$")


def is_spf_record(txt):
    return bool(_SPF_VERSION.match(txt.strip()))


@dataclass(frozen=True)
class Term:
    qualifier: str  # "+", "-", "~", "?" (None for modifiers)
    name: str  # lower-cased mechanism or modifier name
    value: str  # domain-spec / ip / cidr, "" when absent

    @property
    def is_modifier(self):
        return self.qualifier is None


def parse_terms(record):
    """Split an SPF record into Terms. Mechanisms default to the '+' qualifier (RFC 7208 4.6.2)."""
    terms = []
    for token in record.split()[1:]:
        qualifier, name, sep, value = _TERM.match(token).groups()
        if sep == "=":
            terms.append(Term(None, name.lower(), value))
        else:
            terms.append(
                Term(qualifier or "+", name.lower(), value if sep == ":" else "")
            )
    return terms


class SPF:
    """Fetches an SPF record and evaluates it the way a receiver would, without an IP.

    all_mechanism        effective 'all' ("-all", "~all", "?all", "+all") after following
                         redirect= (only when the record has no 'all' of its own), else None
    spf_dns_query_count  DNS-querying terms across the whole include/redirect tree
    errors               conditions that make receivers return permerror
    dangling_includes    include/redirect targets whose registrable domain does not exist:
                         whoever registers it can make mail pass SPF for this domain
    """

    def __init__(self, domain, resolver=None):
        self.domain = domain
        self.resolver = resolver or get_resolver()
        self.all_mechanism = None
        self.spf_dns_query_count = 0
        self.void_lookups = 0
        self.errors = []
        self.warnings = []
        self.dangling_includes = []
        self.lookup_error = False
        self.spf_record = self.get_spf_record()

        if self.spf_record:
            self.all_mechanism = self._walk(domain, self.spf_record, 0, {domain})
            if self.spf_dns_query_count > LOOKUP_LIMIT:
                self.errors.append(
                    f"{self.spf_dns_query_count} DNS-querying terms (limit {LOOKUP_LIMIT})"
                )
            if self.void_lookups > VOID_LOOKUP_LIMIT:
                self.errors.append(
                    f"{self.void_lookups} void lookups (limit {VOID_LOOKUP_LIMIT})"
                )

    @property
    def too_many_dns_queries(self):
        return self.spf_dns_query_count > LOOKUP_LIMIT

    @property
    def state(self):
        """Master table key: the all qualifier, 'noall' or 'nospf'."""
        if not self.spf_record:
            return "nospf"
        return self.all_mechanism or "noall"

    def get_spf_record(self):
        """Fetches the SPF record for the domain."""
        result = self.resolver.txt(self.domain)
        if result.status == "error":
            self.lookup_error = True
            return None
        records = [r.strip() for r in result.records if is_spf_record(r)]
        if len(records) > 1:
            self.errors.append(
                f"{len(records)} SPF records published (only one allowed)"
            )
        return records[0] if records else None

    def _walk(self, domain, record, depth, stack):
        """Counts lookups below `record` and returns its effective 'all' mechanism."""
        all_mechanism = None
        redirect = None
        for term in parse_terms(record):
            if term.is_modifier:
                if term.name == "redirect":
                    redirect = term.value
            # A syntax error anywhere, even after 'all', is a permerror (RFC 7208 4.6).
            elif term.name not in KNOWN_MECHANISMS:
                self.errors.append(
                    f"unknown mechanism '{term.name}' in SPF for {domain}"
                )
            elif term.name in ("ip4", "ip6") and not term.value:
                self.errors.append(
                    f"'{term.name}' without an address in SPF for {domain}"
                )
            elif all_mechanism:
                continue  # evaluation stopped at 'all': later terms cost no lookups
            elif term.name == "all":
                all_mechanism = f"{term.qualifier}all"
            elif term.name in DNS_MECHANISMS:
                self.spf_dns_query_count += 1
                if term.name == "ptr":
                    self._warn(f"deprecated 'ptr' mechanism in SPF for {domain}")
                if term.name == "include":
                    self._follow(term.value, "include", depth, stack)

        # redirect= is ignored when 'all' is present
        if redirect and all_mechanism is None:
            self.spf_dns_query_count += 1
            all_mechanism = self._follow(redirect, "redirect", depth, stack)
        return all_mechanism

    def _follow(self, target, kind, depth, stack):
        if not target:
            self.errors.append(f"{kind} without a domain in SPF")
            return None
        if "%" in target:
            self._warn(f"{kind}:{target} uses macros; not expanded")
            return None
        target = target.lower().rstrip(".")
        if target in stack:
            self.errors.append(f"{kind} loop via {target}")
            return None
        # Bounds the work; the lookup limit error already covers an over-deep chain.
        if depth >= MAX_DEPTH:
            return None

        result = self.resolver.txt(target)
        if result.status == "error":
            # Only a failed redirect hides the effective 'all'; a failed include just
            # makes the lookup count a lower bound.
            self.lookup_error = self.lookup_error or kind == "redirect"
            self._warn(f"{kind}:{target} lookup failed ({result.error})")
            return None
        records = [r.strip() for r in result.records if is_spf_record(r)]
        if not records:
            if result.void:
                self.void_lookups += 1
            if result.status == "nxdomain":
                self._check_dangling(target)
            self.errors.append(f"{kind}:{target} has no SPF record")
            return None
        if len(records) > 1:
            self.errors.append(f"{len(records)} SPF records at {target}")
        return self._walk(target, records[0], depth + 1, stack | {target})

    def _warn(self, message):
        if message not in self.warnings:
            self.warnings.append(message)

    def _check_dangling(self, target):
        registered = registered_domain(target)
        if registered and self.resolver.query(registered, "NS").status == "nxdomain":
            self.dangling_includes.append(registered)
