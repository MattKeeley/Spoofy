# modules/dmarc.py

import re

from .resolver import get_resolver

POLICIES = ("none", "quarantine", "reject")
# "DMARC1" is case sensitive (RFC 9989 4.8: %s"DMARC1"); receivers ignore "v=dmarc1".
_DMARC_VERSION = re.compile(r"^[vV]\s*=\s*DMARC1\s*(;|$)")


def is_dmarc_record(txt):
    return bool(_DMARC_VERSION.match(txt.strip()))


def parse_tags(record):
    """'v=DMARC1; p=reject; sp=none' -> {'v': 'DMARC1', 'p': 'reject', 'sp': 'none'}.

    Tags are matched by name, never by substring, so 'sp=' can't be read as 'p='.
    """
    tags = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        key = key.strip().lower()
        if sep and key and key not in tags:
            tags[key] = value.strip()
    return tags


def applicable_policies(p, sp=None, np=None, inherited=False, domain_exists=True):
    """(policy for the domain itself, policy for its existing subdomains), RFC 9989 4.7.

    A record inherited from a parent applies its 'sp' to the domain (or 'np' when the
    domain does not exist); 'sp' falls back to 'p'.
    """
    if p is None:
        return None, None
    sub_policy = sp or p
    if not inherited:
        return p, sub_policy
    return (np if np and not domain_exists else sub_policy), sub_policy


def tree_walk_targets(domain):
    """Names whose _dmarc record is consulted for `domain`, in order (RFC 9989 4.10 DNS Tree Walk)."""
    labels = domain.split(".")
    rest = labels[1:] if len(labels) <= 8 else labels[-7:]
    targets = [domain]
    while rest:
        targets.append(".".join(rest))
        rest = rest[1:]
    return targets


def one_label_below(domain, ancestor):
    """one_label_below('a.b.example.gov', 'gov') -> 'example.gov'."""
    return ".".join(domain.split(".")[-(len(ancestor.split(".")) + 1):])


class DMARC:
    """Discovers the DMARC policy that applies to mail From: `domain` (RFC 9989 4.10).

    The Author Domain's own record wins, then the Organizational Domain's, then the
    PSD's. For an inherited record 'sp' (or 'np' for a domain that does not exist) is
    the policy for this domain rather than 'p'.
    """

    def __init__(self, domain, dns_server=None, resolver=None):
        self.domain = domain.lower().rstrip(".")
        self.resolver = resolver or get_resolver(dns_server)
        self.dns_server = dns_server or ", ".join(self.resolver.nameservers)
        self.record_domain = None
        self.domain_exists = True
        self.lookup_error = False
        self.warnings = []
        self.tags = {}
        self.policy = None
        self.sp = None
        self.np = None
        self.pct = None
        self.aspf = None
        self.adkim = None
        self.t = None
        self.fo = None
        self.rua = None
        self.ruf = None
        self.dmarc_record = self.get_dmarc_record()

        if self.dmarc_record:
            self._load_tags(self.dmarc_record)
            if self.inherited:
                self.domain_exists = self.resolver.query(self.domain, "A").status != "nxdomain"

    @property
    def inherited(self):
        """True when the applicable record belongs to a parent domain."""
        return self.record_domain not in (None, self.domain)

    def get_dmarc_record(self):
        found = {}  # name -> record, for names publishing exactly one DMARC record
        org_domain = psd = None
        for target in tree_walk_targets(self.domain):
            result = self.resolver.txt(f"_dmarc.{target}")
            if result.status == "error":
                self.lookup_error = True
                self.warnings.append(f"_dmarc.{target} lookup failed ({result.error})")
                return None
            records = [r.strip() for r in result.records if is_dmarc_record(r)]
            for r in result.records:
                if "dmarc1" in r.lower() and not is_dmarc_record(r):
                    self.warnings.append(f"_dmarc.{target} has a malformed record receivers ignore: {r!r}")
            if len(records) > 1:
                self.warnings.append(
                    f"{len(records)} DMARC records at _dmarc.{target}; receivers ignore all of them"
                )
                continue
            if not records:
                continue
            if target == self.domain:
                self.record_domain = target
                return records[0]
            found[target] = records[0]
            # Organizational Domain selection, RFC 9989 4.10.2
            psd_tag = parse_tags(records[0]).get("psd", "").lower()
            if psd_tag == "n":
                org_domain = target
                break
            if psd_tag == "y":
                org_domain, psd = one_label_below(self.domain, target), target
                break
        if found and org_domain is None:
            org_domain = list(found)[-1]  # the record with the fewest labels

        for name in (org_domain, psd):
            if name in found:
                self.record_domain = name
                return found[name]
        return None

    def _load_tags(self, record):
        tags = self.tags = parse_tags(record)
        self.rua = tags.get("rua")
        self.ruf = tags.get("ruf")
        self.fo = tags.get("fo")
        self.t = tags.get("t", "").lower() or None

        policy = tags.get("p", "").lower()
        sp = tags.get("sp", "").lower() or None
        np = tags.get("np", "").lower() or None
        if policy not in POLICIES or sp not in POLICIES + (None,) or np not in POLICIES + (None,):
            # RFC 9989 4.7 / RFC 7489 6.6.3: fall back to p=none if reports are
            # requested, otherwise the record is ignored entirely.
            if self.rua:
                self.warnings.append("invalid p/sp/np tag; receivers treat the record as p=none")
                policy, sp, np = "none", None, None
            else:
                self.warnings.append("invalid p/sp/np tag and no rua; receivers ignore the record")
                policy, sp, np = None, None, None
        self.policy, self.sp, self.np = policy, sp, np

        pct = tags.get("pct")
        if pct is not None:
            if pct.isdigit() and 0 <= int(pct) <= 100:
                self.pct = pct
            else:
                self.warnings.append(f"invalid pct={pct!r} ignored")
        for tag in ("aspf", "adkim"):
            value = tags.get(tag, "").lower() or None
            if value not in (None, "r", "s"):
                self.warnings.append(f"invalid {tag}={value!r}; default 'r' applies")
                value = None
            setattr(self, tag, value)

    def applicable_policies(self):
        return applicable_policies(
            self.policy, self.sp, self.np, self.inherited, self.domain_exists
        )

    def __str__(self):
        return (
            f"DMARC Record: {self.dmarc_record}\n"
            f"Found at: {self.record_domain}\n"
            f"Policy: {self.policy}\n"
            f"Pct: {self.pct}\n"
            f"ASPF: {self.aspf}\n"
            f"Subdomain Policy: {self.sp}\n"
            f"Non-existent Subdomain Policy: {self.np}\n"
            f"Aggregate Report URI: {self.rua}\n"
            f"Forensic Report URI: {self.ruf}"
        )
