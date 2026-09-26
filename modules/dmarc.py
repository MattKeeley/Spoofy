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
    return ".".join(domain.split(".")[-(len(ancestor.split(".")) + 1) :])


class DMARC:
    """Discovers the DMARC policy that applies to mail From: `domain` (RFC 9989 4.10).

    The Author Domain's own record wins, then the Organizational Domain's, then the PSD's.
    Tag attributes hold the values as written (None when absent or invalid), since the
    master table is keyed on what the record actually says.
    """

    policy = sp = np = pct = aspf = t = rua = ruf = None

    def __init__(self, domain, resolver=None):
        self.domain = domain
        self.resolver = resolver or get_resolver()
        self.record_domain = None
        self.domain_exists = True
        self.lookup_error = False
        self.warnings = []
        self.dmarc_record = self.get_dmarc_record()

        if self.dmarc_record:
            self._load_tags(parse_tags(self.dmarc_record))
            if self.inherited:
                self.domain_exists = (
                    self.resolver.query(domain, "A").status != "nxdomain"
                )

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
            records = []
            for record in result.records:
                if is_dmarc_record(record):
                    records.append(record.strip())
                elif "dmarc1" in record.lower():
                    self.warnings.append(
                        f"_dmarc.{target} has a malformed record receivers ignore: {record!r}"
                    )
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

    def _load_tags(self, tags):
        self.rua, self.ruf = tags.get("rua"), tags.get("ruf")
        self.t = tags.get("t", "").lower() or None

        policy, sp, np = (
            tags.get(tag, "").lower() or None for tag in ("p", "sp", "np")
        )
        if policy not in POLICIES or {sp, np} - {None, *POLICIES}:
            # RFC 9989 4.7: act as p=none if reports are requested, else ignore the record.
            policy, sp, np = ("none" if self.rua else None), None, None
            outcome = "treat the record as p=none" if self.rua else "ignore the record"
            self.warnings.append(f"invalid p/sp/np tag; receivers {outcome}")
        self.policy, self.sp, self.np = policy, sp, np

        pct = tags.get("pct")
        if pct is not None and not (pct.isdigit() and int(pct) <= 100):
            self.warnings.append(f"invalid pct={pct!r} ignored")
            pct = None
        aspf = tags.get("aspf", "").lower() or None
        if aspf not in (None, "r", "s"):
            self.warnings.append(f"invalid aspf={aspf!r}; default 'r' applies")
            aspf = None
        self.pct, self.aspf = pct, aspf
