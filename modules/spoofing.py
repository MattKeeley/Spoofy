# modules/spoofing.py

from .dmarc import POLICIES
from .domains import is_subdomain
from .master_table import TABLE

SPF_STATES = ("-all", "~all", "?all", "+all", "noall", "nospf")

# Each code read as (outcome for the domain itself, outcome for its subdomains):
# Y = spoofing possible, M = might be possible (mailbox dependent), N = not possible.
AXES = {
    0: ("Y", "Y"),
    1: ("N", "Y"),
    2: ("Y", "N"),
    3: ("M", "M"),
    4: ("M", "M"),
    5: ("M", "N"),
    6: ("N", "M"),
    7: ("M", "Y"),
    8: ("N", "N"),
}
SUBDOMAIN_CODES = {"Y": 0, "M": 4, "N": 8}
PARTIAL = 3  # p=quarantine applied to only pct < 100 of mail
UNKNOWN = 9  # a DNS lookup failed, so records may be missing from the evaluation


def lookup(spf_state, p=None, sp=None, aspf=None):
    """Tested code from the master table for an SPF state and DMARC tags as written.

    p=None means no DMARC policy applies. The only combinations the table leaves out are an
    enforcing p with an explicit aspf and no sp; sp defaults to p, so the tested row with sp
    written out is the same record.
    """
    if spf_state not in SPF_STATES:
        spf_state = "noall"
    p, sp, aspf = (str(v).lower() if v else None for v in (p, sp, aspf))
    sp = sp if sp in POLICIES else None
    aspf = aspf if aspf in ("r", "s") else None
    if p not in POLICIES:
        return TABLE[(spf_state, None)]
    key = (spf_state, (p, sp, aspf))
    if key not in TABLE:
        key = (spf_state, (p, sp or p, aspf))
    return TABLE[key]


def _testing_mode(policy, t):
    """RFC 9989 t=y: failing mail gets the next weaker policy."""
    if t == "y":
        return {"reject": "quarantine", "quarantine": "none"}.get(policy, policy)
    return policy


def _partial(policy, pct):
    """Quarantine applied to only part of the mail: the rest gets p=none (RFC 7489 6.6.4).

    With reject the unsampled mail is still quarantined, and with none pct changes nothing.
    """
    return policy == "quarantine" and str(pct).isdigit() and int(pct) < 100


class Spoofing:
    def __init__(
        self,
        domain,
        dmarc_record,
        p,
        aspf,
        spf_record,
        spf_all,
        spf_dns_queries,
        sp,
        pct,
        np=None,
        t=None,
        inherited=False,
        domain_exists=True,
        org_spf_state=None,
        lookup_error=False,
        spf_lookup_error=False,
    ):
        self.domain = domain
        self.dmarc_record = dmarc_record
        self.p = p
        self.aspf = aspf
        self.spf_record = spf_record
        self.spf_all = spf_all
        self.spf_dns_queries = spf_dns_queries
        self.sp = sp
        self.pct = pct
        self.np = np
        self.t = t
        self.inherited = inherited
        self.domain_exists = domain_exists
        self.org_spf_state = org_spf_state
        self.lookup_error = lookup_error
        self.spf_lookup_error = spf_lookup_error
        self.domain_type = self.get_domain_type()
        self.spoofable = self.is_spoofable()
        self.spoofing_possible, self.spoofing_type = self.evaluate_spoofing()

    def get_domain_type(self):
        """Determines whether the domain is a domain or subdomain."""
        return "subdomain" if is_subdomain(self.domain) else "domain"

    def is_spoofable(self):
        """Determines the spoofability from the master table."""
        if self.lookup_error:
            return UNKNOWN
        code = self._table_code()
        # Without the SPF record only "not possible" (enforced DMARC) is still certain.
        return UNKNOWN if self.spf_lookup_error and code != 8 else code

    def _table_code(self):
        spf_state = "nospf" if not self.spf_record else (self.spf_all or "noall")
        p = self.p if self.dmarc_record else None
        if p is None:
            return lookup(spf_state)

        p = _testing_mode(p.lower(), self.t)
        sp = _testing_mode(self.sp and self.sp.lower(), self.t)
        if not self.inherited:
            if _partial(p, self.pct):
                return PARTIAL
            return lookup(spf_state, p, sp, self.aspf)

        # The record belongs to a parent (Organizational Domain or PSD), so this domain is
        # one of its subdomains: use the subdomain outcome tested for the parent's records.
        # 'np' takes the place of 'sp' for a domain that does not exist (RFC 9989 4.10.1).
        if self.np and not self.domain_exists:
            sp = _testing_mode(self.np.lower(), self.t)
        if _partial(sp or p, self.pct):
            return PARTIAL
        code = lookup(self.org_spf_state or spf_state, p, sp, self.aspf)
        return SUBDOMAIN_CODES[AXES[code][1]]

    def evaluate_spoofing(self):
        """Evaluates and returns whether spoofing is possible and the type of spoofing."""
        spoofing_types = {
            0: f"Spoofing possible for {self.domain}.",
            1: f"Subdomain spoofing possible for {self.domain}.",
            2: f"Organizational domain spoofing possible for {self.domain}.",
            3: f"Spoofing might be possible for {self.domain}.",
            4: f"Spoofing might be possible (Mailbox dependent) for {self.domain}.",
            5: f"Organizational domain spoofing might be possible (Mailbox dependent) for {self.domain}.",
            6: f"Subdomain spoofing might be possible (Mailbox dependent) for {self.domain}.",
            7: f"Subdomain spoofing is possible and organizational domain spoofing might be possible for {self.domain}.",
            8: f"Spoofing is not possible for {self.domain}.",
            9: f"Unable to determine spoofability for {self.domain} (DNS lookup failed).",
        }

        spoofing_type = spoofing_types.get(
            self.spoofable, f"Unknown spoofing type for {self.domain}."
        )

        if self.spoofable in {0, 1, 2, 7}:
            spoofing_possible = True
        elif self.spoofable == 8:
            spoofing_possible = False
        else:
            spoofing_possible = None  # "maybe"

        return spoofing_possible, spoofing_type

    def __str__(self):
        return (
            f"Domain: {self.domain}\n"
            f"Domain Type: {self.domain_type}\n"
            f"Spoofing Possible: {self.spoofing_possible}\n"
            f"Spoofing Type: {self.spoofing_type}"
        )
