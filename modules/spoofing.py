# modules/spoofing.py

from .master_table import TABLE

PARTIAL = 3  # p=quarantine applied to only pct < 100 of mail
UNKNOWN = 9  # a DNS lookup failed, so records may be missing from the evaluation

MESSAGES = {
    0: "Spoofing possible for {}.",
    1: "Subdomain spoofing possible for {}.",
    2: "Organizational domain spoofing possible for {}.",
    3: "Spoofing might be possible for {}.",
    4: "Spoofing might be possible (Mailbox dependent) for {}.",
    5: "Organizational domain spoofing might be possible (Mailbox dependent) for {}.",
    6: "Subdomain spoofing might be possible (Mailbox dependent) for {}.",
    7: "Subdomain spoofing is possible and organizational domain spoofing might be possible for {}.",
    8: "Spoofing is not possible for {}.",
    9: "Unable to determine spoofability for {} (DNS lookup failed).",
}
POSSIBLE = {
    0: True,
    1: True,
    2: True,
    7: True,
    8: False,
}  # every other code: maybe (None)

# The subdomain half of each code: what the table says about spoofing a subdomain of a
# domain with that code (possible -> 0, mailbox dependent -> 4, not possible -> 8).
AS_SUBDOMAIN = {0: 0, 1: 0, 2: 8, 3: 4, 4: 4, 5: 8, 6: 4, 7: 0, 8: 8}


def lookup(spf_state, p=None, sp=None, aspf=None):
    """Tested code from the master table for an SPF state and DMARC tags as written.

    p=None means no DMARC policy applies. The only combinations the table leaves out are an
    enforcing p with an explicit aspf and no sp; sp defaults to p, so the tested row with sp
    written out is the same record.
    """
    if p is None:
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


def spoofability(spf, dmarc):
    """Master-table code for mail From: dmarc.domain.

    `spf` is the SPF record of the domain whose DMARC record applies: the domain itself, or
    the parent it inherits DMARC from, since the table tested the two records together.
    """
    if dmarc.lookup_error:
        return UNKNOWN
    code = _table_code(spf.state, dmarc)
    # Without the SPF record only "not possible" (enforced DMARC) is still certain.
    return UNKNOWN if spf.lookup_error and code != 8 else code


def _table_code(spf_state, dmarc):
    if dmarc.policy is None:
        return lookup(spf_state)

    # An inherited record makes this domain one of the parent's subdomains, covered by 'sp',
    # or by 'np' if it does not exist (RFC 9989 4.10.1).
    sp = dmarc.sp
    if dmarc.inherited and dmarc.np and not dmarc.domain_exists:
        sp = dmarc.np
    p, sp = _testing_mode(dmarc.policy, dmarc.t), _testing_mode(sp, dmarc.t)

    # pct < 100 lets unsampled mail through only under quarantine (it gets p=none); under
    # reject it is still quarantined (RFC 7489 6.6.4).
    policy = (sp or p) if dmarc.inherited else p
    if policy == "quarantine" and dmarc.pct is not None and int(dmarc.pct) < 100:
        return PARTIAL

    code = lookup(spf_state, p, sp, dmarc.aspf)
    return AS_SUBDOMAIN[code] if dmarc.inherited else code
