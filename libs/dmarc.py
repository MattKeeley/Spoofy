import re, dns.resolver


def get_dmarc_record(domain, dns_server):
    """Returns the DMARC record for a given domain."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        dmarc = resolver.resolve(f"_dmarc.{domain}", "TXT")
    except:
        return None
    for dns_data in dmarc:
        if "DMARC1" in str(dns_data):
            dmarc_record = str(dns_data).replace('"','')
            return dmarc_record
    return None

def get_dmarc_details(dmarc_record):
    """Returns a tuple containing policy, pct, aspf, subdomain policy,
    forensic report uri, and aggregate report uri from a DMARC record"""
    p = get_dmarc_policy(dmarc_record)
    pct = get_dmarc_pct(dmarc_record)
    aspf = get_dmarc_aspf(dmarc_record)
    sp = get_dmarc_subdomain_policy(dmarc_record)
    fo = get_dmarc_forensic_reports(dmarc_record)
    rua = get_dmarc_aggregate_reports(dmarc_record)
    return p, pct, aspf, sp, fo, rua

def get_dmarc_policy(dmarc_record):
    """Returns the policy value from a DMARC record."""
    policy_match = re.search(r'p=(\S+)', dmarc_record)
    if policy_match:
        return policy_match.group(1)
    else:
        return None


def get_dmarc_pct(dmarc_record):
    """Returns the percentage value from a DMARC record."""
    pct_match = re.search(r'pct=(\d+)', dmarc_record)
    if pct_match:
        return int(pct_match.group(1))
    else:
        return None


def get_dmarc_aspf(dmarc_record):
    """Returns the alignment mode for the SPF check from a DMARC record."""
    aspf_match = re.search(r'aspf=(\S+)', dmarc_record)
    if aspf_match:
        return aspf_match.group(1)
    else:
        return None


def get_dmarc_subdomain_policy(dmarc_record):
    """Returns the policy to apply for subdomains from a DMARC record."""
    sp_match = re.search(r'sp=(\S+)', dmarc_record)
    if sp_match:
        return sp_match.group(1)
    else:
        return None


def get_dmarc_forensic_reports(dmarc_record):
    """Returns the email addresses to which forensic reports should be sent."""
    rua_matches = re.findall(r'rua=([\S]+)', dmarc_record)
    if rua_matches:
        return rua_matches
    else:
        return None


def get_dmarc_aggregate_reports(dmarc_record):
    """Returns the email addresses to which aggregate reports should be sent."""
    ruf_match = re.search(r'ruf=([\S]+)', dmarc_record)
    if ruf_match:
        return ruf_match.group(1)
    else:
        return None