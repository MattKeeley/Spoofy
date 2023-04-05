import dns.resolver, tldextract

def get_dmarc_record(domain, dns_server):
    """Returns the DMARC record for a given domain."""
    subdomain = tldextract.extract(domain).registered_domain
    if subdomain != domain:
        return get_dmarc_record(subdomain, dns_server)
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

    subdomain = tldextract.extract(domain).registered_domain
    if subdomain != domain:
        return get_dmarc_record(subdomain, dns_server)

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
    if "p=" in str(dmarc_record): return str(dmarc_record).split("p=")[1].split(";")[0]
    else: return None

def get_dmarc_pct(dmarc_record):
    """Returns the pct value from a DMARC record."""
    if "pct" in str(dmarc_record): return str(dmarc_record).split("pct=")[1].split(";")[0]
    else: return None

def get_dmarc_aspf(dmarc_record):
    """Returns the aspf value from a DMARC record"""
    if "aspf=" in str(dmarc_record): return str(dmarc_record).split("aspf=")[1].split(";")[0]
    else: return None

def get_dmarc_subdomain_policy(dmarc_record):
    """Returns the policy to apply for subdomains from a DMARC record."""
    if "sp=" in str(dmarc_record):return str(dmarc_record).split("sp=")[1].split(";")[0]
    else: return None

def get_dmarc_forensic_reports(dmarc_record):
    """Returns the email addresses to which forensic reports should be sent."""
    if "ruf=" in str(dmarc_record) and "fo=1" in str(dmarc_record): return str(dmarc_record).split("ruf=")[1].split(";")[0]
    else: return None

def get_dmarc_aggregate_reports(dmarc_record):
    """Returns the email addresses to which aggregate reports should be sent."""
    if "rua=" in str(dmarc_record): return str(dmarc_record).split("rua=")[1].split(";")[0]
    else: return None