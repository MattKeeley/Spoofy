import dns.resolver


def get_bimi_record(domain, dns_server):
    """Returns the BIMI record for a given domain."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server, '1.1.1.1', '8.8.8.8']
        query_result = resolver.resolve('default._bimi.' + domain, 'TXT')
        for record in query_result:
            if 'v=BIMI' in str(record):
                return record
        #return None
        return "No BIMI record"
    except:
        return None


def get_bimi_details(bimi_record):
    """Returns a tuple containing policy, pct, aspf, subdomain policy,
    forensic report uri, and aggregate report uri from a BIMI record"""
    version = get_bimi_version(bimi_record)
    location = get_bimi_location(bimi_record)
    authority = get_bimi_authority(bimi_record)
    return version, location, authority
    
    
def get_bimi_version(bimi_record):
    """Returns the version value from a BIMI record."""
    if "v=" in str(bimi_record):
        return str(bimi_record).split("v=")[1].split(";")[0]
    else:
        return None
        
def get_bimi_location(bimi_record):
    """Returns the location value from a BIMI record."""
    if "l=" in str(bimi_record):
        return str(bimi_record).split("l=")[1].split(";")[0]
    else:
        return None
        
def get_bimi_authority(bimi_record):
    """Returns the authority value from a BIMI record."""
    if "a=" in str(bimi_record):
        return str(bimi_record).split("a=")[1].split(";")[0]
    else:
        return None