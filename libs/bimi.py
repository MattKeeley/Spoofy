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
        return None
    except:
        return None



