import dns.resolver, socket
from . import spf, dmarc

def get_soa_record(domain):
    """Returns the SOA record of a given domain."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['1.1.1.1']
    try:
        query = resolver.resolve(domain, 'SOA')
    except:
        return None
    if query:
        for data in query:
            dns_server = str(data.mname)
        return socket.gethostbyname(dns_server)
    return None

def get_dns_server(domain):
    """Finds the DNS server that serves the domain and returns it, along with any SPF or DMARC records."""
    SOA = get_soa_record(domain)
    if SOA:
        spf_record = spf.get_spf_record(domain, SOA)
        dmarc_record = dmarc.get_dmarc_record(domain, SOA)
        if (spf_record is not None) or (dmarc_record is not None):
            return SOA, spf_record, dmarc_record
    spf_record = spf.get_spf_record(domain, '1.1.1.1')
    dmarc_record = dmarc.get_dmarc_record(domain, '1.1.1.1')
    if (spf_record is not None) or (dmarc_record is not None):
        return '1.1.1.1', spf_record, dmarc_record
    spf_record = spf.get_spf_record(domain, '8.8.8.8')
    dmarc_record = dmarc.get_dmarc_record(domain, '8.8.8.8')
    if (spf_record is not None) or (dmarc_record is not None):
        return '8.8.8.8', spf_record, dmarc_record
    # No SPF or DMARC record found using 3 different DNS providers. 
    # Defaulting back to Cloudflare
    return '1.1.1.1', spf_record, dmarc_record

def get_txt_record(domain, record_type):
    """Returns the TXT record of a given type for a given domain."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [get_dns_server(domain)]
    try:
        query = resolver.query(domain, record_type)
        return str(query[0])
    except:
        return None