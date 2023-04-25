import dns.resolver
import socket
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
        try:
            return socket.gethostbyname(dns_server)
        except:
            return None
    return None


def get_dns_server(domain):
    """Finds the DNS server that serves the domain and returns it, along with any SPF or DMARC records."""
    SOA = get_soa_record(domain)
    spf_record = dmarc_record = partial_spf_record = partial_dmarc_record = None

    if SOA:
        spf_record = spf.get_spf_record(domain, SOA)
        dmarc_record = dmarc.get_dmarc_record(domain, SOA)
        if spf_record and dmarc_record:
            return SOA, spf_record, dmarc_record

    for ip_address in ['1.1.1.1', '8.8.8.8', '9.9.9.9']:
        spf_record = spf.get_spf_record(domain, ip_address)
        dmarc_record = dmarc.get_dmarc_record(domain, ip_address)
        if spf_record and dmarc_record:
            return ip_address, spf_record, dmarc_record
        if spf_record:
            partial_spf_record = spf_record
        if dmarc_record:
            partial_dmarc_record = dmarc_record

    return '1.1.1.1', partial_spf_record, partial_dmarc_record


def get_txt_record(domain, record_type):
    """Returns the TXT record of a given type for a given domain."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [get_dns_server(domain)]
    try:
        query = resolver.query(domain, record_type)
        return str(query[0])
    except:
        return None
