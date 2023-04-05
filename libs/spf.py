import re
import dns.resolver


def get_spf_record(domain, dns_server):
    """Returns the SPF record for a given domain."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server, '1.1.1.1', '8.8.8.8']
        query_result = resolver.resolve(domain, 'TXT')
        for record in query_result:
            if 'spf1' in str(record):
                spf_record = str(record).replace('"', '')
                return spf_record
        return None
    except:
        return None


def get_spf_all_string(spf_record):
    """Returns the string value of the all mechanism in the SPF record."""
    all_matches = re.findall(r'[-~?] ?a ?l ?l', spf_record)
    if len(all_matches) == 1:
        return all_matches[0]
    elif len(all_matches) > 1:
        return '2many'
    else:
        return None


def get_spf_includes(domain, count=0):
    """Returns the number of includes in the SPF record for a given domain."""
    if count > 10:
        return count
    try:
        spf_record = get_spf_record(domain, '1.1.1.1')
        if spf_record:
            count += len(re.compile("[ ,+]a[ ,:]").findall(spf_record))
            count += len(re.compile("[ ,+]mx[ ,:]").findall(spf_record))
            count += len(re.compile("[ ]ptr[ ]").findall(spf_record))
            count += len(re.compile("exists[:]").findall(spf_record))
            for item in spf_record.split(' '):
                if "include:" in item:
                    url = item.replace('include:', '')
                    count = get_spf_includes(url, count + 1)
    except:
        pass
        # print("Could not find SPF record for " + domain)
    return count
