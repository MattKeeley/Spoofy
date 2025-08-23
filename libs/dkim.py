import re
import dns.resolver


def get_dkim_record(domain, dns_server=None):
    """Returns the DKIM record for a given domain."""
    global combined_txt_records
    combined_txt_records = ''

    selectors = [
        'selector',
        'selector1', 
        'selector2', 
        'default', 
        'dkim', 
        'mail', 
        's1', 
        's2', 
        's3', 
        'key1', 
        'key2', 
        'key3', 
        'k1', 
        'k2', 
        'k3', 
        'zoho', 
        'google', 
        'googlemail',
        'protonmail',
        'fm1',
        'fm2',
        'fm3',
        'mandrill',
        'sendgrid',
        's1024',
        'm1',
        'm2',
        'ms',
        'amazonses'
        ]
    
    for selector in selectors:
        try:    
            resolver = dns.resolver.Resolver()
            #resolver.nameservers = [dns_server, '1.1.1.1', '8.8.8.8']
            resolver.nameservers = ['1.1.1.1', '8.8.8.8']
            dkim_query = f"{selector}._domainkey.{domain}"
            query_result = dns.resolver.resolve(dkim_query, 'TXT')
            
            if query_result != '':
                combined_txt_records += dkim_query + " "
            else:
                continue
        except:
            continue

    if combined_txt_records != '':    
        return combined_txt_records
    else:
        return "No DKIM found"
