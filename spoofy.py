#! /usr/bin/env python3

import argparse, dns.resolver, socket, re
from email import policy
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init as color_init

from libs.PrettyOutput import (
    output_good,
    output_bad,
    output_warning,
    output_info,
    output_error,
    output_indifferent
)

# Changes on every lookup to the DNS server specified in the SOA record of the domain.
spoofy_resolver = dns.resolver.Resolver()
spoofy_resolver.nameservers = ['1.1.1.1']


def get_dns_server(domain):
    try:
        dns_server = ""
        spoofy_resolver.nameservers = ['1.1.1.1']
        query = spoofy_resolver.resolve(domain, 'SOA')
        if query is not None:
            for data in query: dns_server = str(data.mname)
            return socket.gethostbyname(dns_server)
        else:
            output_error("DNS Server was not found from SOA Record. Using default 1.1.1.1!")
    except: 
        output_error("Failed to find SOA for domain.")
        return "1.1.1.1"


def get_spf_record(domain):
    spf = None
    try: 
        try: spf = spoofy_resolver.resolve(domain , 'TXT')
        except:
            spoofy_resolver.nameservers[0] = '1.1.1.1'
            spf = spoofy_resolver.resolve(domain , 'TXT')
        spf_record = ""
        for dns_data in spf:
            if 'spf1' in str(dns_data):
                spf_record = str(dns_data).replace('"','')
                output_info(f"Found SPF record: {spf_record}")
                break  
        return spf_record
    except:
        output_info("No SPF record found.")
        return None


def get_spf_all_string(spf_record):
    count = spf_record.count(" ~all") + spf_record.count(" ?all") + spf_record.count(" -all")
    if count == 1: 
        record = re.search("[-,~,?]all", spf_record).group(0)
        output_info(f"Found SPF all record: {record}")
        return record
    elif count == 0:
        output_info("SPF does not contain an `All` items.")
        return None
    else:
        output_warning("SPF record contains multiple `All` items.")
        return "2many"


def get_spf_includes(domain):
    count = get_includes_for_domain(domain, [])
    if count > 10:
        output_warning(f"Too many SPF include lookups {count}.")
        return count
    else: return count


def get_list_of_includes(domain):
    spf_record = ""
    includes = []
    try:
        try: spf = spoofy_resolver.resolve(domain , 'TXT')
        except:
            spoofy_resolver.nameservers[0] = '1.1.1.1'
            spf = spoofy_resolver.resolve(domain , 'TXT')
        for dns_data in spf:
            if 'spf1' in str(dns_data):
                spf_record = str(dns_data).replace('"','')
                break 
        if spf_record:
            count = len(re.compile("[ ,+]a[ , :]").findall(spf_record))
            count += len(re.compile("[ ,+]mx[ ,:]").findall(spf_record))
            count += len(re.compile("[ ]ptr[ ]").findall(spf_record))
            count += len(re.compile("exists[:]").findall(spf_record))
            for i in range(0, count): # Since other function is recursive and I dont want to figure out how to count, add a domain with 1 include.
                includes.append("18f.gov")
            for item in spf_record.split(' '):
                url = item.replace('include:', '')
                if "include:" in item:
                    includes.append(url)
    except: 
        print("HIT EXCEPTION")
    return includes


def get_includes_for_domain(domain, list):
    # Recursively check the includes for a given domain
    for i in get_list_of_includes(domain):
        if i == "18f.gov": # this is scuffed but it works. 
            list.append(i)
            get_includes_for_domain(i, list)
        if i not in list:
            list.append(i)
            get_includes_for_domain(i, list)
    return len(list)


def get_dmarc_record(domain):
    if domain.count('.') > 1: return get_dmarc_org_policy(domain)
    else:
        try: 
            dmarc = spoofy_resolver.resolve('_dmarc.' + domain , 'TXT')
            dmarc_record = ""
            for dns_data in dmarc:
                if 'DMARC1' in str(dns_data):
                    dmarc_record = str(dns_data).replace('"','')
                    output_info(f"Found DMARC record: {dmarc_record}")
                    break
            return dmarc_record
        except:
                output_info("No DMARC record found")
                return None


def get_dmarc_org_policy(subdomain):
    domain = ".".join(subdomain.split('.')[1:])
    try: 
        spoofy_resolver.nameservers = ['1.1.1.1']
        dmarc = spoofy_resolver.resolve('_dmarc.' + domain , 'TXT')
        dmarc_record = ""
        for dns_data in dmarc:
            if 'DMARC1' in str(dns_data):
                dmarc_record = str(dns_data).replace('"','')
                output_info(f"Found DMARC record: {dmarc_record}")
                break
        return dmarc_record
    except:
        output_bad("No organizational record.")
        return None


def get_dmarc_policy(dmarc_record):
    if "p=" in str(dmarc_record):
        policy = str(dmarc_record).split("p=")[1].split(";")[0]
        output_info(f"Found DMARC policy: {policy}")
        return policy
    else: return None


def get_dmarc_reports(dmarc_record):
    if "ruf=" in str(dmarc_record) and "fo=1" in str(dmarc_record):
        fo = str(dmarc_record).split("ruf=")[1].split(";")[0]
        output_indifferent(f"Forensics reports will be sent: {fo}")
    if "rua=" in str(dmarc_record):
        rua = str(dmarc_record).split("rua=")[1].split(";")[0]
        output_indifferent(f"Aggregate reports will be sent to: {rua}")


def get_dmarc_pct(dmarc_record):
    if "pct" in str(dmarc_record):
        pct = str(dmarc_record).split("pct=")[1].split(";")[0]
        output_info(f"Found DMARC pct: {pct}")
        return pct
    else: return None


def get_dmarc_aspf(dmarc_record):
    if "aspf=" in str(dmarc_record):
        aspf = str(dmarc_record).split("aspf=")[1].split(";")[0]
        output_info(f"Found DMARC aspf: {aspf}")
        return aspf
    else: return None


def get_dmarc_subdomain_policy(dmarc_record):
    if "sp=" in str(dmarc_record):
        subdomain_policy = str(dmarc_record).split("sp=")[1].split(";")[0]
        output_info(f"Found DMARC subdomain policy: {subdomain_policy}")
        return subdomain_policy
    else: return None


# Table thanks to @Calamity
def is_spoofable(domain, p, aspf, spf_record, spf_all, spf_includes, sp, pct):
    try:
        if spf_record is None:
            if p is None:  output_good("Spoofing possible for " + domain)
            else: output_bad("Spoofing not possible for " + domain)
        elif pct != 100:
            output_warning("Spoofing might be possible for " + domain)
        elif spf_includes > 10 and p is None:
            output_good("Spoofing possible for " + domain)
        elif spf_all == "2many": 
            if p == "none": output_warning("Spoofing might be possible for " + domain)
            else: output_bad("Spoofing not possible for " + domain)
        elif spf_all is not None and p is None: output_good("Spoofing possible for " + domain)
        elif spf_all == "-all":
            if p is not None and aspf is not None and sp == "none": output_good("Subdomain spoofing possible for " + domain)
            elif aspf is None and sp == "none": output_good("Subdomain spoofing possible for " + domain)
            elif p == "none" and (aspf == "r" or aspf is None) and sp is None: output_warning("Spoofing might be possible (Mailbox dependant) for " + domain)
            elif p == "none" and aspf == "r" and (sp == "reject" or sp == "quarentine"): output_good("Organizational domain spoofing possible for " + domain)
            elif p == "none" and aspf is None and (sp == "reject" or sp == "quarentine"): output_warning("Organizational domain spoofing may be possible for " + domain)
            elif p == "none" and aspf is None and sp == "none": output_good("Subdomain spoofing possible for " + domain);output_warning("Organizational domain spoofing may be possible for " + domain)
            else: output_bad("Spoofing not possible for " + domain)
        elif spf_all == "~all":
            if p == "none" and sp == "reject" or sp == "quarentine": output_good("Organizational domain spoofing possible for " + domain)
            elif p == "none" and sp is None: output_good("Spoofing possible for " + domain)
            elif p == "none" and sp == "none": output_good("Subdomain spoofing possible for " + domain);output_good("Organizational domain spoofing possible for " + domain)
            elif (p == "reject" or p == "quarentine") and aspf is None and sp == "none": output_good("Subdomain spoofing possible for " + domain)
            elif (p == "reject" or p == "quarentine") and aspf is not None and sp == "none": output_good("Subdomain spoofing possible for " + domain)
            else: output_bad("Spoofing not possible for " + domain)

        elif spf_all == "?all":
            if (p == "reject" or p == "quarentine") and aspf is not None and sp == "none": output_warning("Subdomain spoofing might be possible (Mailbox dependant) for " + domain)
            elif (p == "reject" or p == "quarentine") and aspf is None and sp == "none": output_warning("Subdomain spoofing might be possible (Mailbox dependant) for " + domain)
            elif p == "none" and aspf == "r" and sp is None:  output_good("Spoofing possible for " + domain)
            elif p == "none" and aspf == "r" and sp == "none":  output_good("Subdomain spoofing possible for " + domain);output_good("Organizational domain spoofing possible for " + domain)
            elif p == "none" and aspf == "s" or None and sp == "none": output_good("Subdomain spoofing possible for " + domain);output_warning("Organizational domain spoofing may be possible for " + domain)
            elif p == "none" and aspf == "s" or None and sp is None:  output_warning("Subdomain spoofing might be possible (Mailbox dependant) for " + domain)
            elif p == "none" and aspf is not None and (sp == "reject" or sp == "quarentine"):output_warning("Organizational domain spoofing may be possible for " + domain)
            elif p == "none" and aspf is None and sp  == "reject": output_warning("Organizational domain spoofing may be possible for " + domain)
            else: output_bad("Spoofing not possible for " + domain)
    except:
        output_error("If you hit this error message, something is really messed up.")


def check_domains(domains):
        for domain in domains:
            try:
                p=None; aspf=None; spf_record=None; spf_alls=None; 
                spf_includes=None; sp=None; pct=None;
                spoofy_resolver.nameservers[0] = get_dns_server(domain)
                output_indifferent("Domain: " + domain)
                spf_record = get_spf_record(domain)
                if spf_record is not None:
                    spf_alls = get_spf_all_string(spf_record)
                    spf_includes = get_spf_includes(domain)
                dmarc_record = get_dmarc_record(domain)
                if dmarc_record is not None:
                    p = get_dmarc_policy(dmarc_record)
                    aspf = get_dmarc_aspf(dmarc_record)
                    sp = get_dmarc_subdomain_policy(dmarc_record)
                    pct = get_dmarc_pct(dmarc_record)
                is_spoofable(domain, p, aspf, spf_record, spf_alls, spf_includes, sp, pct)
                print("\n")
            except: output_error("Domain format cannot be interpreted.")


if __name__ == "__main__":
    color_init()
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-iL", type=str, required=False, help="Provide an input list.")
    group.add_argument("-d", type=str, required=False, help="Provide an single domain.")
    options = parser.parse_args()
    if not any(vars(options).values()): parser.error("No arguments provided. Usage: `spoofcheck.py -d [DOMAIN]` OR `spoofcheck.py -iL [DOMAIN_LIST]`")
    domains = []
    if options.iL:
        try:
            with open(options.iL, "r") as f:
                for line in f: domains.append(line.strip('\n'))
        except IOError: output_error("File doesnt exist or cannot be read.")
    if options.d:
        domains.append(options.d)
    check_domains(domains)