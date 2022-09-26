#! /usr/bin/env python3

import argparse, dns.resolver, socket
from colorama import init as color_init

from libs.PrettyOutput import (
    output_good,
    output_bad,
    output_warning,
    output_info,
    output_error,
    output_indifferent
)

spoofy_resolver = dns.resolver.Resolver()
spoofy_resolver.nameservers = ['8.8.8.8']


def get_dns_server(domain):
    query = spoofy_resolver.resolve(domain, 'SOA')
    if query is not None:
        dns_server = ""
        for data in query: dns_server = str(data.mname)
        return socket.gethostbyname(dns_server)
    else:
        output_error("DNS Server was not found from SOA Record. Using default 8.8.8.8!")

def get_spf_record(domain):
    try: 
        spf = spoofy_resolver.resolve(domain , 'TXT')
        spf_record = ""
        for dns_data in spf:
            if 'spf1' in str(dns_data):
                spf_record = str(dns_data).replace('"','')
                output_info(f"Found SPF record: {spf_record}")
                break  
        all = check_spf_all_string(spf_record)
        includes = check_spf_includes(domain)
        return all, includes
    except:
        output_info("No SPF record found.")
        return None, None


def check_spf_all_string(spf_record):
    if spf_record.count("all") > 1: 
        output_good("SPF record contains multiple `All` items.")
        return "2many"
    else:
        record = spf_record.split("all")[0][-1] + "all"
        output_info(f"Found SPF all record: {record}")
        return record


def check_spf_includes(domain):
    count = get_includes_for_domain(domain)
    if count > 10:
        output_warning(f"Too many SPF include lookups {count}.")
        return True
    else: return False


def get_includes_for_domain(domain):
    spf_record = ""
    includes = []
    try:
        spf = spoofy_resolver.resolve(domain , 'TXT')
        for dns_data in spf:
            if 'spf1' in str(dns_data):
                spf_record = str(dns_data).replace('"','')
                break 
        if spf_record:
            for item in spf_record.split(' '):
                if "include:" in item:
                    includes.append(item.replace('include:', ''))
    except: 
        pass #intentionally shitty
    return len(includes) + sum([get_includes_for_domain(i) for i in includes]) + 1


def get_dmarc_record(domain):
    try: 
        dmarc = spoofy_resolver.resolve('_dmarc.' + domain , 'TXT')
        dmarc_record = ""
        for dns_data in dmarc:
            if 'DMARC1' in str(dns_data):
                dmarc_record = str(dns_data).replace('"','')
                output_info(f"Found DMARC record: {dmarc_record}")
                break
        policy = get_dmarc_policy(dmarc_record)
        get_dmarc_reports(dmarc_record)
        pct = get_dmarc_pct(dmarc_record)
        aspf = get_dmarc_aspf(dmarc_record)
        sub = get_dmarc_subdomain_policy(dmarc_record)
        return policy, pct, aspf, sub
    except:
        if domain.count('.') > 1: return check_dmarc_org_policy(domain)
        else: 
            output_info("No DMARC record found")
            return None, None, None, None


def check_dmarc_org_policy(subdomain):
        domain = ".".join(subdomain.split('.')[1:])
        try: 
            dmarc = spoofy_resolver.resolve('_dmarc.' + domain , 'TXT')
            dmarc_record = ""
            for dns_data in dmarc:
                if 'DMARC1' in str(dns_data):
                    dmarc_record = str(dns_data).replace('"','')
                    output_info(f"Found DMARC record: {dmarc_record}")
                    break
            policy = get_dmarc_policy(dmarc_record)
            get_dmarc_reports(dmarc_record)
            pct = get_dmarc_pct(dmarc_record)
            aspf = get_dmarc_aspf(dmarc_record)
            sub = get_dmarc_subdomain_policy(dmarc_record)
            return policy, pct, aspf, sub
        except:
            output_bad("No organizational record.")
            return None, None, None, None


def get_dmarc_policy(dmarc_record):
    if "p=" in str(dmarc_record):
        policy = str(dmarc_record).split("p=")[1].split(";")[0]
        output_info(f"Found DMARC policy: {policy}")
        return policy
    else:
        return None


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
    else:
        return None


def get_dmarc_aspf(dmarc_record):
    if "aspf=" in str(dmarc_record):
        aspf = str(dmarc_record).split("aspf=")[1].split(";")[0]
        output_info(f"Found DMARC aspf: {aspf}")
        return aspf
    else:
        return None


def get_dmarc_subdomain_policy(dmarc_record):
    if "sp=" in str(dmarc_record):
        subdomain_policy = str(dmarc_record).split("sp=")[1].split(";")[0]
        output_info(f"Found DMARC subdomain policy: {subdomain_policy}")
        return subdomain_policy
    else:
        return None


# Table thanks to @Calamity
def is_spoofable(domain, dmarc, spf, includes, pct, aspf):
    try:
        if dmarc is None: output_good("Spoofing possible for " + domain)
        elif (pct is not None) and (pct != 100): output_good("Spoofing possible for " + domain)
        elif dmarc == "none":
            if aspf is not None:
                if aspf == "r":
                    if spf == "?all": output_good("Spoofing possible for " + domain)
                    else: output_warning("Spoofing might be possible for " + domain)
                if aspf == "s":
                    if spf == "~all": output_warning("Spoofing might be possible for " + domain)
                    elif spf == "?all": output_good("Spoofing possible for " + domain)
                    else: output_bad("Spoofing is not possible for " + domain)
            else:
                if spf == "-all" or spf == "~all": output_warning("Spoofing might be possible for " + domain)
                else: output_good("Spoofing possible for " + domain)
        elif dmarc == "reject" or dmarc == "quarantine":
            if aspf is not None:
                if aspf == "r": output_warning("Spoofing might be possible for " + domain)
                else:
                    if spf == "?all": output_warning("Spoofing might be possible for " + domain)
                    else: output_bad("Spoofing is not possible for " + domain)
            else:
                if spf == "-all" or spf == "~all": output_bad("Spoofing is not possible for " + domain)
                else: output_warning("Spoofing might be possible for " + domain)
    except IndexError:
        output_error("If you hit this error message, something is really messed up.")


def check_domains(domains):
        for domain in domains:
            try:
                spoofy_resolver.nameservers[0] = get_dns_server(domain)
                output_indifferent("Domain: " + domain)
                spf_keys = get_spf_record(domain)
                dmarc_keys = get_dmarc_record(domain)
                is_spoofable(domain, dmarc_keys[0], spf_keys[0], spf_keys[1], dmarc_keys[1], dmarc_keys[2])
                print("\n")
            except IndexError: output_error("Domain format cannot be interpreted.")


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
