#! /usr/bin/env python3

import argparse, sys, dns.resolver, time

from colorama import init as color_init

from libs.PrettyOutput import (
    output_good,
    output_bad,
    output_warning,
    output_info,
    output_error,
    output_indifferent,
)

def get_spf_record(domain):
    try: 
        spf_record = dns.resolver.resolve(domain , 'TXT')
        for dns_data in spf_record:
            if 'spf1' in str(dns_data):
                output_info(f"Found SPF record: {dns_data}")
                break
        all = check_spf_all_string(str(dns_data).replace('"',''))
        includes = False

        return all, includes
    except:
        output_info("No SPF record found")
        return None, None

def check_spf_all_string(spf_record):
    record = ""
    if spf_record.count("all") > 1: 
        output_good("SPF record contains multiple `All` items.")
        return "2many"
    else:
        record = spf_record.split("all")[0][-1] + "all"
        output_info(f"Found SPF all record: {record}")
        return record



"""
check if DMARC record exists, 
if it DOES exist: check policy and agg/forensic and pct and aspf and subdomain policy
if NOT then check for organizational record
if it DOES exist: check policy and agg/forensic and pct and aspf and subdomain policy
"""
def get_dmarc_record(domain):
    try: 
        dmarc_record = dns.resolver.resolve('_dmarc.' + domain , 'TXT')
        for dns_data in dmarc_record:
            if 'DMARC1' in str(dns_data):
                output_info(f"Found DMARC record: {dns_data}")
                break
        # Policy
        policy = get_dmarc_policy(str(dns_data))
        output_info(f"Found DMARC policy: {policy}")
        # Reports
        #get_dmarc_reports(str(dns_data))
        # pct
        pct = get_dmarc_pct(str(dns_data))
        # ASPF
        aspf = get_dmarc_aspf(str(dns_data))
        # SUBDOMAIN
        sub = get_dmarc_subdomain_policy(str(dns_data))
        return policy, pct, aspf, sub
    except:
        if domain.count('.') > 1: return check_dmarc_org_policy(domain)
        else: 
            #print( "Not a subdomain" )
            return None, None, None, None
        # not subdomain


def check_dmarc_org_policy(subdomain):
        domain = ".".join(subdomain.split('.')[1:])
        print("DEBUG: Org Domain: " + domain)
        try: 
            dmarc_record = dns.resolver.resolve('_dmarc.' + domain , 'TXT')
            # if org record exists
            for dns_data in dmarc_record:
                if 'DMARC1' in str(dns_data):
                    output_info(f"Found DMARC record: {dns_data}")
                    break
            # if org record exists        
            policy = get_dmarc_policy(str(dns_data))
            output_info(f"Found DMARC policy: {policy}")
                # pct
            pct = get_dmarc_pct(str(dns_data))
            # ASPF
            aspf = get_dmarc_aspf(str(dns_data))
            # SUBDOMAIN
            sub = get_dmarc_subdomain_policy(str(dns_data))
            return policy, pct, aspf, sub
        except:
            print( "No Organizational Record" )
            return None, None, None, None

def get_dmarc_policy(dmarc_record):
    #print("DEBUG (get_dmarc_policy):" + dmarc_record )
    if "p=" in str(dmarc_record):
        policy = str(dmarc_record).split("p=")[1].split(";")[0] #Aint that jank
        return policy
    else:
        return None

def get_dmarc_reports():
    return "Agg"


def get_dmarc_pct(dmarc_record):
    #print("DEBUG (get_dmarc_pct):" + dmarc_record )
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
    #print("DEBUG (get_dmarc_subdomain_policy):" + dmarc_record )
    if "sp=" in str(dmarc_record):
        subdomain_policy = str(dmarc_record).split("sp=")[1].split(";")[0]
        output_info(f"Found DMARC subdomain policy: {subdomain_policy}")
        return subdomain_policy
    else:
        return None


def is_spoofable(domain, dmarc, spf, includes, pct, aspf):
    try:
        if dmarc is None:
            output_good("Spoofing possible for " + domain)
        elif (pct is not None) and (pct != 100):  output_good("Spoofing possible for " + domain)
        elif dmarc == "none":
            if aspf is not None:
                if aspf == "r":
                    if spf == "?all":output_good("Spoofing possible for " + domain)
                    else:output_warning("Spoofing might be possible for " + domain)
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
                    else:output_bad("Spoofing is not possible for " + domain)
            else:
                if spf == "-all" or spf == "~all": output_bad("Spoofing is not possible for " + domain)
                else: output_warning("Spoofing might be possible for " + domain)

    except IndexError:
        output_error("Something broke. Debug:2")



def check_domains(domains):
        for domain in domains:
            try:
                print("\nDomain: " + domain)
                # Returns 0-all 1-includes
                spf_keys = get_spf_record(domain)
                # Returns policy, pct, aspf, sub
                dmarc_keys = get_dmarc_record(domain)
                # domain, dmarc, spf(alls), spf(includes), pct, aspf, 
                #print("D domain:" + domain)
                #print("D dmarc:" + str(dmarc_keys[0]))
                #print(len(spf_keys))
                #print("D spf(alls):" +str(spf_keys[0]))
                #print("D spf(includes):" + str(spf_keys[1]))
                #print("D pct:" + str(dmarc_keys[1]))
                #print("D aspf:" + str(dmarc_keys[2]))
                is_spoofable(domain, dmarc_keys[0], spf_keys[0], spf_keys[1], dmarc_keys[1], dmarc_keys[2] )
                #is_spoofable(domain, "reject", "-all", None, None, None )
            except IndexError:
                output_error("Something broke. Debug:HERE")


if __name__ == "__main__":
    color_init()
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-iL", type=str, required=False, help="Provide an input list.")
    group.add_argument("-d", type=str, required=False, help="Provide an single domain.")
    options = parser.parse_args()
    if not any(vars(options).values()):
        parser.error("No arguments provided. Usage: `spoofcheck.py -d [DOMAIN]` OR `spoofcheck.py -iL [DOMAIN_LIST]`")
    domains = []
    if options.iL:
        try:
            with open(options.iL, "r") as f:
                for line in f:
                    domains.append(line.strip('\n'))
        except IOError:
            print("File doesnt exist or cannot be read.")
    if options.d:
        domains.append(options.d)
    check_domains(domains)
