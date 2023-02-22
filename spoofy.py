#! /usr/bin/env python3

import argparse, dns.resolver, tldextract, socket, re, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init as color_init
import pandas as pd
from libs.Printer import printer, error
from libs.SpoofyLogic import is_spoofable

temp = dns.resolver.Resolver()

def get_soa_record(domain):
    temp.nameservers[0] = '1.1.1.1'
    query = temp.resolve(domain, 'SOA')
    if query:
        for data in query: dns_server = str(data.mname)
        return socket.gethostbyname(dns_server)
    return None

def get_spf_record(domain, dns_server):
    spf = None
    try: 
        try: 
            a = dns.resolver.Resolver()
            a.nameservers[0] = dns_server
            spf = a.resolve(domain , 'TXT')
        except:
            return None
        for dns_data in spf:
            if 'spf1' in str(dns_data):
                spf_record = str(dns_data).replace('"','')
                break  
        if spf_record == "": return None
        return spf_record
    except:
        return None

def get_spf_all_string(spf_record):
    count = spf_record.count(" ~all") + spf_record.count(" ?all") + spf_record.count(" -all")
    if count == 1: 
        record = re.search("[-,~,?]all", spf_record).group(0)
        return record
    elif count == 0: return None
    else: return "2many"

def get_spf_includes(domain, count=0):
    if count > 10: return count
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
        # uncomment for debug. Shows if cannot find SPF record for a domain
        #print("Could not find SPF record for " + domain)
    return count

def get_dmarc_record(domain, dns_server):
    def dmarc(domain):
        try: 
            temp.nameservers[0] = dns_server
            dmarc = temp.resolve('_dmarc.' + domain , 'TXT')
        except:
            return None
        dmarc_record = ""
        for dns_data in dmarc:
            if 'DMARC1' in str(dns_data):
                dmarc_record = str(dns_data).replace('"','')
                break
        return dmarc_record

    dmarc_record = dmarc(domain)
    if dmarc_record:
        return dmarc_record
    else:
        subdomain = tldextract.extract(domain).registered_domain
        if subdomain != domain:
            sub_dmarc = dmarc(subdomain)
            if sub_dmarc:
                return sub_dmarc
        return None

def get_dmarc_policy(dmarc_record):
    if "p=" in str(dmarc_record): return str(dmarc_record).split("p=")[1].split(";")[0]
    else: return None

def get_dmarc_pct(dmarc_record):
    if "pct" in str(dmarc_record): return str(dmarc_record).split("pct=")[1].split(";")[0]
    else: return None

def get_dmarc_aspf(dmarc_record):
    if "aspf=" in str(dmarc_record): return str(dmarc_record).split("aspf=")[1].split(";")[0]
    else: return None

def get_dmarc_subdomain_policy(dmarc_record):
    if "sp=" in str(dmarc_record):return str(dmarc_record).split("sp=")[1].split(";")[0]
    else: return None

def get_forensics_report(dmarc_record):
    if "ruf=" in str(dmarc_record) and "fo=1" in str(dmarc_record): return str(dmarc_record).split("ruf=")[1].split(";")[0]
    else: return None

def get_aggregate_report(dmarc_record):
    if "rua=" in str(dmarc_record): return str(dmarc_record).split("rua=")[1].split(";")[0]
    else: return None

def find_dns_server(domain):
    SOA = get_soa_record(domain)
    if SOA:
        spf = get_spf_record(domain, SOA)
        dmarc = get_dmarc_record(domain, SOA)
        if (spf is not None) or (dmarc is not None):
            return SOA, spf, dmarc
    spf = get_spf_record(domain, '1.1.1.1')
    dmarc = get_dmarc_record(domain, '1.1.1.1')
    if (spf is not None) or (dmarc is not None):
        return '1.1.1.1', spf, dmarc
    spf = get_spf_record(domain, '8.8.8.8')
    dmarc = get_dmarc_record(domain, '8.8.8.8')
    if (spf is not None) or (dmarc is not None):
        return '8.8.8.8', spf, dmarc
    # No SPF or DMARC record found using 3 different DNS providers. 
    # Defaulting back to Cloudflare
    return '1.1.1.1', None, None 

def orchestrator(domains, output):
    for domain in domains:
        try:
            # Initiate Variables
            dns_server=None;
            spf_record=None; spf_all=None; spf_includes=None;
            dmarc_record=None; subdomain=bool(tldextract.extract(domain).subdomain); 
            p=None; pct=None; aspf=None; sp=None; fo=None; rua=None;
            dns_server, spf_record, dmarc_record = find_dns_server(domain)
            if spf_record:
                spf_all = get_spf_all_string(spf_record)
                spf_includes = get_spf_includes(domain)
            if dmarc_record:
                p = get_dmarc_policy(dmarc_record)
                pct = get_dmarc_pct(dmarc_record)
                aspf = get_dmarc_aspf(dmarc_record)
                sp = get_dmarc_subdomain_policy(dmarc_record)
                fo = get_forensics_report(dmarc_record)
                rua = get_aggregate_report(dmarc_record)
            spoofable = is_spoofable(domain, p, aspf, spf_record, spf_all, spf_includes, sp, pct)
            if output == "xls":
                data = [
                {'DOMAIN': domain, 'SUBDOMAIN': subdomain,'SPF': spf_record, 'SPF MULTIPLE ALLS': spf_all,
                 'SPF TOO MANY INCLUDES': spf_includes,'DMARC': dmarc_record,'DMARC POLICY': p,
                 'DMARC PCT': pct,'DMARC ASPF': aspf,'DMARC SP': sp,'DMARC FORENSIC REPORT': fo,
                 'DMARC AGGREGATE REPORT': rua,'SPOOFING POSSIBLE': spoofable}]
                file_name = "report.xlsx"
                if not os.path.exists(file_name):
                    with open(file_name, 'w'):
                        pass
                if os.path.getsize(file_name) > 0:
                    existing_df = pd.read_excel(file_name)
                    new_df = pd.DataFrame(data)
                    combined_df = pd.concat([existing_df, new_df])
                    combined_df.to_excel(file_name, index=False)
                else:
                    df = pd.DataFrame(data)
                    df.to_excel(file_name, index=False)
            else:
                printer(domain, subdomain, dns_server, spf_record, spf_all,
                 spf_includes, dmarc_record, p, pct, aspf, sp, fo, rua, spoofable) 
        except: error(f"Domain {domain} format cannot be interpreted.")



if __name__ == "__main__":
    color_init()
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-iL", type=str, required=False, help="Provide an input list.")
    group.add_argument("-d", type=str, required=False, help="Provide an single domain.")
    parser.add_argument("-o", type=str, choices=['xls', 'stdout'], required=True, help="Output format stdout or xls")
    options = parser.parse_args()
    if not any(vars(options).values()): parser.error("No arguments provided. Usage: `spoofy.py -d [DOMAIN]` OR `spoofy.py -iL [DOMAIN_LIST] Optional: -t [THREADS]`")
    domains = []
    if options.iL:
        try:
            with open(options.iL, "r") as f:
                for line in f: domains.append(line.strip('\n'))
        except IOError: error("File doesnt exist or cannot be read.")
    if options.d:
        domains.append(options.d)
    orchestrator(domains, options.o)