#! /usr/bin/env python3

import argparse, tldextract
from libs import dmarc, dns, logic, spf, report


def process_domains(domains, output):
    """This function takes a list of domains and an output format (either 'xls' or 'stdout')
      as arguments. It processes each domain, collects its relevant details, 
      and outputs the results to the console or an Excel file."""
    for domain in domains:
        try:
            dns_server = spf_record = dmarc_record = None
            print("DEBUG A")
            spf_all = spf_includes = p = pct = aspf = sp = fo = rua = None
            print("DEBUG B")
            print(domain)
            subdomain = bool(tldextract.extract(domain).subdomain)
            print("DEBUG C")
            dns_server, spf_record, dmarc_record = dns.get_dns_server(domain)
            print("DEBUG D")
            print(dns_server)
            print(spf_record)
            print(dmarc_record)
            if spf_record:
                spf_all = spf.get_spf_all_string(spf_record)
                print(f"DEBUG D1 {spf_all}")
                spf_includes = spf.get_spf_includes(domain)
                print(f"DEBUG D2 {spf_includes} ")

            print("DEBUG E")
            if dmarc_record:
                p, pct, aspf, sp, fo, rua = dmarc.get_dmarc_details(dmarc_record)
            print("DEBUG F")
            spoofable = logic.is_spoofable(domain, p, aspf, spf_record, spf_all, spf_includes, sp, pct)
            print("DEBUG G")
            if output == "xls":
                data = [{'DOMAIN': domain, 'SUBDOMAIN': subdomain, 'SPF': spf_record, 'SPF MULTIPLE ALLS': spf_all,
                        'SPF TOO MANY INCLUDES': spf_includes, 'DMARC': dmarc_record, 'DMARC POLICY': p,
                        'DMARC PCT': pct, 'DMARC ASPF': aspf, 'DMARC SP': sp, 'DMARC FORENSIC REPORT': fo,
                        'DMARC AGGREGATE REPORT': rua, 'SPOOFING POSSIBLE': spoofable}]
                report.write_to_excel(data)
                print("DEBUG H")               
            else:
                print("DEBUG I")   
                report.printer(domain, subdomain, dns_server, spf_record, spf_all, spf_includes, dmarc_record, p, pct, aspf,
                        sp, fo, rua, spoofable)
        except:
            report.output_error(f"Domain {domain} is offline or format cannot be interpreted.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-iL", type=str, required=False, help="Provide an input list.")
    group.add_argument("-d", type=str, required=False, help="Provide an single domain.")
    parser.add_argument("-o", type=str, choices=['xls', 'stdout'], required=True, help="Output format stdout or xls")
    options = parser.parse_args()
    if not any(vars(options).values()): parser.error("No arguments provided. Usage: `spoofy.py -d [DOMAIN] -o [stdout or xls]` OR `spoofy.py -iL [DOMAIN_LIST] -o [stdout or xls]`")
    domains = []
    if options.iL:
        try:
            with open(options.iL, "r") as f:
                for line in f: domains.append(line.strip('\n'))
        except IOError: report.output_error("File doesnt exist or cannot be read.")
    if options.d:
        domains.append(options.d)
    process_domains(domains, options.o)