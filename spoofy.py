#! /usr/bin/env python3
from modules.dns import DNS
from modules.spf import SPF
from modules.dmarc import DMARC
from modules.bimi import BIMI
from modules.spoofing import Spoofing

import argparse
import tldextract
import threading

def process_domain(domain):

    dns_info = DNS(domain)
    spf = SPF(domain, dns_info.dns_server)
    dmarc = DMARC(domain, dns_info.dns_server)
    bimi_info = BIMI(domain, dns_info.dns_server)

    spf_record = spf.spf_record
    spf_all = spf.all_mechanism
    spf_num_includes = spf.num_includes
    spf_too_many_includes = spf.too_many_includes

    dmarc_record = dmarc.dmarc_record
    dmarc_p = dmarc.policy
    dmarc_pct = dmarc.pct
    dmarc_aspf = dmarc.aspf
    dmarc_sp = dmarc.sp
    dmarc_fo = dmarc.fo
    dmarc_rua = dmarc.rua

    bimi_record = bimi_info.bimi_record
    bimi_version = bimi_info.version
    bimi_location = bimi_info.location
    bimi_authority = bimi_info.authority


    spoofing_info = Spoofing(domain, dmarc_p, dmarc_aspf, spf_record, spf_all, spf_num_includes, dmarc_sp, dmarc_pct)

    domain_type = spoofing_info.domain_type
    spoofing_possible = spoofing_info.spoofing_possible
    spoofing_type = spoofing_info.spoofing_type


    result = {
    'DOMAIN_TYPE': domain_type,
    'DNS_SERVER': dns_info.dns_server,
    'SPF': spf_record, 
    'SPF_MULTIPLE_ALLS': spf_all,
    'SPF_NUM_INCLUDES': spf_num_includes,
    'SPF_TOO_MANY_INCLUDES': spf_too_many_includes, 
    'DMARC': dmarc_record, 
    'DMARC_POLICY': dmarc_p, 
    'DMARC_PCT': dmarc_pct, 
    'DMARC_ASPF': dmarc_aspf,
    'DMARC_SP': dmarc_sp, 
    'DMARC_FORENSIC_REPORT': dmarc_fo,
    'DMARC_AGGREGATE_REPORT': dmarc_rua,
    'BIMI_RECORD': bimi_record, 
    'BIMI_VERSION': bimi_version,
    'BIMI_LOCATION': bimi_location,
    'BIMI_AUTHORITY': bimi_authority,
    'SPOOFING_POSSIBLE': spoofing_possible,
    'SPOOFING_TYPE': spoofing_type
    }
    return result

if __name__ == "__main__":
    # for domain in domains
    # process the domain, get the results. Store those results in batches of 100
    # if the 100 mark is hit, write it to stdout, clear the stoage and work on next batch
    pass