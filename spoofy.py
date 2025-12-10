#! /usr/bin/env python3

# spoofy.py
import argparse
import threading
from queue import Queue
from modules.dns import DNS
from modules.spf import SPF
from modules.dmarc import DMARC
from modules.dkim import DKIM
from modules.bimi import BIMI
from modules.mx import MX
from modules.spoofing import Spoofing
from modules.dnssec import DNSSEC
from modules.tenancy import CloudTenancy
from modules import report

print_lock = threading.Lock()


def process_domain(domain, enable_dkim=False):
    """Process a domain to gather DNS, SPF, DMARC, MX, DNSSEC and BIMI records."""
    dns_info = DNS(domain)
    spf = SPF(domain, dns_info.dns_server)
    dmarc = DMARC(domain, dns_info.dns_server)
    mx_info = MX(domain, dns_info.dns_server)
    bimi_info = BIMI(domain, dns_info.dns_server)

    spf_record = spf.spf_record
    spf_all = spf.all_mechanism
    spf_dns_query_count = spf.spf_dns_query_count
    spf_too_many_dns_queries = spf.too_many_dns_queries

    dmarc_record = dmarc.dmarc_record
    dmarc_p = dmarc.policy
    dmarc_pct = dmarc.pct
    dmarc_aspf = dmarc.aspf
    dmarc_sp = dmarc.sp
    dmarc_fo = dmarc.fo
    dmarc_rua = dmarc.rua

    mx_records = mx_info.mx_records
    mx_provider = mx_info.provider
    is_microsoft = mx_info.is_microsoft_customer()

    # Simplified cloud tenancy detection
    tenancy_info = CloudTenancy(domain, spf_record)
    tenant_domains = tenancy_info.get_tenant_domains() if tenancy_info.should_discover_tenants() else []

    dkim_record = None
    if enable_dkim:
        dkim = DKIM(domain, dns_info.dns_server)
        dkim_record = dkim.dkim_record

    bimi_record = bimi_info.bimi_record
    bimi_version = bimi_info.version
    bimi_location = bimi_info.location
    bimi_authority = bimi_info.authority

    spoofing_info = Spoofing(
        domain,
        dmarc_record,
        dmarc_p,
        dmarc_aspf,
        spf_record,
        spf_all,
        spf_dns_query_count,
        dmarc_sp,
        dmarc_pct,
    )

    domain_type = spoofing_info.domain_type
    spoofing_possible = spoofing_info.spoofing_possible
    spoofing_type = spoofing_info.spoofing_type
    dnssec_info = DNSSEC(domain, dns_info.dns_server)

    result = {
        "DOMAIN": domain,
        "DOMAIN_TYPE": domain_type,
        "DNS_SERVER": dns_info.dns_server,
        "SPF": spf_record,
        "SPF_MULTIPLE_ALLS": spf_all,
        "SPF_NUM_DNS_QUERIES": spf_dns_query_count,
        "SPF_TOO_MANY_DNS_QUERIES": spf_too_many_dns_queries,
        "DMARC": dmarc_record,
        "DMARC_POLICY": dmarc_p,
        "DMARC_PCT": dmarc_pct,
        "DMARC_ASPF": dmarc_aspf,
        "DMARC_SP": dmarc_sp,
        "DMARC_FORENSIC_REPORT": dmarc_fo,
        "DMARC_AGGREGATE_REPORT": dmarc_rua,
        "MX_RECORDS": mx_records,
        "MX_PROVIDER": mx_provider,
        "IS_MICROSOFT": is_microsoft,
        "DKIM": dkim_record,
        "DNSSEC_ENABLED": dnssec_info.dnssec_enabled,
        "BIMI_RECORD": bimi_record,
        "BIMI_VERSION": bimi_version,
        "BIMI_LOCATION": bimi_location,
        "BIMI_AUTHORITY": bimi_authority,
        "SPOOFING_POSSIBLE": spoofing_possible,
        "SPOOFING_TYPE": spoofing_type,
        "TENANT_DOMAINS": tenant_domains,
    }
    return result


def worker(domain_queue, print_lock, output, results, enable_dkim=False):
    """Worker function to process domains and output results."""
    while True:
        domain = domain_queue.get()
        if domain is None:
            break
        result = process_domain(domain, enable_dkim=enable_dkim)

        with print_lock:
            if output == "stdout":
                report.printer(**result)
            else:
                results.append(result)
        domain_queue.task_done()


def main():
    parser = argparse.ArgumentParser(
        description="Process domains to gather DNS, SPF, DMARC, and BIMI records. Use --dkim to enable DKIM selector enumeration."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", type=str, help="Single domain to process.")
    group.add_argument(
        "-iL", type=str, help="File containing a list of domains to process."
    )
    parser.add_argument(
        "-o",
        type=str,
        choices=["stdout", "xls", "json"],
        default="stdout",
        help="Output format: stdout or xls (default: stdout).",
    )
    parser.add_argument(
        "-t", type=int, default=4, help="Number of threads to use (default: 4)"
    )
    parser.add_argument(
        "--dkim", action="store_true", help="Enable DKIM selector enumeration via API"
    )
    parser.add_argument(
        "--expand-tenants", action="store_true", 
        help="Automatically discover and process Microsoft tenant domains"
    )

    args = parser.parse_args()

    if args.d:
        domains = [args.d]
    elif args.iL:
        with open(args.iL, "r") as file:
            domains = [line.strip() for line in file]

    # Expand tenant domains if requested
    if args.expand_tenants:
        initial_domains = domains.copy()
        for domain in initial_domains:
            # Quick check for Microsoft tenancy
            dns_info = DNS(domain)
            spf = SPF(domain, dns_info.dns_server)
            tenancy_info = CloudTenancy(domain, spf.spf_record)
            
            if tenancy_info.should_discover_tenants():
                tenant_domains = tenancy_info.get_tenant_domains()
                for tenant_domain in tenant_domains:
                    if tenant_domain not in domains:
                        domains.append(tenant_domain)
                        print(f"[*] Microsoft tenant domain discovered: {tenant_domain}")

    domain_queue = Queue()
    results = []

    for domain in domains:
        domain_queue.put(domain)

    threads = []
    for _ in range(min(args.t, len(domains))):
        thread = threading.Thread(
            target=worker, args=(domain_queue, print_lock, args.o, results, args.dkim)
        )
        thread.start()
        threads.append(thread)

    domain_queue.join()

    if args.o == "xls" and results:
        report.write_to_excel(results)
        print("Results written to output.xlsx")
    elif args.o == "json" and results:
        report.output_json(results)

    for _ in range(len(threads)):
        domain_queue.put(None)
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
