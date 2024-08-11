#! /usr/bin/env python3
import argparse
import threading
from modules.dns import DNS
from modules.spf import SPF
from modules.dmarc import DMARC
from modules.bimi import BIMI
from modules.spoofing import Spoofing
from modules import report


def process_domain(domain):
    """Process a domain to gather DNS, SPF, DMARC, and BIMI records, and evaluate spoofing potential."""
    dns_info = DNS(domain)
    spf = SPF(domain, dns_info.dns_server)
    dmarc = DMARC(domain, dns_info.dns_server)
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

    bimi_record = bimi_info.bimi_record
    bimi_version = bimi_info.version
    bimi_location = bimi_info.location
    bimi_authority = bimi_info.authority

    spoofing_info = Spoofing(
        domain,
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
        "BIMI_RECORD": bimi_record,
        "BIMI_VERSION": bimi_version,
        "BIMI_LOCATION": bimi_location,
        "BIMI_AUTHORITY": bimi_authority,
        "SPOOFING_POSSIBLE": spoofing_possible,
        "SPOOFING_TYPE": spoofing_type,
    }
    return result


def worker(domain_queue, result_queue):
    """Worker function to process domains and put results into the result queue."""
    while not domain_queue.empty():
        domain = domain_queue.get()
        if domain is None:
            break
        result = process_domain(domain)
        result_queue.put(result)
        domain_queue.task_done()


def process_domain_and_output(domain, output, results):
    """Process a domain and handle output based on the specified format."""
    result = process_domain(domain)
    if output == "stdout":
        report.printer(**result)
    else:
        results.append(result)


def main():
    parser = argparse.ArgumentParser(
        description="Process domains to gather DNS, SPF, DMARC, and BIMI records."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", type=str, help="Single domain to process.")
    group.add_argument(
        "-iL", type=str, help="File containing a list of domains to process."
    )
    parser.add_argument(
        "-o",
        type=str,
        choices=["stdout", "xls"],
        default="stdout",
        help="Output format: stdout or xls (default: stdout).",
    )

    args = parser.parse_args()

    # Load domains
    if args.d:
        domains = [args.d]
    elif args.iL:
        with open(args.iL, "r") as file:
            domains = [line.strip() for line in file]

    # Prepare for processing
    results = []
    threads = []

    # Start threads to process each domain
    for domain in domains:
        thread = threading.Thread(
            target=process_domain_and_output, args=(domain, args.o, results)
        )
        thread.start()
        threads.append(thread)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Handle output for xls format
    if args.o == "xls" and results:
        report.write_to_excel(results)
        print("Results written to output.xlsx")


if __name__ == "__main__":
    main()
