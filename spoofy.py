#! /usr/bin/env python3

# spoofy.py
import argparse
import threading
from queue import Queue
from modules.dns import DNS
from modules.spf import SPF
from modules.dmarc import DMARC
from modules.bimi import BIMI
from modules.spoofing import Spoofing
from modules import report

print_lock = threading.Lock()


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


def worker(domain_queue, print_lock, output, results):
    """Worker function to process domains and output results."""
    while True:
        domain = domain_queue.get()
        if domain is None:
            break
        result = process_domain(domain)
        with print_lock:
            if output == "stdout":
                report.printer(**result)
            else:
                results.append(result)
        domain_queue.task_done()


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
        choices=["stdout", "xls", "json"],
        default="stdout",
        help="Output format: stdout (optionally as json) or xls (default: stdout).",
    )
    parser.add_argument(
        "-t", type=int, default=4, help="Number of threads to use (default: 4)"
    )

    args = parser.parse_args()

    if args.d:
        domains = [args.d]
    elif args.iL:
        with open(args.iL, "r") as file:
            domains = [line.strip() for line in file]

    domain_queue = Queue()
    results = []

    for domain in domains:
        domain_queue.put(domain)

    threads = []
    for _ in range(min(args.t, len(domains))):
        thread = threading.Thread(
            target=worker, args=(domain_queue, print_lock, args.o, results)
        )
        thread.start()
        threads.append(thread)

    domain_queue.join()

    if args.o == "json" and results:
        report.print_as_json(results)

    if args.o == "xls" and results:
        report.write_to_excel(results)
        print("Results written to output.xlsx")

    for _ in range(len(threads)):
        domain_queue.put(None)
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
