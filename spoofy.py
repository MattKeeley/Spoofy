#! /usr/bin/env python3

# spoofy.py
import argparse
from concurrent.futures import ThreadPoolExecutor

from modules import report
from modules.bimi import BIMI
from modules.dkim import DKIM
from modules.dmarc import DMARC
from modules.domains import is_subdomain, normalize_domain
from modules.resolver import get_resolver
from modules.spf import SPF
from modules.spoofing import MESSAGES, POSSIBLE, spoofability


def process_domain(domain, enable_dkim=False, dns_server=None, resolver=None):
    """Process a domain to gather SPF, DMARC, and BIMI records. Optionally enumerate DKIM selectors if enabled."""
    resolver = resolver or get_resolver(dns_server)
    spf = SPF(domain, resolver)
    dmarc = DMARC(domain, resolver)
    bimi = BIMI(domain, resolver)
    dkim_record = DKIM(domain).dkim_record if enable_dkim else None

    warnings = spf.warnings + dmarc.warnings
    if resolver.txt(domain).status == "nxdomain":
        warnings.insert(
            0, f"{domain} does not exist (NXDOMAIN); most receivers reject mail from it"
        )

    # An inherited DMARC record was tested together with the parent's SPF record.
    code = spoofability(
        SPF(dmarc.record_domain, resolver) if dmarc.inherited else spf, dmarc
    )

    return {
        "DOMAIN": domain,
        "DOMAIN_TYPE": "subdomain" if is_subdomain(domain) else "domain",
        "DNS_SERVER": ", ".join(resolver.nameservers),
        "SPF": spf.spf_record,
        "SPF_MULTIPLE_ALLS": spf.all_mechanism,
        "SPF_NUM_DNS_QUERIES": spf.spf_dns_query_count,
        "SPF_TOO_MANY_DNS_QUERIES": spf.too_many_dns_queries,
        "SPF_VOID_LOOKUPS": spf.void_lookups,
        "SPF_ERRORS": spf.errors,
        "SPF_DANGLING_INCLUDES": spf.dangling_includes,
        "DMARC": dmarc.dmarc_record,
        "DMARC_RECORD_DOMAIN": dmarc.record_domain,
        "DMARC_POLICY": dmarc.policy,
        "DMARC_PCT": dmarc.pct,
        "DMARC_ASPF": dmarc.aspf,
        "DMARC_SP": dmarc.sp,
        "DMARC_NP": dmarc.np,
        "DMARC_T": dmarc.t,
        "DMARC_FORENSIC_REPORT": dmarc.ruf,
        "DMARC_AGGREGATE_REPORT": dmarc.rua,
        "DKIM": dkim_record,
        "BIMI_RECORD": bimi.bimi_record,
        "BIMI_VERSION": bimi.version,
        "BIMI_LOCATION": bimi.location,
        "BIMI_AUTHORITY": bimi.authority,
        "WARNINGS": warnings,
        "SPOOFING_CODE": code,
        "SPOOFING_POSSIBLE": POSSIBLE.get(code),
        "SPOOFING_TYPE": MESSAGES[code].format(domain),
        "ERROR": None,
    }


def safe_process_domain(domain, enable_dkim=False, dns_server=None):
    """process_domain that never raises, so one bad domain cannot stall a bulk run."""
    try:
        return process_domain(domain, enable_dkim=enable_dkim, dns_server=dns_server)
    except Exception as e:  # noqa: BLE001 - one bad domain must not stall a bulk run
        return {
            "DOMAIN": domain,
            "SPOOFING_CODE": 9,
            "SPOOFING_POSSIBLE": None,
            "SPOOFING_TYPE": f"Unable to determine spoofability for {domain} ({type(e).__name__}: {e}).",
            "ERROR": f"{type(e).__name__}: {e}",
        }


def read_domains(args):
    if args.d:
        raw = [args.d]
    else:
        with open(args.iL, "r") as file:
            raw = file.read().splitlines()
    domains = []
    for line in raw:
        line = line.split("#", 1)[0]
        domain = normalize_domain(line) if line.strip() else ""
        if domain and domain not in domains:
            domains.append(domain)
    return domains


def main():
    parser = argparse.ArgumentParser(
        description="Process domains to gather SPF, DMARC, and BIMI records. Use --dkim to enable DKIM selector enumeration."
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
        help="Output format: stdout, xls, or json (default: stdout).",
    )
    parser.add_argument(
        "-t", type=int, default=4, help="Number of threads to use (default: 4)"
    )
    parser.add_argument(
        "--dkim", action="store_true", help="Enable DKIM selector enumeration via API"
    )
    parser.add_argument(
        "--dns-server",
        type=str,
        default=None,
        help="Resolver to query (default: 1.1.1.1, 8.8.8.8, 9.9.9.9 with failover)",
    )

    args = parser.parse_args()
    domains = read_domains(args)
    if not domains:
        parser.error("no domains to process")

    with ThreadPoolExecutor(max_workers=max(1, min(args.t, len(domains)))) as pool:
        # map() runs the lookups concurrently and yields results in input order
        results = pool.map(
            lambda domain: safe_process_domain(domain, args.dkim, args.dns_server),
            domains,
        )
        if args.o == "stdout":
            for result in results:
                report.printer(**result)
        elif args.o == "xls":
            report.write_to_excel(list(results))
            print("Results written to output.xlsx")
        else:
            report.output_json(list(results))


if __name__ == "__main__":
    main()
