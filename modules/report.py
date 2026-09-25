# modules/report.py

import json
import os

import pandas as pd
from colorama import Fore, Style, init

# Initialize colorama
init()


def output_message(symbol, message, level="info"):
    """Generic function to print messages with different colors and symbols based on the level."""
    colors = {
        "good": Fore.GREEN + Style.BRIGHT,
        "warning": Fore.YELLOW + Style.BRIGHT,
        "bad": Fore.RED + Style.BRIGHT,
        "indifferent": Fore.BLUE + Style.BRIGHT,
        "error": Fore.RED + Style.BRIGHT + "!!! ",
        "info": Fore.WHITE + Style.BRIGHT,
    }
    color = colors.get(level, Fore.WHITE + Style.BRIGHT)
    print(color + f"{symbol} {message}" + Style.RESET_ALL)


def _flatten(result):
    """Excel cells hold scalars only: join list values."""
    return {
        key: "; ".join(map(str, value)) if isinstance(value, list) else value
        for key, value in result.items()
    }


def write_to_excel(data, file_name="output.xlsx"):
    """Writes a DataFrame of data to an Excel file, appending if the file exists."""
    new_df = pd.DataFrame([_flatten(result) for result in data])
    if os.path.exists(file_name) and os.path.getsize(file_name) > 0:
        existing_df = pd.read_excel(file_name)
        combined_df = pd.concat([existing_df, new_df])
        combined_df.to_excel(file_name, index=False)
    else:
        new_df.to_excel(file_name, index=False)


def output_json(results):
    print(json.dumps(results, indent=2, default=str))


def printer(**kwargs):
    """Utility function to print the results of DMARC, SPF, and BIMI checks in the original format."""
    domain = kwargs.get("DOMAIN")
    subdomain = kwargs.get("DOMAIN_TYPE") == "subdomain"
    dns_server = kwargs.get("DNS_SERVER")
    spf_record = kwargs.get("SPF")
    spf_all = kwargs.get("SPF_MULTIPLE_ALLS")
    spf_dns_query_count = kwargs.get("SPF_NUM_DNS_QUERIES")
    dmarc_record = kwargs.get("DMARC")
    p = kwargs.get("DMARC_POLICY")
    pct = kwargs.get("DMARC_PCT")
    aspf = kwargs.get("DMARC_ASPF")
    sp = kwargs.get("DMARC_SP")
    fo = kwargs.get("DMARC_FORENSIC_REPORT")
    rua = kwargs.get("DMARC_AGGREGATE_REPORT")
    dkim_record = kwargs.get("DKIM")
    bimi_record = kwargs.get("BIMI_RECORD")
    vbimi = kwargs.get("BIMI_VERSION")
    location = kwargs.get("BIMI_LOCATION")
    authority = kwargs.get("BIMI_AUTHORITY")
    spoofable = kwargs.get("SPOOFING_POSSIBLE")
    spoofing_type = kwargs.get("SPOOFING_TYPE")
    spf_errors = kwargs.get("SPF_ERRORS") or []
    dangling = kwargs.get("SPF_DANGLING_INCLUDES") or []
    record_domain = kwargs.get("DMARC_RECORD_DOMAIN")
    np = kwargs.get("DMARC_NP")
    effective = kwargs.get("DMARC_EFFECTIVE_POLICY")
    warnings = kwargs.get("WARNINGS") or []
    error = kwargs.get("ERROR")

    output_message("[*]", f"Domain: {domain}", "indifferent")
    if error:
        output_message("[!]", f"Error: {error}", "error")
        output_message("[?]", spoofing_type, "warning")
        print()
        return
    output_message("[*]", f"Is subdomain: {subdomain}", "indifferent")
    output_message("[*]", f"DNS Server: {dns_server}", "indifferent")

    if spf_record:
        output_message("[*]", f"SPF record: {spf_record}", "info")
        if spf_all is None:
            output_message("[*]", "SPF does not contain an `All` item.", "info")
        else:
            output_message("[*]", f"SPF all record: {spf_all}", "info")
        output_message(
            "[*]",
            f"SPF DNS query count: {spf_dns_query_count}"
            if spf_dns_query_count <= 10
            else f"Too many SPF DNS query lookups {spf_dns_query_count}.",
            "info",
        )
        for spf_error in spf_errors:
            output_message("[?]", f"SPF permerror: {spf_error}", "warning")
        for target in dangling:
            output_message(
                "[+]",
                f"SPF includes {target}, which appears unregistered: registering it lets you pass SPF for {domain}.",
                "good",
            )
    else:
        output_message("[?]", "No SPF record found.", "warning")

    if dmarc_record:
        output_message("[*]", f"DMARC record: {dmarc_record}", "info")
        if record_domain and record_domain != domain:
            output_message(
                "[*]",
                f"DMARC record inherited from {record_domain}; effective policy for {domain}: {effective}",
                "info",
            )
        output_message(
            "[*]", f"Found DMARC policy: {p}" if p else "No DMARC policy found.", "info"
        )
        output_message(
            "[*]", f"Found DMARC pct: {pct}" if pct else "No DMARC pct found.", "info"
        )
        output_message(
            "[*]",
            f"Found DMARC aspf: {aspf}" if aspf else "No DMARC aspf found.",
            "info",
        )
        output_message(
            "[*]",
            f"Found DMARC subdomain policy: {sp}"
            if sp
            else "No DMARC subdomain policy found.",
            "info",
        )
        if np:
            output_message("[*]", f"Found DMARC non-existent subdomain policy: {np}", "info")
        output_message(
            "[*]",
            f"Forensics reports will be sent: {fo}"
            if fo
            else "No DMARC forensics report location found.",
            "indifferent",
        )
        output_message(
            "[*]",
            f"Aggregate reports will be sent to: {rua}"
            if rua
            else "No DMARC aggregate report location found.",
            "indifferent",
        )
    else:
        output_message("[?]", "No DMARC record found.", "warning")

    if dkim_record:
        output_message("[*]", f"DKIM selectors: \r\n{dkim_record}", "info")
    else:
        output_message("[?]", f"No known DKIM selectors enumerated on {domain}.", "warning")

    if bimi_record:
        output_message("[*]", f"BIMI record: {bimi_record}", "info")
        output_message("[*]", f"BIMI version: {vbimi}", "info")
        output_message("[*]", f"BIMI location: {location}", "info")
        output_message("[*]", f"BIMI authority: {authority}", "info")

    for warning in warnings:
        output_message("[?]", warning, "warning")

    if spoofing_type:
        level, symbol = {True: ("good", "[+]"), False: ("bad", "[-]")}.get(
            spoofable, ("warning", "[?]")
        )
        output_message(symbol, spoofing_type, level)

    print()  # Padding
