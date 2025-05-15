# modules/report.py

import os
import pandas as pd
import json
from colorama import init, Fore, Style

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


def print_as_json(data):
    print(json.dumps(data))


def write_to_excel(data, file_name="output.xlsx"):
    """Writes a DataFrame of data to an Excel file, appending if the file exists."""
    if os.path.exists(file_name) and os.path.getsize(file_name) > 0:
        existing_df = pd.read_excel(file_name)
        new_df = pd.DataFrame(data)
        combined_df = pd.concat([existing_df, new_df])
        combined_df.to_excel(file_name, index=False)
    else:
        pd.DataFrame(data).to_excel(file_name, index=False)


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
    bimi_record = kwargs.get("BIMI_RECORD")
    vbimi = kwargs.get("BIMI_VERSION")
    location = kwargs.get("BIMI_LOCATION")
    authority = kwargs.get("BIMI_AUTHORITY")
    spoofable = kwargs.get("SPOOFING_POSSIBLE")
    spoofing_type = kwargs.get("SPOOFING_TYPE")

    output_message("[*]", f"Domain: {domain}", "indifferent")
    output_message("[*]", f"Is subdomain: {subdomain}", "indifferent")
    output_message("[*]", f"DNS Server: {dns_server}", "indifferent")

    if spf_record:
        output_message("[*]", f"SPF record: {spf_record}", "info")
        if spf_all is None:
            output_message("[*]", "SPF does not contain an `All` item.", "info")
        elif spf_all == "2many":
            output_message(
                "[?]", "SPF record contains multiple `All` items.", "warning"
            )
        else:
            output_message("[*]", f"SPF all record: {spf_all}", "info")
        output_message(
            "[*]",
            f"SPF DNS query count: {spf_dns_query_count}"
            if spf_dns_query_count <= 10
            else f"Too many SPF DNS query lookups {spf_dns_query_count}.",
            "info",
        )
    else:
        output_message("[?]", "No SPF record found.", "warning")

    if dmarc_record:
        output_message("[*]", f"DMARC record: {dmarc_record}", "info")
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

    if bimi_record:
        output_message("[*]", f"BIMI record: {bimi_record}", "info")
        output_message("[*]", f"BIMI version: {vbimi}", "info")
        output_message("[*]", f"BIMI location: {location}", "info")
        output_message("[*]", f"BIMI authority: {authority}", "info")

    if spoofing_type:
        level = "good" if spoofable else "bad"
        symbol = "[+]" if level == "good" else "[-]"
        output_message(symbol, spoofing_type, level)

    print()  # Padding
