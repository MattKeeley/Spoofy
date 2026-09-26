# modules/report.py

import json
import os

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
    import pandas as pd  # slow to import, and only -o xls needs it

    new_df = pd.DataFrame([_flatten(result) for result in data])
    if os.path.exists(file_name) and os.path.getsize(file_name) > 0:
        existing_df = pd.read_excel(file_name)
        combined_df = pd.concat([existing_df, new_df])
        combined_df.to_excel(file_name, index=False)
    else:
        new_df.to_excel(file_name, index=False)


def output_json(results):
    print(json.dumps(results, indent=2, default=str))


# (result key, message when set, message when missing or None to skip, level)
DMARC_LINES = (
    ("DMARC_POLICY", "Found DMARC policy: {}", "No DMARC policy found.", "info"),
    ("DMARC_PCT", "Found DMARC pct: {}", "No DMARC pct found.", "info"),
    ("DMARC_ASPF", "Found DMARC aspf: {}", "No DMARC aspf found.", "info"),
    (
        "DMARC_SP",
        "Found DMARC subdomain policy: {}",
        "No DMARC subdomain policy found.",
        "info",
    ),
    ("DMARC_NP", "Found DMARC non-existent subdomain policy: {}", None, "info"),
    (
        "DMARC_FORENSIC_REPORT",
        "Forensics reports will be sent: {}",
        "No DMARC forensics report location found.",
        "indifferent",
    ),
    (
        "DMARC_AGGREGATE_REPORT",
        "Aggregate reports will be sent to: {}",
        "No DMARC aggregate report location found.",
        "indifferent",
    ),
)


def printer(**result):
    """Prints the SPF, DMARC, DKIM, and BIMI results for one domain."""
    get = result.get
    domain = get("DOMAIN")

    output_message("[*]", f"Domain: {domain}", "indifferent")
    if get("ERROR"):
        output_message("[!]", f"Error: {get('ERROR')}", "error")
        output_message("[?]", get("SPOOFING_TYPE"), "warning")
        print()
        return
    output_message(
        "[*]", f"Is subdomain: {get('DOMAIN_TYPE') == 'subdomain'}", "indifferent"
    )
    output_message("[*]", f"DNS Server: {get('DNS_SERVER')}", "indifferent")

    if get("SPF"):
        spf_all, count = get("SPF_MULTIPLE_ALLS"), get("SPF_NUM_DNS_QUERIES")
        output_message("[*]", f"SPF record: {get('SPF')}", "info")
        output_message(
            "[*]",
            f"SPF all record: {spf_all}"
            if spf_all
            else "SPF does not contain an `All` item.",
            "info",
        )
        output_message(
            "[*]",
            f"SPF DNS query count: {count}"
            if count <= 10
            else f"Too many SPF DNS query lookups {count}.",
            "info",
        )
        for error in get("SPF_ERRORS") or []:
            output_message("[?]", f"SPF permerror: {error}", "warning")
        for target in get("SPF_DANGLING_INCLUDES") or []:
            output_message(
                "[+]",
                f"SPF includes {target}, which appears unregistered: registering it lets you pass SPF for {domain}.",
                "good",
            )
    else:
        output_message("[?]", "No SPF record found.", "warning")

    if get("DMARC"):
        output_message("[*]", f"DMARC record: {get('DMARC')}", "info")
        if get("DMARC_RECORD_DOMAIN") not in (None, domain):
            output_message(
                "[*]",
                f"DMARC record inherited from {get('DMARC_RECORD_DOMAIN')}.",
                "info",
            )
        for key, found, missing, level in DMARC_LINES:
            if get(key) or missing:
                output_message(
                    "[*]", found.format(get(key)) if get(key) else missing, level
                )
    else:
        output_message("[?]", "No DMARC record found.", "warning")

    if get("DKIM"):
        output_message("[*]", f"DKIM selectors: \r\n{get('DKIM')}", "info")
    else:
        output_message(
            "[?]", f"No known DKIM selectors enumerated on {domain}.", "warning"
        )

    if get("BIMI_RECORD"):
        output_message("[*]", f"BIMI record: {get('BIMI_RECORD')}", "info")
        output_message("[*]", f"BIMI version: {get('BIMI_VERSION')}", "info")
        output_message("[*]", f"BIMI location: {get('BIMI_LOCATION')}", "info")
        output_message("[*]", f"BIMI authority: {get('BIMI_AUTHORITY')}", "info")

    for warning in get("WARNINGS") or []:
        output_message("[?]", warning, "warning")

    level, symbol = {True: ("good", "[+]"), False: ("bad", "[-]")}.get(
        get("SPOOFING_POSSIBLE"), ("warning", "[?]")
    )
    output_message(symbol, get("SPOOFING_TYPE"), level)

    print()  # Padding
