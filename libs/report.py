from colorama import Fore, Style
from colorama import init as color_init
import os
import pandas as pd

color_init()


def output_good(line):
    print(Fore.GREEN + Style.BRIGHT + "[+]" + Style.RESET_ALL, line)


def output_warning(line):
    print(Fore.YELLOW + Style.BRIGHT + "[?]" + Style.RESET_ALL, line)


def output_bad(line):
    print(Fore.RED + Style.BRIGHT + "[-]" + Style.RESET_ALL, line)


def output_indifferent(line):
    print(Fore.BLUE + Style.BRIGHT + "[*]" + Style.RESET_ALL, line)


def output_error(line):
    print(Fore.RED + Style.BRIGHT + "[-] !!! " +
          Style.NORMAL, line, Style.BRIGHT + "!!!\n")


def output_info(line):
    print(Fore.WHITE + Style.BRIGHT + "[*]" + Style.RESET_ALL, line)


def write_to_excel(data):
    """This function writes a DataFrame of data to an Excel file. 
    If the file does not already exist, it creates the file, and if the file already exists, it appends the new data to the existing data."""
    file_name = "report.xlsx"
    if not os.path.exists(file_name):
        open(file_name, 'w').close()

    if os.path.getsize(file_name) > 0:
        existing_df = pd.read_excel(file_name)
        new_df = pd.DataFrame(data)
        combined_df = pd.concat([existing_df, new_df])
        combined_df.to_excel(file_name, index=False)
    else:
        df = pd.DataFrame(data)
        df.to_excel(file_name, index=False)


def printer(domain, subdomain, dns_server, spf_record, spf_all, spf_includes, dmarc_record, p, pct, aspf, sp, fo, rua, bimi_record, vbimi, location, authority, spoofable):
    """This function is a utility function that takes in various parameters related to the 
    results of DMARC and SPF checks and outputs the results to the console in a human-readable format.

    Printer ID Handler:
    0: Indicates that spoofing is possible for the domain.
    1: Indicates that subdomain spoofing is possible for the domain.
    2: Indicates that organizational domain spoofing is possible for the domain.
    3: Indicates that spoofing might be possible for the domain.
    4: Indicates that spoofing might be possible (mailbox dependent) for the domain.
    5: Indicates that organizational domain spoofing may be possible for the domain.
    6: Indicates that subdomain spoofing might be possible (mailbox dependent) for the domain.
    7: Indicates that subdomain spoofing is possible, and organizational domain spoofing might be possible.
    8: Indicates that spoofing is not possible for the domain.
    """
    output_indifferent(f"Domain: {domain}")
    output_indifferent(f"Is subdomain: {subdomain}")
    output_indifferent(f"DNS Server: {dns_server}")

    if spf_record:
        output_info(f"SPF record: {spf_record}")
        if spf_all is None:
            output_info("SPF does not contain an `All` items.")
        elif spf_all == "2many":
            output_warning("SPF record contains multiple `All` items.")
        else:
            output_info(f"SPF all record: {spf_all}")
        output_info(f"SPF include count: {spf_includes}" if spf_includes <=
                    10 else f"Too many SPF include lookups {spf_includes}.")
    else:
        output_warning("No SPF record found.")

    if dmarc_record:
        output_info(f"DMARC record: {dmarc_record}")
        output_info(
            f"Found DMARC policy: {p}" if p else "No DMARC policy found.")
        output_info(
            f"Found DMARC pct: {pct}" if pct else "No DMARC pct found.")
        output_info(
            f"Found DMARC aspf: {aspf}" if aspf else "No DMARC aspf found.")
        output_info(
            f"Found DMARC subdomain policy: {sp}" if sp else "No DMARC subdomain policy found.")
        output_indifferent(
            f"Forensics reports will be sent: {fo}" if fo else "No DMARC forensics report location found.")
        output_indifferent(
            f"Aggregate reports will be sent to: {rua}" if rua else "No DMARC aggregate report location found.")
    else:
        output_warning("No DMARC record found.")
    
    if(bimi_record):
        output_info(f"BIMI record : {bimi_record}")
        output_info(f"BIMI version : {vbimi}")
        output_info(f"BIMI location : {location}")
        output_info(f"BIMI authority : {authority}")
    
    if spoofable in [0, 1, 2, 3, 4, 5, 6, 7, 8]:
        if spoofable == 8:
            output_bad("Spoofing not possible for " + domain)
        else:
            output_good("Spoofing possible for " + domain 
                        if spoofable == 0 else "Subdomain spoofing possible for " + domain 
                        if spoofable == 1 else "Organizational domain spoofing possible for " + domain 
                        if spoofable == 2 else "Spoofing might be possible for " + domain 
                        if spoofable == 3 else "Spoofing might be possible (Mailbox dependant) for " + domain 
                        if spoofable == 4 else "Organizational domain spoofing may be possible for " + domain 
                        if spoofable == 5 else "Subdomain spoofing might be possible (Mailbox dependant) for " + domain 
                        if spoofable == 6 else "Subdomain spoofing might be possible (Mailbox dependant) for " + domain 
                        if spoofable == 7 else "")
    print()  # padding
