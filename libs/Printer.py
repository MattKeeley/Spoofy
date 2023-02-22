from libs.PrettyOutput import (
    output_good,
    output_bad,
    output_warning,
    output_info,
    output_error,
    output_indifferent
)

def printer(domain, dns_server, spf_record, spf_all, spf_includes,
            dmarc_record, subdomain, p, pct, aspf, sp, fo, rua, is_spoofable):
    
    output_indifferent(f"Domain: {domain}" )
    output_indifferent(f"Is subdomain: {subdomain}" )
    output_indifferent(f"DNS Server: {dns_server}")
    if spf_record:
            output_info(f"SPF record: {spf_record}")
            if spf_all is None: output_info("SPF does not contain an `All` items.")
            elif spf_all == "2many": output_warning("SPF record contains multiple `All` items.")
            else: output_info(f"SPF all record: {spf_all}")
            if spf_includes > 10: output_warning(f"Too many SPF include lookups {spf_includes}.")
            else: output_info(f"SPF include count: {spf_includes}")
    else: output_info("No SPF record found.")

    if dmarc_record:
        output_info(f"DMARC record: {dmarc_record}")
        if p: output_info(f"Found DMARC policy: {p}")
        else: output_info("No DMARC policy found.")
        if pct: output_info(f"Found DMARC pct: {pct}")
        else: output_info("No DMARC pct found.")
        if aspf: output_info(f"Found DMARC aspf: {aspf}")
        else: output_info("No DMARC aspf found.")
        if sp: output_info(f"Found DMARC subdomain policy: {sp}")
        else: output_info("No DMARC subdomain policy found.")
        if fo: output_indifferent(f"Forensics reports will be sent: {fo}")
        else: output_info("No DMARC foresnic report location found.")
        if rua: output_indifferent(f"Aggregate reports will be sent to: {rua}")
        else: output_info("No DMARC aggregate report location found.")

    # Can change this to 3.10 case if you wanna. Im not going to.
    if is_spoofable == 0: output_good("Spoofing possible for " + domain)
    elif is_spoofable == 1: output_good("Subdomain spoofing possible for " + domain)
    elif is_spoofable == 2: output_good("Organizational domain spoofing possible for " + domain)
    elif is_spoofable == 3: output_warning("Spoofing might be possible for " + domain)
    elif is_spoofable == 4: output_warning("Spoofing might be possible (Mailbox dependant) for " + domain)
    elif is_spoofable == 5: output_warning("Organizational domain spoofing may be possible for " + domain)
    elif is_spoofable == 6: output_warning("Subdomain spoofing might be possible (Mailbox dependant) for " + domain)
    elif is_spoofable == 7: output_bad("Spoofing not possible for " + domain)
    elif is_spoofable == 8: output_good("Subdomain spoofing possible for " + domain);output_good("Organizational domain spoofing possible for " + domain)
    elif is_spoofable == 9: output_good("Subdomain spoofing possible for " + domain);output_warning("Organizational domain spoofing may be possible for " + domain)
    else: output_error("Something went wrong.")

def error(msg):
    output_error(msg)
