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


def write_to_excel(data, file_name="output.xlsx"):
    """Writes a DataFrame of data to an Excel file, appending if the file exists."""
    if os.path.exists(file_name) and os.path.getsize(file_name) > 0:
        existing_df = pd.read_excel(file_name)
        new_df = pd.DataFrame(data)
        combined_df = pd.concat([existing_df, new_df])
        combined_df.to_excel(file_name, index=False)
    else:
        pd.DataFrame(data).to_excel(file_name, index=False)

def output_json(results):
    output = []
    for result in results:
        output.append(result)
    print(json.dumps(output))


def print_section_header(title):
    """Print a visually distinct section header."""
    print(f"\n{title}")

def assess_spf_security(spf_record, spf_all, spf_dns_query_count):
    """Assess SPF security posture and return appropriate level."""
    if not spf_record:
        return "bad"
    
    issues = 0
    if spf_all is None:
        issues += 1
    elif spf_all == "2many":
        issues += 2
    elif spf_all not in ["-all", "~all"]:
        issues += 1
        
    if spf_dns_query_count > 10:
        issues += 2
    elif spf_dns_query_count > 7:
        issues += 1
        
    if issues >= 3:
        return "bad"
    elif issues >= 1:
        return "warning"
    else:
        return "good"

def assess_dmarc_security(dmarc_record, policy, pct, aspf, sp):
    """Assess DMARC security posture and return appropriate level."""
    if not dmarc_record:
        return "bad"
        
    if policy in ["reject", "quarantine"]:
        if pct:
            try:
                pct_val = int(pct)
                if pct_val >= 100:
                    return "good" if policy == "reject" else "warning"
                else:
                    return "warning"
            except (ValueError, TypeError):
                return "warning"
        else:
            return "good" if policy == "reject" else "warning"
    else:
        return "bad"

def assess_overall_security(spf_level, dmarc_level, dnssec_enabled):
    """Assess overall domain security posture."""
    levels = {"good": 3, "warning": 2, "bad": 1}
    
    score = levels.get(spf_level, 1) + levels.get(dmarc_level, 1)
    if dnssec_enabled:
        score += 1
        
    if score >= 7:
        return "good"
    elif score >= 5:
        return "warning" 
    else:
        return "bad"


def printer(**kwargs):
    """Enhanced utility function with improved readability and flexible conditional logic."""
    domain = kwargs.get("DOMAIN")
    subdomain = kwargs.get("DOMAIN_TYPE") == "subdomain"
    dns_server = kwargs.get("DNS_SERVER")
    spf_record = kwargs.get("SPF")
    spf_all = kwargs.get("SPF_MULTIPLE_ALLS")
    spf_dns_query_count = kwargs.get("SPF_NUM_DNS_QUERIES")
    spf_too_many_dns_queries = kwargs.get("SPF_TOO_MANY_DNS_QUERIES")
    dmarc_record = kwargs.get("DMARC")
    p = kwargs.get("DMARC_POLICY")
    pct = kwargs.get("DMARC_PCT")
    aspf = kwargs.get("DMARC_ASPF")
    sp = kwargs.get("DMARC_SP")
    fo = kwargs.get("DMARC_FORENSIC_REPORT")
    rua = kwargs.get("DMARC_AGGREGATE_REPORT")
    dkim_record = kwargs.get("DKIM")
    mx_records = kwargs.get("MX_RECORDS")
    mx_provider = kwargs.get("MX_PROVIDER")
    is_microsoft = kwargs.get("IS_MICROSOFT")
    bimi_record = kwargs.get("BIMI_RECORD")
    vbimi = kwargs.get("BIMI_VERSION")
    location = kwargs.get("BIMI_LOCATION")
    tenant_domains = kwargs.get("TENANT_DOMAINS")
    authority = kwargs.get("BIMI_AUTHORITY")
    spoofable = kwargs.get("SPOOFING_POSSIBLE")
    spoofing_type = kwargs.get("SPOOFING_TYPE")
    dnssec_enabled = kwargs.get("DNSSEC_ENABLED")

    # Assess security levels for intelligent formatting
    spf_level = assess_spf_security(spf_record, spf_all, spf_dns_query_count)
    dmarc_level = assess_dmarc_security(dmarc_record, p, pct, aspf, sp)
    overall_level = assess_overall_security(spf_level, dmarc_level, dnssec_enabled)

    # DOMAIN INFORMATION SECTION
    print_section_header("DOMAIN INFORMATION")
    output_message("[*]", f"Domain: {domain}", "indifferent")
    output_message("[*]", f"Subdomain: {'Yes' if subdomain else 'No'}", "indifferent")
    output_message("[*]", f"DNS Server: {dns_server}", "indifferent")

    # CLOUD PROVIDER SECTION  
    if is_microsoft or tenant_domains:
        print_section_header("CLOUD PROVIDER DETECTION")
        if is_microsoft:
            output_message("[*]", "Microsoft 365 customer detected", "info")
        if tenant_domains:
            output_message("[*]", f"Tenant domains: {', '.join(tenant_domains)}", "info")

    # EMAIL INFRASTRUCTURE SECTION
    print_section_header("EMAIL INFRASTRUCTURE")
    if mx_records:
        mx_list = ", ".join(mx_records)
        output_message("[*]", f"MX records: {mx_list}", "info")
        
        # Intelligent provider assessment
        provider_level = "good" if mx_provider in ["Microsoft Exchange Online", "Google Workspace"] else "indifferent"
        output_message("[*]", f"Email provider: {mx_provider}", provider_level)
    else:
        output_message("[!]", "No MX records found", "bad")

    # SPF ANALYSIS SECTION
    print_section_header("SPF ANALYSIS")
    if spf_record:
        output_message("[*]", f"SPF record: {spf_record}", "info")
        
        # Intelligent SPF all mechanism assessment
        if spf_all is None:
            output_message("[!]", "SPF missing 'all' mechanism - allows any server", "bad")
        elif spf_all == "2many":
            output_message("[!]", "Multiple 'all' mechanisms detected", "bad")
        elif spf_all == "-all":
            output_message("[+]", f"SPF all mechanism: {spf_all} (strict)", "good")
        elif spf_all == "~all":
            output_message("[?]", f"SPF all mechanism: {spf_all} (soft fail)", "warning")
        else:
            output_message("[!]", f"SPF all mechanism: {spf_all} (permissive)", "bad")
            
        # Intelligent DNS query count assessment
        if spf_dns_query_count <= 5:
            output_message("[+]", f"SPF DNS queries: {spf_dns_query_count} (efficient)", "good")
        elif spf_dns_query_count <= 10:
            output_message("[?]", f"SPF DNS queries: {spf_dns_query_count} (acceptable)", "warning")
        else:
            output_message("[!]", f"SPF DNS queries: {spf_dns_query_count} (exceeds RFC limit)", "bad")
    else:
        output_message("[!]", "No SPF record found", "bad")

    # DMARC ANALYSIS SECTION  
    print_section_header("DMARC ANALYSIS")
    if dmarc_record:
        output_message("[*]", f"DMARC record: {dmarc_record}", "info")
        
        # Intelligent policy assessment
        if p == "reject":
            policy_level = "good"
            policy_symbol = "[+]"
        elif p == "quarantine":
            policy_level = "warning"
            policy_symbol = "[?]"
        else:
            policy_level = "bad"
            policy_symbol = "[!]"
        output_message(policy_symbol, f"DMARC policy: {p or 'none'}", policy_level)
        
        # Intelligent percentage assessment
        if pct:
            try:
                pct_val = int(pct)
                if pct_val == 100:
                    output_message("[+]", f"DMARC percentage: {pct}% (full enforcement)", "good")
                elif pct_val >= 50:
                    output_message("[?]", f"DMARC percentage: {pct}% (partial enforcement)", "warning")  
                else:
                    output_message("[!]", f"DMARC percentage: {pct}% (minimal enforcement)", "bad")
            except (ValueError, TypeError):
                output_message("[?]", f"DMARC percentage: {pct} (invalid format)", "warning")
        else:
            output_message("[*]", "DMARC percentage: 100% (default)", "indifferent")
            
        # Other DMARC fields with intelligent assessment
        if aspf:
            aspf_level = "good" if aspf == "s" else "warning"
            output_message("[*]", f"DMARC ASPF alignment: {aspf}", aspf_level)
            
        if sp:
            output_message("[*]", f"DMARC subdomain policy: {sp}", "info")
            
        if fo:
            output_message("[*]", f"Forensic reporting: {fo}", "indifferent")
        if rua:
            output_message("[*]", f"Aggregate reporting: {rua}", "indifferent")
    else:
        output_message("[!]", "No DMARC record found", "bad")

    # ADDITIONAL SECURITY SECTION
    print_section_header("ADDITIONAL SECURITY")
    
    # DNSSEC
    if dnssec_enabled:
        output_message("[+]", "DNSSEC: Enabled", "good")
    else:
        output_message("[?]", "DNSSEC: Not detected", "warning")
    
    # DKIM
    if dkim_record:
        output_message("[+]", f"DKIM selectors found:\n{dkim_record}", "good")
    else:
        output_message("[?]", "No DKIM selectors enumerated", "warning")
        
    # BIMI
    if bimi_record:
        output_message("[*]", f"BIMI record: {bimi_record}", "info")
        output_message("[*]", f"BIMI version: {vbimi}", "info")
        output_message("[*]", f"BIMI location: {location}", "info")
        output_message("[*]", f"BIMI authority: {authority}", "info")

    # SPOOFABILITY ASSESSMENT SECTION
    if spoofing_type:
        print_section_header("SPOOFABILITY ASSESSMENT")
        level = "good" if not spoofable else "bad"
        symbol = "[+]" if level == "good" else "[!]"
        output_message(symbol, spoofing_type, level)
        
        # Overall security assessment
        if overall_level == "good":
            output_message("[+]", "Overall security posture: STRONG", "good")
        elif overall_level == "warning":
            output_message("[?]", "Overall security posture: MODERATE", "warning")
        else:
            output_message("[!]", "Overall security posture: WEAK", "bad")

    print(f"\n{'═' * 60}\n")  # Final separator