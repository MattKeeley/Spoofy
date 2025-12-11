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

def assess_spf_security(spf_record, spf_all, spf_multiple_alls, spf_dns_query_count):
    """Assess SPF security posture and return appropriate level."""
    if not spf_record:
        return "bad"
    
    issues = 0
    
    # Handle multiple 'all' mechanisms (boolean flag)
    if spf_multiple_alls:
        issues += 3  # Multiple 'all' mechanisms is very bad
    
    # Handle SPF 'all' mechanism more comprehensively
    if spf_all is None:
        issues += 2  # Missing 'all' mechanism allows any server
    elif spf_all in ["+all", "all", "?all"]:
        issues += 3  # Very permissive, dangerous
    elif spf_all == "~all":
        issues += 1  # Soft fail - moderate risk
    elif spf_all == "-all":
        issues += 0  # Hard fail - good security
    else:
        issues += 2  # Unknown/unexpected 'all' mechanism
        
    # DNS query count assessment (RFC 7208 limit is 10)
    if spf_dns_query_count > 10:
        issues += 2  # Exceeds RFC limit
    elif spf_dns_query_count > 7:
        issues += 1  # Getting close to limit
        
    # Return security level based on issues
    if issues >= 4:
        return "bad"
    elif issues >= 2:
        return "warning"
    else:
        return "good"

def assess_dmarc_security(dmarc_record, policy, pct, aspf, sp):
    """Assess DMARC security posture and return appropriate level."""
    if not dmarc_record:
        return "bad"
    
    # Handle policy assessment
    if policy == "reject":
        base_level = "good"
    elif policy == "quarantine":
        base_level = "warning"
    elif policy == "none" or not policy:
        return "bad"  # No protection, allows spoofing
    else:
        return "bad"  # Unknown policy
        
    # Handle percentage - anything less than 100% is partial deployment
    if pct:
        try:
            pct_val = int(pct)
            if pct_val == 100:
                return base_level  # Full enforcement
            elif pct_val >= 50:
                return "warning"  # Partial enforcement
            else:
                return "bad"  # Minimal enforcement, mostly unprotected
        except (ValueError, TypeError):
            return "warning"  # Invalid percentage format
    else:
        # No pct specified defaults to 100%
        return base_level

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

def map_spoofing_to_level(spoofing_possible):
    """Map spoofing.py assessment to display level."""
    if spoofing_possible is True:
        return "bad"
    elif spoofing_possible is False:
        return "good"
    else:  # None (maybe spoofable)
        return "warning"

def get_spoofing_symbol(spoofing_possible):
    """Get appropriate symbol for spoofing assessment."""
    if spoofing_possible is True:
        return "[!]"
    elif spoofing_possible is False:
        return "[+]"
    else:  # None (maybe spoofable)
        return "[?]"


def printer(**kwargs):
    """Enhanced utility function using spoofing.py's authoritative assessment."""
    domain = kwargs.get("DOMAIN")
    subdomain = kwargs.get("DOMAIN_TYPE") == "subdomain"
    dns_server = kwargs.get("DNS_SERVER")
    spf_record = kwargs.get("SPF")
    spf_all = kwargs.get("SPF_ALL_MECHANISM")
    spf_multiple_alls = kwargs.get("SPF_MULTIPLE_ALLS", False)
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
    dnssec_enabled = kwargs.get("DNSSEC_ENABLED")
    
    # Use spoofing.py's authoritative assessment
    spoofing_possible = kwargs.get("SPOOFING_POSSIBLE")
    spoofing_type = kwargs.get("SPOOFING_TYPE")

    # Assess security levels for intelligent formatting
    spf_level = assess_spf_security(spf_record, spf_all, spf_multiple_alls, spf_dns_query_count)
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
        
        # Check for multiple 'all' mechanisms first
        if spf_multiple_alls:
            output_message("[!]", "Multiple 'all' mechanisms detected - configuration error", "bad")
        
        # Enhanced SPF 'all' mechanism assessment
        if spf_all is None:
            output_message("[!]", "SPF missing 'all' mechanism - allows ANY server to send mail", "bad")
        elif spf_all in ["+all", "all"]:
            output_message("[!]", f"SPF all mechanism: {spf_all} - DANGEROUS: allows ANY server", "bad")
        elif spf_all == "?all":
            output_message("[!]", f"SPF all mechanism: {spf_all} - neutral policy, no protection", "bad")
        elif spf_all == "-all":
            output_message("[+]", f"SPF all mechanism: {spf_all} (strict - rejects unauthorized)", "good")
        elif spf_all == "~all":
            output_message("[?]", f"SPF all mechanism: {spf_all} (soft fail - accepts but marks)", "warning")
        else:
            output_message("[!]", f"SPF all mechanism: {spf_all} (unknown/unexpected)", "bad")
            
        # Enhanced DNS query count assessment
        if spf_dns_query_count <= 5:
            output_message("[+]", f"SPF DNS queries: {spf_dns_query_count} (efficient)", "good")
        elif spf_dns_query_count <= 10:
            output_message("[?]", f"SPF DNS queries: {spf_dns_query_count} (acceptable, RFC limit is 10)", "warning")
        else:
            output_message("[!]", f"SPF DNS queries: {spf_dns_query_count} (EXCEEDS RFC 7208 limit of 10)", "bad")
    else:
        output_message("[!]", "No SPF record found - allows spoofing from any server", "bad")

    # DMARC ANALYSIS SECTION  
    print_section_header("DMARC ANALYSIS")
    if dmarc_record:
        output_message("[*]", f"DMARC record: {dmarc_record}", "info")
        
        # Enhanced policy assessment with clear security implications
        if p == "reject":
            policy_level = "good"
            policy_symbol = "[+]"
            policy_msg = f"DMARC policy: {p} (blocks unauthorized email)"
        elif p == "quarantine":
            policy_level = "warning"
            policy_symbol = "[?]"
            policy_msg = f"DMARC policy: {p} (quarantines unauthorized email)"
        elif p == "none" or not p:
            policy_level = "bad"
            policy_symbol = "[!]"
            policy_msg = f"DMARC policy: {p or 'none'} - ALLOWS SPOOFING (no enforcement)"
        else:
            policy_level = "bad"
            policy_symbol = "[!]"
            policy_msg = f"DMARC policy: {p} (unknown policy)"
        output_message(policy_symbol, policy_msg, policy_level)
        
        # Enhanced percentage assessment
        if pct:
            try:
                pct_val = int(pct)
                if pct_val == 100:
                    output_message("[+]", f"DMARC percentage: {pct}% (full enforcement)", "good")
                elif pct_val >= 50:
                    output_message("[?]", f"DMARC percentage: {pct}% (partial deployment - {100-pct_val}% unprotected)", "warning")  
                else:
                    output_message("[!]", f"DMARC percentage: {pct}% (testing phase - {100-pct_val}% unprotected)", "bad")
            except (ValueError, TypeError):
                output_message("[?]", f"DMARC percentage: {pct} (invalid format)", "warning")
        else:
            output_message("[*]", "DMARC percentage: 100% (default full enforcement)", "indifferent")
            
        # Other DMARC fields with security context
        if aspf:
            aspf_level = "good" if aspf == "s" else "warning"
            aspf_msg = f"DMARC ASPF alignment: {aspf} ({'strict' if aspf == 's' else 'relaxed'})"
            output_message("[*]", aspf_msg, aspf_level)
            
        if sp:
            output_message("[*]", f"DMARC subdomain policy: {sp}", "info")
            
        if fo:
            output_message("[*]", f"Forensic reporting: {fo}", "indifferent")
        if rua:
            output_message("[*]", f"Aggregate reporting: {rua}", "indifferent")
    else:
        output_message("[!]", "No DMARC record found - ALLOWS EMAIL SPOOFING", "bad")

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

    # SPOOFABILITY ASSESSMENT SECTION - Uses spoofing.py's authoritative assessment
    print_section_header("SPOOFABILITY ASSESSMENT")
    
    if spoofing_type:
        # Use spoofing.py's comprehensive assessment
        spoofing_level = map_spoofing_to_level(spoofing_possible)
        spoofing_symbol = get_spoofing_symbol(spoofing_possible)
        output_message(spoofing_symbol, spoofing_type, spoofing_level)
    else:
        # Fallback if no spoofing assessment available
        output_message("[?]", "No spoofing assessment available", "warning")
        
    # Overall security assessment
    if overall_level == "good":
        output_message("[+]", "Overall security posture: STRONG", "good")
    elif overall_level == "warning":
        output_message("[?]", "Overall security posture: MODERATE", "warning")
    else:
        output_message("[!]", "Overall security posture: WEAK", "bad")

    print(f"\n{'─' * 60}\n")  # Final separator