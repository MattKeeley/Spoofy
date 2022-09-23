#! /usr/bin/env python3

import os, argparse

from colorama import init as color_init

import emailprotectionslib.dmarc as dmarclib
import emailprotectionslib.spf as spflib
import logging

from libs.PrettyOutput import (
    output_good,
    output_bad,
    output_warning,
    output_info,
    output_error,
    output_indifferent,
)


logging.basicConfig(level=logging.INFO)


def get_spf_record(domain):
    spf_record = spflib.SpfRecord.from_domain(domain)
    if spf_record is not None and spf_record.record is not None:
        output_info("Found SPF record:")
        output_info(str(spf_record))
    else:
        output_good(domain + " has no SPF record!")
    return spf_record


def check_spf_multiple_alls(spf_record):
    print("SPF RECORD COUNT= " + str(spf_record).count("all"))
    if str(spf_record).count("all") > 1:
        return True
    else:
        return False


def check_spf_redirect_mechanisms(spf_record):
    redirect_domain = spf_record.get_redirect_domain()
    if redirect_domain is not None:
        output_info("Processing an SPF redirect domain: %s" % redirect_domain)

        return is_spf_record_strong(redirect_domain)

    else:
        return False


def is_spf_redirect_record_strong(spf_record):
    output_info(
        "Checking SPF redirect domian: %(domain)s"
        % {"domain": spf_record.get_redirect_domain}
    )
    redirect_strong = spf_record._is_redirect_mechanism_strong()
    if redirect_strong:
        output_bad("Redirect mechanism is strong.")
    else:
        output_indifferent("Redirect mechanism is not strong.")

    return redirect_strong


def are_spf_include_mechanisms_strong(spf_record):
    output_info("Checking SPF include mechanisms")
    include_strong = spf_record._are_include_mechanisms_strong()
    if include_strong:
        output_bad("Include mechanisms include a strong record")
    else:
        output_indifferent("Include mechanisms are not strong")

    return include_strong


def check_spf_include_redirect(spf_record):
    other_records_strong = False
    if spf_record.get_redirect_domain() is not None:
        other_records_strong = is_spf_redirect_record_strong(spf_record)

    if not other_records_strong:
        other_records_strong = are_spf_include_mechanisms_strong(spf_record)

    return other_records_strong


def check_spf_all_string(spf_record):
    if spf_record.all_string is not None:
        if str(spf_record).count("all") > 1:
            output_bad("SPF record contains multiple All items.")
            return "2many"
        elif spf_record.all_string == "~all":
            output_indifferent(
                "SPF record contains an All item: " + spf_record.all_string
            )
            return "~all"

        elif spf_record.all_string == "-all":
            output_indifferent(
                "SPF record contains an All item: " + spf_record.all_string
            )
            return "-all"
        else:
            output_good("SPF record has no All string")
            return None
    else:
        return None


def get_dmarc_record(domain):
    dmarc = dmarclib.DmarcRecord.from_domain(domain)
    if dmarc is not None and dmarc.record is not None:
        output_info("Found DMARC record:")
        output_info(str(dmarc.record))
    return dmarc


def get_dmarc_org_record(dmarc_record):
    org_record = dmarc_record.get_org_record()
    if org_record is not None:
        output_info("Found DMARC Organizational record:")
        output_info(str(org_record.record))
    return org_record


def get_dmarc_aspf(dmarc):
    if "aspf" in str(dmarc.record):
        aspf = str(dmarc.record).split("aspf")[1][1]
        return aspf
    else:
        return None


def check_dmarc_extras(dmarc_record):
    if dmarc_record.pct is not None and dmarc_record.pct != str(100):
        output_indifferent(
            "DMARC pct is set to " + dmarc_record.pct + "% - might be possible"
        )

    if dmarc_record.rua is not None:
        output_indifferent("Aggregate reports will be sent: " + dmarc_record.rua)

    if dmarc_record.ruf is not None:
        output_indifferent("Forensics reports will be sent: " + dmarc_record.ruf)


def check_dmarc_policy(dmarc_record):
    if dmarc_record.policy is not None:
        return dmarc_record.policy
    else:
        return "none"


def check_dmarc_org_policy(base_record):
    policy_strong = False

    try:
        org_record = base_record.get_org_record()
        if org_record is not None and org_record.record is not None:
            output_info("Found organizational DMARC record:")
            output_info(str(org_record.record))

            if org_record.subdomain_policy is not None:
                if org_record.subdomain_policy == "none":
                    output_good(
                        "Organizational subdomain policy set to %(sp)s"
                        % {"sp": org_record.subdomain_policy}
                    )
                elif (
                    org_record.subdomain_policy == "quarantine"
                    or org_record.subdomain_policy == "reject"
                ):
                    output_bad(
                        "Organizational subdomain policy explicitly set to %(sp)s"
                        % {"sp": org_record.subdomain_policy}
                    )
                    policy_strong = True
            else:
                output_info(
                    "No explicit organizational subdomain policy. Defaulting to organizational policy"
                )
                policy_strong = check_dmarc_policy(org_record)
        else:
            output_good("No organizational DMARC record")

    except dmarclib.OrgDomainException:
        output_good("No organizational DMARC record")

    except Exception as e:
        logging.exception(e)

    return policy_strong


def is_dmarc_record_strong(domain):
    dmarc_record_strong = False

    dmarc = get_dmarc_record(domain)

    if dmarc is not None and dmarc.record is not None:
        dmarc_record_strong = check_dmarc_policy(dmarc)

        check_dmarc_extras(dmarc)
    elif dmarc.get_org_domain() is not None:
        output_info("No DMARC record found. Looking for organizational record")
        dmarc_record_strong = check_dmarc_org_policy(dmarc)
    else:
        output_good(domain + " has no DMARC record!")

    return dmarc_record_strong


def is_spoofable(domain, dmarc, spf, aspf):
    try:
        if dmarc is None:
            output_good("Spoofing possible for " + domain)
        elif dmarc.policy == "none":
            if aspf is not None:
                if aspf == "r":
                    if spf == "?all":
                        output_good("Spoofing possible for " + domain)
                    else:
                        output_warning("Spoofing might be possible for " + domain)
                if aspf == "s":
                    if spf == "~all":
                        output_warning(
                            "Spoofing might be possible for " + domain
                        )
                    elif spf == "?all":
                        output_good("Spoofing possible for " + domain)
                    else:
                        output_bad("Spoofing is not possible for " + domain)
            else:
                if spf == "-all" or spf == "~all":
                    output_warning("Spoofing might be possible for " + domain)
                else:
                    output_good("Spoofing possible for " + domain)
        elif dmarc.policy == "reject" or dmarc.policy == "quarentine":
            if aspf is not None:
                if aspf == "r":
                    output_warning("Spoofing might be possible for " + domain)
                else:
                    if spf == "?all":
                        output_warning("Spoofing might be possible for " + domain)
                    else:
                        output_bad("Spoofing is not possible for " + domain)
            else:
                if spf == "-all" or "~all":
                    output_bad("Spoofing is not possible for " + domain)
                else:
                    output_warning("Spoofing might be possible for " + domain)

    except IndexError:
        output_error("Something broke. Debug:2")


def check_domain(domains):
    for domain in domains:
        try:
            print("Domain: " + domain)
            # DMARC
            dmarc = get_dmarc_record(domain)
            check_dmarc_org_policy(dmarc)
            check_dmarc_extras(dmarc)
            check_dmarc_policy(dmarc)
            aspf = get_dmarc_aspf(dmarc)
            # SPF
            spf = get_spf_record(domain)
            check_spf_redirect_mechanisms(spf)
            spf_all = check_spf_all_string(spf)
            check_spf_include_redirect(spf)
            # Spoofable
            is_spoofable(domain, dmarc, spf_all, aspf)

        except IndexError:
            output_error("Something broke. Debug:1")


if __name__ == "__main__":
    color_init()
    spoofable = False
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-iL", type=str, required=False, help="Provide an input list.")
    group.add_argument("-d", type=str, required=False, help="Provide an single domain.")
    options = parser.parse_args()
    if not any(vars(options).values()):
        parser.error(
            "No arguments provided. Usage: `spoofcheck.py -d [DOMAIN]` OR `spoofcheck.py -iL [DOMAIN_LIST]`"
        )
    domains = []
    if options.iL:
        try:
            with open(options.iL, "r") as f:
                for line in f:
                    domains.append(line)
        except IOError:
            print("File doesnt exist or cannot be read.")
    if options.d:
        domains.append(options.d)
    check_domain(domains)
