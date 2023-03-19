def is_spoofable(domain, p, aspf, spf_record, spf_all, spf_includes, sp, pct):
    """This function takes in DMARC and SPF data for a domain, as well as subdomain policy and percentage options,
      and determines if the domain is vulnerable to email spoofing. The function returns an integer value indicating
      the class of vulnerability. A table of what each number means can be found in the /templates/report.py file."""
    try:
        if pct and int(pct) != 100:
            return 3
        elif not spf_record:
            return 7 if p else 0
        elif spf_includes > 10 and not p:
            return 0
        elif spf_all == "2many":
            return 3 if p == "none" else 7
        elif spf_all and not p:
            return 0
        elif spf_all == "-all":
            if p == "none":
                if aspf == "r" and sp in ["reject", "quarentine"]:
                    return 2
                elif aspf is None and sp == "none":
                    return 8
                elif aspf == "r" and sp == "none":
                    return 4
                else:
                    return 1
            elif p == "none" and sp is None:
                return 4 if aspf == "r" else 8
            else:
                return 7
        elif spf_all == "~all":
            if p == "none":
                if sp in ["reject", "quarentine"]:
                    return 2
                elif sp is None:
                    return 8
                else:
                    return 1
            elif p in ["reject", "quarentine"] and not aspf and sp == "none":
                return 1
            else:
                return 7
        elif spf_all == "?all":
            if p in ["reject", "quarentine"]:
                if aspf and not sp:
                    return 6
                elif not aspf and not sp:
                    return 6
                elif aspf == "r" and sp == "none":
                    return 0
                elif aspf == "s" or None and sp == "none":
                    return 8
                elif aspf == "s" or None and not sp:
                    return 6
                elif aspf and sp in ["reject", "quarentine"]:
                    return 5
                elif not aspf and sp == "reject":
                    return 5
            elif p == "none":
                if aspf == "r" and not sp:
                    return 0
                elif aspf == "r" and sp == "none":
                    return 8
                elif aspf == "s" or None and sp == "none":
                    return 8
                elif aspf == "s" or None and not sp:
                    return 6
                elif aspf and sp in ["reject", "quarentine"]:
                    return 5
                elif not aspf and sp == "reject":
                    return 5
            return 7
        else:
            return 7
    except:
        print("If you hit this error message, Open an issue with your testcase.")