def is_spoofable(domain, p, aspf, spf_record, spf_all, spf_includes, sp, pct):
    """This function takes in DMARC and SPF data for a domain, as well as subdomain policy and percentage options,
    and determines if the domain is vulnerable to email spoofing. The function returns an integer value indicating
    the class of vulnerability. 
    ID Handler:
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
    try:
        if pct and int(pct) != 100:
            return 3
        elif spf_record is None:
            return 0 if p is None else 8
        elif spf_includes > 10 and p is None:
            return 0
        elif spf_all == "2many":
            return 3 if p == "none" else 8
        elif spf_all and p is None:
            return 0
        elif spf_all == "-all":
            if p == "none":
                if aspf == "r" and (sp == "reject" or sp == "quarantine"):
                    return 2
                elif aspf is None and (sp == "reject" or sp == "quarantine"):
                    return 5
                elif aspf is None and sp == "none":
                    return 7
                elif (aspf == "r" or aspf is None) and sp is None:
                    return 4
                else:
                    return 8
            elif p and aspf and sp == "none":
                return 1
            elif aspf is None and sp == "none":
                return 1
            else:
                return 8
        elif spf_all == "~all":
            if p == "none":
                if sp == "reject" or sp == "quarantine":
                    return 2
                elif sp is None:
                    return 0
                elif sp == "none":
                    return 7
                else:
                    return 8
            elif (p == "reject" or p == "quarantine") and (aspf is None or aspf) and sp == "none":
                return 1
            else:
                return 8
        elif spf_all == "?all":
            if p == "none":
                if (aspf == "r" or aspf is None) and sp is None:
                    return 6
                elif aspf == "r" and sp == "none":
                    return 7
                elif (aspf == "s" or aspf is None) and sp == "none":
                    return 7
                elif aspf and (sp == "reject" or sp == "quarantine"):
                    return 5
                elif aspf is None and sp == "reject":
                    return 5
                else:
                    return 8
            elif (p == "reject" or p == "quarantine") and (aspf is None or aspf) and sp == "none":
                return 6
            else:
                return 8
        else:
            return 8
    except Exception as e:
        print("An error occurred: ", e)
        print("Open an issue with your testcase.")