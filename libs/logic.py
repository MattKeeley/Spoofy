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
        if pct and int(pct) != 100: return 3
        elif spf_record is None:
            if p is None:  return 0
            else: return 8
        elif spf_includes > 10 and p is None:
            return 0
        elif spf_all == "2many": 
            if p == "none": return 3
            else: return 8
        elif spf_all and p is None: return 0
        elif spf_all == "-all":
            if p  and aspf and sp == "none": return 1
            elif aspf is None and sp == "none": return 1
            elif p == "none" and (aspf == "r" or aspf is None) and sp is None: return 4
            elif p == "none" and aspf == "r" and (sp == "reject" or sp == "quarentine"): return 2
            elif p == "none" and aspf is None and (sp == "reject" or sp == "quarentine"): return 5
            elif p == "none" and aspf is None and sp == "none": return 7
            else: return 8
        elif spf_all == "~all":
            if p == "none" and sp == "reject" or sp == "quarentine": return 2
            elif p == "none" and sp is None: return 0
            elif p == "none" and sp == "none": return 7
            elif (p == "reject" or p == "quarentine") and aspf is None and sp == "none": return 1
            elif (p == "reject" or p == "quarentine") and aspf and sp == "none": return 1
            else: return 8
        elif spf_all == "?all":
            if (p == "reject" or p == "quarentine") and aspf and sp == "none": return 6
            elif (p == "reject" or p == "quarentine") and aspf is None and sp == "none": return 6
            elif p == "none" and aspf == "r" and sp is None:  return 0
            elif p == "none" and aspf == "r" and sp == "none":  return 7
            elif p == "none" and aspf == "s" or None and sp == "none": return 7
            elif p == "none" and aspf == "s" or None and sp is None:  return 6
            elif p == "none" and aspf and (sp == "reject" or sp == "quarentine"):return 5
            elif p == "none" and aspf is None and sp  == "reject": return 5
            else: return 8
        else: return 8
    except:
        print("If you hit this error message, Open an issue with your testcase.")
