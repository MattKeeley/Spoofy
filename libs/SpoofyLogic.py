def is_spoofable(domain, p, aspf, spf_record, spf_all, spf_includes, sp, pct):
    try:
        if pct and int(pct) != 100: return 3
        elif spf_record is None:
            if p is None:  return 0
            else: return 7
        elif spf_includes > 10 and p is None:
            return 0
        elif spf_all == "2many": 
            if p == "none": return 3
            else: return 7
        elif spf_all and p is None: return 0
        elif spf_all == "-all":
            if p  and aspf and sp == "none": return 1
            elif aspf is None and sp == "none": return 1
            elif p == "none" and (aspf == "r" or aspf is None) and sp is None: return 4
            elif p == "none" and aspf == "r" and (sp == "reject" or sp == "quarentine"): return 2
            elif p == "none" and aspf is None and (sp == "reject" or sp == "quarentine"): return 5
            elif p == "none" and aspf is None and sp == "none": return 8
            else: return 7
        elif spf_all == "~all":
            if p == "none" and sp == "reject" or sp == "quarentine": return 2
            elif p == "none" and sp is None: return 0
            elif p == "none" and sp == "none": return 8
            elif (p == "reject" or p == "quarentine") and aspf is None and sp == "none": return 1
            elif (p == "reject" or p == "quarentine") and aspf and sp == "none": return 1
            else: return 7
        elif spf_all == "?all":
            if (p == "reject" or p == "quarentine") and aspf and sp == "none": return 6
            elif (p == "reject" or p == "quarentine") and aspf is None and sp == "none": return 6
            elif p == "none" and aspf == "r" and sp is None:  return 0
            elif p == "none" and aspf == "r" and sp == "none":  return 8
            elif p == "none" and aspf == "s" or None and sp == "none": return 8
            elif p == "none" and aspf == "s" or None and sp is None:  return 6
            elif p == "none" and aspf and (sp == "reject" or sp == "quarentine"):return 5
            elif p == "none" and aspf is None and sp  == "reject": return 5
            else: return 7
        else: return 7
    except:
        print("If you hit this error message, Open an issue with your testcase.")


