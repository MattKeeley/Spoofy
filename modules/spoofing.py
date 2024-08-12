# modules/spoofing.py

import tldextract


class Spoofing:
    def __init__(self, domain, p, aspf, spf_record, spf_all, spf_dns_queries, sp, pct):
        self.domain = domain
        self.p = p
        self.aspf = aspf
        self.spf_record = spf_record
        self.spf_all = spf_all
        self.spf_dns_queries = spf_dns_queries
        self.sp = sp
        self.pct = pct
        self.domain_type = self.get_domain_type()
        self.spoofable = self.is_spoofable()
        self.spoofing_possible, self.spoofing_type = self.evaluate_spoofing()

    def get_domain_type(self):
        """Determines whether the domain is a domain or subdomain."""
        subdomain = bool(tldextract.extract(self.domain).subdomain)
        return "subdomain" if subdomain else "domain"

    def is_spoofable(self):
        """Determines the spoofability based on DMARC and SPF data."""
        try:
            if self.pct and int(self.pct) != 100:
                return 3
            elif self.spf_record is None:
                if self.p is None:
                    return 0
                elif self.p == "none":
                    return 4
                else:
                    return 8
            elif self.spf_dns_queries > 10 and self.p is None:
                return 0
            elif self.spf_all == "2many":
                if self.p == "none":
                    return 3
                else:
                    return 8
            elif self.spf_all and self.p is None:
                return 0
            elif self.spf_all == "-all":
                if self.p and self.aspf and self.sp == "none":
                    return 1
                elif self.aspf is None and self.sp == "none":
                    return 1
                elif (
                    self.p == "none"
                    and (self.aspf == "r" or self.aspf is None)
                    and self.sp is None
                ):
                    return 4
                elif (
                    self.p == "none"
                    and self.aspf == "r"
                    and (self.sp == "reject" or self.sp == "quarantine")
                ):
                    return 2
                elif (
                    self.p == "none"
                    and self.aspf is None
                    and (self.sp == "reject" or self.sp == "quarantine")
                ):
                    return 5
                elif self.p == "none" and self.aspf is None and self.sp == "none":
                    return 7
                else:
                    return 8
            elif self.spf_all == "~all":
                if self.p == "none" and self.sp == "reject" or self.sp == "quarantine":
                    return 2
                elif self.p == "none" and self.sp is None:
                    return 0
                elif self.p == "none" and self.sp == "none":
                    return 7
                elif (
                    (self.p == "reject" or self.p == "quarantine")
                    and self.aspf is None
                    and self.sp == "none"
                ):
                    return 1
                elif (
                    (self.p == "reject" or self.p == "quarantine")
                    and self.aspf
                    and self.sp == "none"
                ):
                    return 1
                else:
                    return 8
            elif self.spf_all == "?all":
                if (
                    (self.p == "reject" or self.p == "quarantine")
                    and self.aspf
                    and self.sp == "none"
                ):
                    return 6
                elif (
                    (self.p == "reject" or self.p == "quarantine")
                    and self.aspf is None
                    and self.sp == "none"
                ):
                    return 6
                elif self.p == "none" and self.aspf == "r" and self.sp is None:
                    return 0
                elif self.p == "none" and self.aspf == "r" and self.sp == "none":
                    return 7
                elif (
                    self.p == "none" and self.aspf == "s" or None and self.sp == "none"
                ):
                    return 7
                elif self.p == "none" and self.aspf == "s" or None and self.sp is None:
                    return 6
                elif (
                    self.p == "none"
                    and self.aspf
                    and (self.sp == "reject" or self.sp == "quarantine")
                ):
                    return 5
                elif self.p == "none" and self.aspf is None and self.sp == "reject":
                    return 5
                else:
                    return 8
            else:
                return 8
        except Exception:
            print("If you hit this error message, Open an issue with your testcase.")
            return 8

    def evaluate_spoofing(self):
        """Evaluates and returns whether spoofing is possible and the type of spoofing."""
        spoofing_types = {
            0: f"Spoofing possible for {self.domain}.",
            1: f"Subdomain spoofing possible for {self.domain}.",
            2: f"Organizational domain spoofing possible for {self.domain}.",
            3: f"Spoofing might be possible for {self.domain}.",
            4: f"Spoofing might be possible (Mailbox dependent) for {self.domain}.",
            5: f"Organizational domain spoofing might be possible for {self.domain}.",
            6: f"Subdomain spoofing might be possible (Mailbox dependent) for {self.domain}.",
            7: f"Subdomain spoofing is possible and organizational domain spoofing might be possible for {self.domain}.",
            8: f"Spoofing is not possible for {self.domain}.",
        }

        spoofing_type = spoofing_types.get(
            self.spoofable, f"Unknown spoofing type for {self.domain}."
        )

        if self.spoofable in {0, 1, 3, 7}:
            spoofing_possible = True
        elif self.spoofable == 8:
            spoofing_possible = False
        else:
            spoofing_possible = None  # "maybe"

        return spoofing_possible, spoofing_type

    def __str__(self):
        return (
            f"Domain: {self.domain}\n"
            f"Domain Type: {self.domain_type}\n"
            f"Spoofing Possible: {self.spoofing_possible}\n"
            f"Spoofing Type: {self.spoofing_type}"
        )
