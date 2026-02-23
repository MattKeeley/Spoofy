# modules/spoofing.py

import tldextract
from functools import lru_cache
from .syntax import validate_record_syntax

# Generated lookup table from Master_Table.xlsx - 198 empirically tested configurations
SPOOFABILITY_LOOKUP = {
    ('-all', 'No DMARC'): 0,
    ('-all', 'p=quarantine, sp=none'): 1,
    ('-all', 'p=reject, sp=none'): 1,
    ('-all', 'p=none, sp=none, aspf=r'): 1,
    ('-all', 'p=none, sp=none, aspf=s'): 1,
    ('-all', 'p=quarantine, sp=none, aspf=r'): 1,
    ('-all', 'p=reject, sp=none, aspf=r'): 1,
    ('-all', 'p=none, sp=quarantine, aspf=r'): 2,
    ('-all', 'p=none, sp=reject, aspf=r'): 2,
    ('all-', 'p=none'): 4,
    ('all-', 'p=none, aspf=r'): 4,
    ('all-', 'p=none, aspf=s'): 4,
    ('all-', 'p=none, sp=quarantine'): 5,
    ('all-', 'p=none, sp=reject'): 5,
    ('all-', 'p=none, sp=none'): 7,
    ('all-', 'p=quarantine'): 8,
    ('all-', 'p=reject'): 8,
    ('all-', 'p=quarantine, sp=quarantine'): 8,
    ('all-', 'p=quarantine, sp=reject'): 8,
    ('all-', 'p=reject, sp=quarantine'): 8,
    ('all-', 'p=reject, sp=reject'): 8,
    ('all-', 'p=none, sp=quarantine, aspf=s'): 8,
    ('all-', 'p=none, sp=reject, aspf=s'): 8,
    ('all-', 'p=quarantine, sp=none, aspf=s'): 8,
    ('all-', 'p=quarantine, sp=quarantine, aspf=r'): 8,
    ('all-', 'p=quarantine, sp=quarantine, aspf=s'): 8,
    ('all-', 'p=quarantine, sp=reject, aspf=r'): 8,
    ('all-', 'p=quarantine, sp=reject, aspf=s'): 8,
    ('all-', 'p=reject, sp=none, aspf=s'): 8,
    ('all-', 'p=reject, sp=quarantine, aspf=r'): 8,
    ('all-', 'p=reject, sp=quarantine, aspf=s'): 8,
    ('all-', 'p=reject, sp=reject, aspf=r'): 8,
    ('all-', 'p=reject, sp=reject, aspf=s'): 8,
    ('all?', 'p=none, aspf=r'): 0,
    ('all?', 'p=none, sp=none, aspf=r'): 0,
    ('all?', 'No DMARC'): 0,
    ('all?', 'p=quarantine, sp=none, aspf=r'): 1,
    ('all?', 'p=quarantine, sp=none, aspf=s'): 1,
    ('all?', 'p=reject, sp=none, aspf=r'): 1,
    ('all?', 'p=reject, sp=none, aspf=s'): 1,
    ('all?', 'p=none'): 4,
    ('all?', 'p=none, sp=none'): 4,
    ('all?', 'p=none, aspf=s'): 4,
    ('all?', 'p=none, sp=none, aspf=s'): 4,
    ('all?', 'p=none, sp=quarantine'): 5,
    ('all?', 'p=none, sp=reject'): 5,
    ('all?', 'p=none, sp=quarantine, aspf=r'): 5,
    ('all?', 'p=none, sp=quarantine, aspf=s'): 5,
    ('all?', 'p=none, sp=reject, aspf=r'): 5,
    ('all?', 'p=none, sp=reject, aspf=s'): 5,
    ('all?', 'p=quarantine, sp=none'): 6,
    ('all?', 'p=reject, sp=none'): 6,
    ('all?', 'p=quarantine'): 8,
    ('all?', 'p=reject'): 8,
    ('all?', 'p=quarantine, sp=quarantine'): 8,
    ('all?', 'p=quarantine, sp=reject'): 8,
    ('all?', 'p=reject, sp=quarantine'): 8,
    ('all?', 'p=reject, sp=reject'): 8,
    ('all?', 'p=quarantine, sp=quarantine, aspf=r'): 8,
    ('all?', 'p=quarantine, sp=quarantine, aspf=s'): 8,
    ('all?', 'p=quarantine, sp=reject, aspf=r'): 8,
    ('all?', 'p=quarantine, sp=reject, aspf=s'): 8,
    ('all?', 'p=reject, sp=quarantine, aspf=r'): 8,
    ('all?', 'p=reject, sp=quarantine, aspf=s'): 8,
    ('all?', 'p=reject, sp=reject, aspf=r'): 8,
    ('all?', 'p=reject, sp=reject, aspf=s'): 8,
    ('all+', 'p=none'): 4,
    ('all+', 'p=quarantine'): 4,
    ('all+', 'p=reject'): 4,
    ('all+', 'p=none, sp=none'): 4,
    ('all+', 'p=none, sp=quarantine'): 4,
    ('all+', 'p=none, sp=reject'): 4,
    ('all+', 'p=none, aspf=r'): 4,
    ('all+', 'p=none, aspf=s'): 4,
    ('all+', 'p=quarantine, sp=none'): 4,
    ('all+', 'p=quarantine, sp=quarantine'): 4,
    ('all+', 'p=quarantine, sp=reject'): 4,
    ('all+', 'p=reject, sp=none'): 4,
    ('all+', 'p=reject, sp=quarantine'): 4,
    ('all+', 'p=reject, sp=reject'): 4,
    ('all+', 'p=none, sp=none, aspf=r'): 4,
    ('all+', 'p=none, sp=none, aspf=s'): 4,
    ('all+', 'p=none, sp=quarantine, aspf=r'): 4,
    ('all+', 'p=none, sp=quarantine, aspf=s'): 4,
    ('all+', 'p=none, sp=reject, aspf=r'): 4,
    ('all+', 'p=none, sp=reject, aspf=s'): 4,
    ('all+', 'p=quarantine, sp=none, aspf=r'): 4,
    ('all+', 'p=quarantine, sp=none, aspf=s'): 4,
    ('all+', 'p=quarantine, sp=quarantine, aspf=r'): 4,
    ('all+', 'p=quarantine, sp=quarantine, aspf=s'): 4,
    ('all+', 'p=quarantine, sp=reject, aspf=r'): 4,
    ('all+', 'p=quarantine, sp=reject, aspf=s'): 4,
    ('all+', 'p=reject, sp=none, aspf=r'): 4,
    ('all+', 'p=reject, sp=none, aspf=s'): 4,
    ('all+', 'p=reject, sp=quarantine, aspf=r'): 4,
    ('all+', 'p=reject, sp=quarantine, aspf=s'): 4,
    ('all+', 'p=reject, sp=reject, aspf=r'): 4,
    ('all+', 'p=reject, sp=reject, aspf=s'): 4,
    ('all+', 'No DMARC'): 4,
    ('all~', 'p=none, sp=none'): 0,
    ('all~', 'No DMARC'): 0,
    ('all~', 'p=quarantine, sp=none'): 1,
    ('all~', 'p=reject, sp=none'): 1,
    ('all~', 'p=none, sp=quarantine'): 2,
    ('all~', 'p=none, sp=reject'): 2,
    ('all~', 'p=none, aspf=r'): 2,
    ('all~', 'p=none, aspf=s'): 2,
    ('all~', 'p=none, sp=quarantine, aspf=r'): 2,
    ('all~', 'p=none, sp=quarantine, aspf=s'): 2,
    ('all~', 'p=none, sp=reject, aspf=r'): 2,
    ('all~', 'p=none, sp=reject, aspf=s'): 2,
    ('all~', 'p=none, sp=none, aspf=r'): 7,
    ('all~', 'p=none, sp=none, aspf=s'): 7,
    ('all~', 'p=none'): 0,
    ('all~', 'p=quarantine'): 8,
    ('all~', 'p=reject'): 8,
    ('all~', 'p=quarantine, sp=quarantine'): 8,
    ('all~', 'p=quarantine, sp=reject'): 8,
    ('all~', 'p=reject, sp=quarantine'): 8,
    ('all~', 'p=reject, sp=reject'): 8,
    ('all~', 'p=quarantine, sp=none, aspf=r'): 8,
    ('all~', 'p=quarantine, sp=none, aspf=s'): 8,
    ('all~', 'p=quarantine, sp=quarantine, aspf=r'): 8,
    ('all~', 'p=quarantine, sp=quarantine, aspf=s'): 8,
    ('all~', 'p=quarantine, sp=reject, aspf=r'): 8,
    ('all~', 'p=quarantine, sp=reject, aspf=s'): 8,
    ('all~', 'p=reject, sp=none, aspf=r'): 8,
    ('all~', 'p=reject, sp=none, aspf=s'): 8,
    ('all~', 'p=reject, sp=quarantine, aspf=r'): 8,
    ('all~', 'p=reject, sp=quarantine, aspf=s'): 8,
    ('all~', 'p=reject, sp=reject, aspf=r'): 8,
    ('all~', 'p=reject, sp=reject, aspf=s'): 8,
    ('No All', 'p=none, aspf=r'): 0,
    ('No All', 'p=none, sp=none, aspf=r'): 0,
    ('No All', 'No DMARC'): 0,
    ('No All', 'p=quarantine, sp=none, aspf=r'): 1,
    ('No All', 'p=quarantine, sp=none, aspf=s'): 1,
    ('No All', 'p=reject, sp=none, aspf=r'): 1,
    ('No All', 'p=reject, sp=none, aspf=s'): 1,
    ('No All', 'p=none'): 4,
    ('No All', 'p=none, sp=none'): 4,
    ('No All', 'p=none, aspf=s'): 4,
    ('No All', 'p=none, sp=none, aspf=s'): 4,
    ('No All', 'p=none, sp=quarantine'): 5,
    ('No All', 'p=none, sp=reject'): 5,
    ('No All', 'p=none, sp=quarantine, aspf=r'): 5,
    ('No All', 'p=none, sp=quarantine, aspf=s'): 5,
    ('No All', 'p=none, sp=reject, aspf=r'): 5,
    ('No All', 'p=none, sp=reject, aspf=s'): 5,
    ('No All', 'p=quarantine, sp=none'): 6,
    ('No All', 'p=reject, sp=none'): 6,
    ('No All', 'p=quarantine'): 8,
    ('No All', 'p=reject'): 8,
    ('No All', 'p=quarantine, sp=quarantine'): 8,
    ('No All', 'p=quarantine, sp=reject'): 8,
    ('No All', 'p=reject, sp=quarantine'): 8,
    ('No All', 'p=reject, sp=reject'): 8,
    ('No All', 'p=quarantine, sp=quarantine, aspf=r'): 8,
    ('No All', 'p=quarantine, sp=quarantine, aspf=s'): 8,
    ('No All', 'p=quarantine, sp=reject, aspf=r'): 8,
    ('No All', 'p=quarantine, sp=reject, aspf=s'): 8,
    ('No All', 'p=reject, sp=quarantine, aspf=r'): 8,
    ('No All', 'p=reject, sp=quarantine, aspf=s'): 8,
    ('No All', 'p=reject, sp=reject, aspf=r'): 8,
    ('No All', 'p=reject, sp=reject, aspf=s'): 8,
    ('No SPF', 'No DMARC'): 0,
    ('No SPF', 'p=none, sp=none, aspf=r'): 2,
    ('No SPF', 'p=none, sp=none, aspf=s'): 2,
    ('No SPF', 'p=none'): 4,
    ('No SPF', 'p=quarantine'): 8,
    ('No SPF', 'p=reject'): 8,
    ('No SPF', 'p=none, sp=none'): 8,
    ('No SPF', 'p=none, sp=quarantine'): 8,
    ('No SPF', 'p=none, sp=reject'): 8,
    ('No SPF', 'p=none, aspf=r'): 8,
    ('No SPF', 'p=none, aspf=s'): 8,
    ('No SPF', 'p=quarantine, sp=none'): 8,
    ('No SPF', 'p=quarantine, sp=quarantine'): 8,
    ('No SPF', 'p=quarantine, sp=reject'): 8,
    ('No SPF', 'p=reject, sp=none'): 8,
    ('No SPF', 'p=reject, sp=quarantine'): 8,
    ('No SPF', 'p=reject, sp=reject'): 8,
    ('No SPF', 'p=none, sp=quarantine, aspf=r'): 8,
    ('No SPF', 'p=none, sp=quarantine, aspf=s'): 8,
    ('No SPF', 'p=none, sp=reject, aspf=r'): 8,
    ('No SPF', 'p=none, sp=reject, aspf=s'): 8,
    ('No SPF', 'p=quarantine, sp=none, aspf=r'): 8,
    ('No SPF', 'p=quarantine, sp=none, aspf=s'): 8,
    ('No SPF', 'p=quarantine, sp=quarantine, aspf=r'): 8,
    ('No SPF', 'p=quarantine, sp=quarantine, aspf=s'): 8,
    ('No SPF', 'p=quarantine, sp=reject, aspf=r'): 8,
    ('No SPF', 'p=quarantine, sp=reject, aspf=s'): 8,
    ('No SPF', 'p=reject, sp=none, aspf=r'): 8,
    ('No SPF', 'p=reject, sp=none, aspf=s'): 8,
    ('No SPF', 'p=reject, sp=quarantine, aspf=r'): 8,
    ('No SPF', 'p=reject, sp=quarantine, aspf=s'): 8,
    ('No SPF', 'p=reject, sp=reject, aspf=r'): 8,
    ('No SPF', 'p=reject, sp=reject, aspf=s'): 8,
}


class Spoofing:
    def __init__(
        self,
        domain,
        dmarc_record,
        p,
        aspf,
        spf_record,
        spf_all,
        spf_dns_queries,
        sp,
        pct,
    ):
        self.domain = domain
        self.dmarc_record = dmarc_record
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

    def _normalize_spf_config(self):
        """Convert SPF parameters to lookup table format."""
        if self.spf_record is None:
            return "No SPF"
        
        if self.spf_all is None:
            return "No All"
        
        # Handle multiple all mechanisms  
        if self.spf_all == "2many":
            return "Multiple All"  # Custom handling for multiple alls
            
        # SPF all mechanisms are already in correct format for table lookup
        # Table expects: "-all", "~all", "+all", "?all", "all-", "all+", "all?", "all~"
        return self.spf_all

    def _normalize_dmarc_config(self):
        """Convert DMARC parameters to lookup table format."""
        if not self.dmarc_record:
            return "No DMARC"
            
        # Build DMARC configuration string to match table format
        parts = []
        
        if self.p:
            parts.append(f"p={self.p}")
        
        if self.sp:
            parts.append(f"sp={self.sp}")
            
        if self.aspf:
            parts.append(f"aspf={self.aspf}")
        
        if not parts:
            return "No DMARC"
            
        return ", ".join(parts)

    @lru_cache(maxsize=512)
    def _lookup_spoofability(self, spf_config, dmarc_config):
        """Cached lookup for spoofability code."""
        return SPOOFABILITY_LOOKUP.get((spf_config, dmarc_config), 8)

    def is_spoofable(self):
        """Efficient spoofability lookup using empirical table."""
        # Handle percentage < 100%
        try:
            if self.pct and int(self.pct) != 100:
                return 3  # Partial enforcement = maybe spoofable
        except (ValueError, TypeError):
            pass
            
        # Handle too many DNS queries
        if self.spf_dns_queries > 10 and not self.dmarc_record:
            return 0  # SPF failure + no DMARC = spoofable
            
        # Get normalized configurations
        spf_config = self._normalize_spf_config()
        dmarc_config = self._normalize_dmarc_config()
        
        # Handle special cases not in table
        if spf_config == "Multiple All":
            return 3 if self.p == "none" else 8
            
        # Lookup in empirical table (O(1) operation)
        spoofability_code = self._lookup_spoofability(spf_config, dmarc_config)
        
        # Handle syntax validation fallback for unknown configurations
        if spoofability_code == 8 and (spf_config, dmarc_config) not in SPOOFABILITY_LOOKUP:
            try:
                spf_valid = validate_record_syntax(self.spf_record, "SPF")
                dmarc_valid = validate_record_syntax(self.dmarc_record, "DMARC")
                
                if (not spf_valid and not dmarc_valid) or (spf_valid and not dmarc_valid):
                    return 0  # Invalid records = spoofable
                if not spf_valid and dmarc_valid and self.p == "none":
                    return 3  # Invalid SPF + permissive DMARC = maybe
            except Exception:
                pass
                
        return spoofability_code

    def evaluate_spoofing(self):
        """Evaluates and returns whether spoofing is possible and the type of spoofing."""
        spoofing_types = {
            0: f"Spoofing possible for {self.domain}.",
            1: f"Subdomain spoofing possible for {self.domain}.",
            2: f"Organizational domain spoofing possible for {self.domain}.",
            3: f"Spoofing might be possible for {self.domain} (DMARC enforcement: {self.pct or '100'}%).",
            4: f"Spoofing might be possible (Mailbox dependent) for {self.domain}.",
            5: f"Organizational domain spoofing might be possible (Mailbox dependent) for {self.domain}.",
            6: f"Subdomain spoofing might be possible (Mailbox dependent) for {self.domain}.",
            7: f"Subdomain spoofing is possible and organizational domain spoofing might be possible for {self.domain}.",
            8: f"Spoofing is not possible for {self.domain}.",
        }

        spoofing_type = spoofing_types.get(
            self.spoofable, f"Unknown spoofing type for {self.domain}."
        )

        # Refined mapping for better symbol consistency
        if self.spoofable in {0, 1, 7}:
            spoofing_possible = True  # Definite spoofing
        elif self.spoofable == 8:
            spoofing_possible = False  # Not spoofable
        else:  # Codes 2, 3, 4, 5, 6
            spoofing_possible = None  # "maybe" - more accurate for uncertainty

        return spoofing_possible, spoofing_type

    def __str__(self):
        return (
            f"Domain: {self.domain}\n"
            f"Domain Type: {self.domain_type}\n"
            f"Spoofing Possible: {self.spoofing_possible}\n"
            f"Spoofing Type: {self.spoofing_type}"
        )