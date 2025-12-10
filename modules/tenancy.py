# modules/tenancy.py

import dns.resolver


class CloudTenancy:
    def __init__(self, domain, spf_record=None, mx_records=None, dns_server=None):
        self.domain = domain
        self.spf_record = spf_record  
        self.mx_records = mx_records
        self.dns_server = dns_server or "1.1.1.1"
        self.is_microsoft_tenant = self.detect_microsoft_tenancy()
        
    def detect_microsoft_tenancy(self):
        """Detect Microsoft tenant from SPF includes or MX records"""
        # Check SPF includes first (most reliable)
        if self.spf_record:
            spf_lower = self.spf_record.lower()
            if "spf.protection.outlook.com" in spf_lower:
                return True
            if "include:outlook.com" in spf_lower:
                return True
                
        # Check MX records as secondary indicator
        if self.mx_records:
            mx_hostnames = " ".join(self.mx_records).lower()
            if "outlook.com" in mx_hostnames or "mail.protection.outlook.com" in mx_hostnames:
                return True
                
        return False
        
    def get_microsoft_tenant_domains(self):
        """Returns Microsoft default domains if tenant detected"""
        if not self.is_microsoft_tenant:
            return []
            
        # Extract base domain name (remove existing .onmicrosoft.com suffixes)
        base_domain = self.domain
        if base_domain.endswith('.mail.onmicrosoft.com'):
            base_domain = base_domain.replace('.mail.onmicrosoft.com', '')
        elif base_domain.endswith('.onmicrosoft.com'):
            base_domain = base_domain.replace('.onmicrosoft.com', '')
            
        # Generate potential tenant domains
        tenant_domains = [
            f"{base_domain}.onmicrosoft.com",
            f"{base_domain}.mail.onmicrosoft.com"
        ]
        
        # Filter out the original domain to avoid duplicates
        return [domain for domain in tenant_domains if domain != self.domain]
        
    def verify_tenant_domain_exists(self, tenant_domain):
        """Verify if a Microsoft tenant domain actually exists via DNS query"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            # Try to resolve the domain - if it exists, we get a response
            resolver.resolve(tenant_domain, "A")
            return True
        except:
            try:
                # Also try TXT record in case A record doesn't exist
                resolver.resolve(tenant_domain, "TXT")
                return True
            except:
                return False
                
    def get_verified_tenant_domains(self):
        """Returns only verified Microsoft tenant domains that actually exist"""
        potential_domains = self.get_microsoft_tenant_domains()
        verified_domains = []
        
        for domain in potential_domains:
            if self.verify_tenant_domain_exists(domain):
                verified_domains.append(domain)
                
        return verified_domains
        
    def should_auto_discover(self):
        """Determine if we should auto-discover tenant domains"""
        # Only auto-discover if we detected Microsoft tenancy
        # and the original domain is not already a .onmicrosoft.com domain
        return (self.is_microsoft_tenant and 
                not self.domain.endswith('.onmicrosoft.com') and 
                not self.domain.endswith('.mail.onmicrosoft.com'))

    def __str__(self):
        return (
            f"Domain: {self.domain}\n"
            f"Microsoft Tenant: {self.is_microsoft_tenant}\n"
            f"Tenant Domains: {self.get_microsoft_tenant_domains()}"
        )