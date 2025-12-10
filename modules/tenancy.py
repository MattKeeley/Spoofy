# modules/tenancy.py

class CloudTenancy:
    def __init__(self, domain, spf_record=None):
        self.domain = domain
        self.spf_record = spf_record
        self.is_microsoft_tenant = self._is_microsoft_tenant()
        
    def _is_microsoft_tenant(self):
        """Simple Microsoft 365 detection via SPF record"""
        if not self.spf_record:
            return False
        return "include:spf.protection.outlook.com" in self.spf_record.lower()
        
    def get_tenant_domains(self):
        """Generate Microsoft tenant domains using simple pattern"""
        if not self.is_microsoft_tenant:
            return []
            
        # Extract domain name (before first dot) unless already onmicrosoft domain
        if self.domain.endswith('.onmicrosoft.com') or self.domain.endswith('.mail.onmicrosoft.com'):
            # Already a tenant domain, extract the base name
            if self.domain.endswith('.mail.onmicrosoft.com'):
                domain_name = self.domain.replace('.mail.onmicrosoft.com', '')
            else:
                domain_name = self.domain.replace('.onmicrosoft.com', '')
        else:
            # Regular domain - extract name before first dot
            domain_name = self.domain.split('.')[0]
            
        # Generate both standard tenant domains
        tenant_domains = [
            f"{domain_name}.onmicrosoft.com",
            f"{domain_name}.mail.onmicrosoft.com"
        ]
        
        # Only return domains different from original
        return [domain for domain in tenant_domains if domain != self.domain]
        
    def should_discover_tenants(self):
        """Determine if tenant discovery should occur"""
        return (self.is_microsoft_tenant and 
                not self.domain.endswith('.onmicrosoft.com'))