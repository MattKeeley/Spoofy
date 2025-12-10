# modules/mx.py

import dns.resolver


class MX:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.mx_records = self.get_mx_records()
        self.provider = None
        
        if self.mx_records:
            self.provider = self.detect_provider()

    def get_mx_records(self):
        """Returns the MX records for the domain."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server, "1.1.1.1", "8.8.8.8"]
            query_result = resolver.resolve(self.domain, "MX")
            
            mx_records = []
            for record in query_result:
                # MX records have priority and exchange (hostname)
                priority = record.preference
                hostname = str(record.exchange).rstrip('.')
                mx_records.append(f"{priority} {hostname}")
            
            return mx_records if mx_records else None
        except Exception:
            return None

    def detect_provider(self):
        """Detects email provider based on MX record hostnames."""
        if not self.mx_records:
            return None
            
        # Combine all MX hostnames for pattern matching
        mx_hostnames = " ".join(self.mx_records).lower()
        
        # Provider detection patterns
        if "outlook.com" in mx_hostnames or "mail.protection.outlook.com" in mx_hostnames:
            return "Microsoft Exchange Online"
        elif "google.com" in mx_hostnames or "googlemail.com" in mx_hostnames:
            return "Google Workspace"
        elif "protonmail.ch" in mx_hostnames:
            return "ProtonMail"
        elif "mailgun.org" in mx_hostnames:
            return "Mailgun"
        elif "sendgrid.net" in mx_hostnames:
            return "SendGrid"
        elif "ppe-hosted.com" in mx_hostnames:
            return "ProofPoint (potentially Exchange connector)"
        else:
            return "Custom/Unknown"

    def is_microsoft_customer(self):
        """Returns True if domain uses Microsoft Exchange Online."""
        return self.provider == "Microsoft Exchange Online"

    def __str__(self):
        mx_list = "\n".join([f"    {record}" for record in self.mx_records]) if self.mx_records else "None"
        return (
            f"MX Records:\n{mx_list}\n"
            f"Email Provider: {self.provider}"
        )