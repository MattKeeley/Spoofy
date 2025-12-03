# modules/dkim.py

import requests


class DKIM:
    def __init__(self, domain, dns_server=None, api_base_url=None):
        self.domain = domain
        self.dns_server = dns_server
        self.api_base_url = "https://archive.prove.email/api"
        self.dkim_record = self.get_dkim_record()

    def get_dkim_record(self):
        """Returns the DKIM records for a given domain using the API."""
        try:
            base_url = self.api_base_url.rstrip('/')
            url = f"{base_url}/key"
            params = {"domain": self.domain}
            headers = {"accept": "application/json"}
            
            response = requests.get(url, params=params, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return self.format_dkim_records(data)
            elif response.status_code == 400:
                return None
            elif response.status_code == 429:
                return None
            elif response.status_code == 500:
                return None
            else:
                return None
        except requests.exceptions.RequestException:
            return None
        except (KeyError, ValueError, TypeError):
            return None

    def format_dkim_records(self, api_response):
        """Formats the API response into a readable string format."""
        combined_txt_records = ""
        
        if not isinstance(api_response, list):
            return None
        
        records_by_key = {}
        for record in api_response:
            if not isinstance(record, dict):
                continue
                
            selector = record.get("selector", "unknown")
            domain = record.get("domain", self.domain)
            value = record.get("value", "")
            last_seen = record.get("lastSeenAt", "")
            
            key = f"{selector}._domainkey.{domain}"
            
            if key not in records_by_key:
                records_by_key[key] = record
            else:
                existing_last_seen = records_by_key[key].get("lastSeenAt", "")
                if last_seen > existing_last_seen:
                    records_by_key[key] = record
        
        for key, record in records_by_key.items():
            selector = record.get("selector", "unknown")
            domain = record.get("domain", self.domain)
            value = record.get("value", "")
            
            if len(value) > 128:
                trimmed_value = value[:128] + "...(trimmed)"
            else:
                trimmed_value = value
            
            combined_txt_records += (
                f"[*]    {selector}._domainkey.{domain} -> {trimmed_value}\r\n"
            )
        
        if combined_txt_records:
            return combined_txt_records.strip()
        else:
            return None

    def __str__(self):
        return f"DKIM Record: {self.dkim_record}"

