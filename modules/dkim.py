# modules/dkim.py

import requests
from bs4 import BeautifulSoup


class DKIM:
    def __init__(self, domain, dns_server=None, api_base_url=None):
        self.domain = domain
        self.dns_server = dns_server
        self.api_base_url = "https://easydmarc.com/tools/dkim-lookup/status"
        self.dkim_record = self.get_dkim_record()

    def get_dkim_record(self):
        """Returns the DKIM records for a given domain by scraping easydmarc.com."""
        try:
            url = f"{self.api_base_url}?domain={self.domain}&selector=auto&is_embed=false"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                return self.parse_html_response(response.text)
            else:
                return None
        except requests.exceptions.RequestException:
            return None
        except Exception:
            return None

    def parse_html_response(self, html_content):
        """Parses the HTML response from easydmarc.com to extract DKIM records."""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find all DKIM record blocks directly
            record_blocks = soup.find_all('div', class_='block')
            if not record_blocks:
                return None
            
            records = []
            for block in record_blocks:
                record = self.extract_record_from_block(block)
                if record:
                    records.append(record)
            
            if records:
                return self.format_dkim_records(records)
            else:
                return None
                
        except Exception:
            return None

    def extract_record_from_block(self, block):
        """Extracts selector and value from a single record block."""
        try:
            # Find selector
            selector_span = block.find('span', class_='fw-bold')
            if not selector_span:
                return None
            selector = selector_span.get_text(strip=True)
            
            # Find record value
            value_span = block.find('span', class_='font-family-ibm-plex-mono')
            if not value_span:
                return None
            value = value_span.get_text(strip=True)
            
            return {
                'selector': selector,
                'domain': self.domain,
                'value': value
            }
        except Exception:
            return None

    def format_dkim_records(self, records):
        """Formats the extracted records into the same output format as the original."""
        combined_txt_records = ""
        
        for record in records:
            selector = record.get("selector", "unknown")
            domain = record.get("domain", self.domain)
            value = record.get("value", "")
            
            combined_txt_records += (
                f"[*]    {selector}._domainkey.{domain} -> {value}\r\n"
            )
        
        if combined_txt_records:
            return combined_txt_records.strip()
        else:
            return None

    def __str__(self):
        return f"DKIM Record: {self.dkim_record}"
