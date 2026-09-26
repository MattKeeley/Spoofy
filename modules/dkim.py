# modules/dkim.py

API_URL = "https://archive.prove.email/api/key"


class DKIM:
    """Known DKIM selectors for a domain, from the archive.prove.email key archive."""

    def __init__(self, domain):
        self.domain = domain
        self.dkim_record = self.get_dkim_record()

    def get_dkim_record(self):
        """Returns the DKIM records for the domain, or None if there are none or the API fails."""
        import requests  # only --dkim needs it

        try:
            response = requests.get(
                API_URL,
                params={"domain": self.domain},
                headers={"accept": "application/json"},
                timeout=10,
            )
            if response.status_code == 200:
                return self.format_dkim_records(response.json())
        except (requests.exceptions.RequestException, ValueError, TypeError):
            pass
        return None

    def format_dkim_records(self, api_response):
        """One line per selector (its latest sighting), key values trimmed to 128 characters."""
        if not isinstance(api_response, list):
            return None
        latest = {}
        for record in api_response:
            if not isinstance(record, dict):
                continue
            selector = record.get("selector", "unknown")
            name = f"{selector}._domainkey.{record.get('domain', self.domain)}"
            if name not in latest or record.get("lastSeenAt", "") > latest[name].get("lastSeenAt", ""):
                latest[name] = record

        lines = []
        for name, record in latest.items():
            value = record.get("value", "")
            if len(value) > 128:
                value = value[:128] + "...(trimmed)"
            lines.append(f"[*]    {name} -> {value}")
        return "\r\n".join(lines).strip() or None
