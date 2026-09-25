# modules/resolver.py

import threading
from dataclasses import dataclass, field

import dns.exception
import dns.resolver

DEFAULT_NAMESERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


@dataclass(frozen=True)
class DNSResult:
    """Outcome of one DNS query.

    status is one of:
      "ok"       - the name exists and has records of the requested type
      "nodata"   - the name exists but has no records of the requested type
      "nxdomain" - the name does not exist
      "error"    - timeout, SERVFAIL, REFUSED, ... (the answer is unknown)

    Keeping "error" distinct from "nodata"/"nxdomain" matters: a DMARC lookup
    that times out must not be reported as "No DMARC -> spoofing possible".
    """

    status: str
    records: tuple = field(default_factory=tuple)
    error: str = None

    @property
    def ok(self):
        return self.status == "ok"

    @property
    def void(self):
        """RFC 7208 4.6.4 'void lookup': NXDOMAIN or an empty answer."""
        return self.status in ("nxdomain", "nodata")


def txt_to_str(rdata):
    """Join the character-strings of a TXT RR the way RFC 7208 3.3 requires (no separator)."""
    return b"".join(rdata.strings).decode("utf-8", errors="replace")


class Resolver:
    """Thread-safe, caching wrapper around dnspython shared by every lookup of a run.

    A bulk run asks for the same names repeatedly (e.g. _spf.google.com is included by
    thousands of domains), so answers are cached for the lifetime of the process.
    """

    def __init__(self, nameservers=None, timeout=3.0, lifetime=8.0):
        self.nameservers = list(nameservers or DEFAULT_NAMESERVERS)
        self._resolver = dns.resolver.Resolver(configure=False)
        self._resolver.nameservers = self.nameservers
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime
        self._cache = {}
        self._lock = threading.Lock()

    def query(self, name, rdtype):
        key = (name.lower().rstrip("."), rdtype)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        result = self._query(key[0], rdtype)
        if result.status != "error":  # a transient failure must not stick for the whole run
            with self._lock:
                self._cache[key] = result
        return result

    def txt(self, name):
        return self.query(name, "TXT")

    def _query(self, name, rdtype):
        try:
            answer = self._resolver.resolve(name, rdtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return DNSResult("nxdomain")
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            return DNSResult("error", error=type(e).__name__)
        except dns.exception.DNSException as e:
            return DNSResult("error", error=f"{type(e).__name__}: {e}")
        if answer.rrset is None:
            return DNSResult("nodata")
        if rdtype == "TXT":
            records = tuple(txt_to_str(r) for r in answer.rrset)
        else:
            records = tuple(r.to_text() for r in answer.rrset)
        return DNSResult("ok", records)


_shared = {}
_shared_lock = threading.Lock()


def get_resolver(dns_server=None):
    """Return the process-wide Resolver for the given server (default: public resolvers)."""
    key = dns_server or ""
    with _shared_lock:
        if key not in _shared:
            _shared[key] = Resolver([dns_server] if dns_server else None)
        return _shared[key]
