# modules/domains.py

import tldextract


def registered_domain(name):
    """Registrable domain per the Public Suffix List ('' when `name` is itself a public suffix)."""
    extracted = tldextract.extract(name)
    # tldextract >= 5.3 renamed registered_domain and warns on the old name.
    if hasattr(extracted, "top_domain_under_public_suffix"):
        return extracted.top_domain_under_public_suffix
    return extracted.registered_domain


def is_subdomain(name):
    return bool(tldextract.extract(name).subdomain)


def normalize_domain(value):
    """Turn user input ('https://Example.com/x', 'example.com.', ' EXAMPLE.com ') into 'example.com'."""
    value = value.strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split("@")[-1].split(":", 1)[0]
    return value.rstrip(".")
