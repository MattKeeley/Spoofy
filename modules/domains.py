# modules/domains.py

import tldextract


def registered_domain(name):
    """Registrable domain per the Public Suffix List ('' when `name` is itself a public suffix)."""
    extracted = tldextract.extract(name)
    return (
        f"{extracted.domain}.{extracted.suffix}"
        if extracted.domain and extracted.suffix
        else ""
    )


def is_subdomain(name):
    return bool(tldextract.extract(name).subdomain)


def normalize_domain(value):
    """Turn user input ('https://Example.com/x', 'example.com.', ' EXAMPLE.com ') into 'example.com'."""
    value = value.strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split("@")[-1].split(":", 1)[0]
    return value.rstrip(".")
