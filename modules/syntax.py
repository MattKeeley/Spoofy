# modules/syntax.py
import re


def validate_record_syntax(record, record_type):
    """Validate the syntax of a DNS record (SPF or DMARC)."""

    if record_type == "SPF":
        mechanism_patterns = {
            "all": r"^all$",
            "include": r"^include:[\w\.\-]+\.[a-zA-Z]{2,}$",
            "a": r"^a(:[\w\.\-]+)?$",
            "mx": r"^mx(:[\w\.\-]+)?$",
            "ptr": r"^ptr(:[\w\.\-]+)?$",
            "ip4": r"^ip4:(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$",
            "ip6": r"^ip6:[a-fA-F0-9:]+(\/\d{1,3})?$",
            "exists": r"^exists:[\w\.\-]+\.[a-zA-Z]{2,}$",
        }

        modifier_patterns = {
            "redirect": r"^redirect=[\w\.\-]+\.[a-zA-Z]{2,}$",
            "exp": r"^exp=[\w\.\-]+\.[a-zA-Z]{2,}$",
        }

        elements = record.split()

        if len(elements) == 0 or elements[0].strip().lower() != "v=spf1":
            return False

        for element in elements[1:]:
            element = element.strip()

            if element[0] in ["+", "-", "~", "?"]:
                qualifier = element[0]
                element = element[1:]
            else:
                qualifier = "+"

            if ":" in element:
                mechanism, value = element.split(":", 1)
            elif "=" in element:
                modifier, value = element.split("=", 1)
                mechanism = modifier
            else:
                mechanism = element
                value = None

            if mechanism in mechanism_patterns:
                pattern = mechanism_patterns[mechanism]
                if value:
                    if not re.match(pattern, element):
                        return False
                elif not re.match(r"^" + mechanism + r"$", element):
                    return False

            elif mechanism in modifier_patterns:
                pattern = modifier_patterns[mechanism]
                if not re.match(pattern, element):
                    return False
            else:
                return False
    elif record_type == "DMARC":
        tag_patterns = {
            "v": r"^DMARC1$",
            "p": r"^(none|quarantine|reject)$",
            "sp": r"^(none|quarantine|reject)$",
            "pct": r"^(100|[1-9]?[0-9])$",
            "rua": r"^[\w\.\-]+@[\w\.\-]+\.[a-zA-Z]{2,}$",
            "ruf": r"^[\w\.\-]+@[\w\.\-]+\.[a-zA-Z]{2,}$",
            "rf": r"^(afrf)$",
            "fo": r"^(0|1|d|s)$",
            "ri": r"^\d+$",
            "aspf": r"^(r|s)$",
            "adkim": r"^(r|s)$",
        }

        tags = record.split(";")

        if len(tags) < 2 or not tags[0].strip().startswith("v=DMARC1"):
            return False

        for tag in tags:
            tag = tag.strip()
            if not tag:
                continue
            tag_key_value = tag.split("=")

            if len(tag_key_value) != 2:
                return False

            tag_key, tag_value = tag_key_value
            tag_key = tag_key.lower().strip()
            tag_value = tag_value.strip()

            if tag_key in tag_patterns:
                if not re.match(tag_patterns[tag_key], tag_value):
                    return False
            else:
                return False
    else:
        return False
    return True
