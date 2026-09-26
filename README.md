<h1 align="center">
<br>
<img src=https://raw.githubusercontent.com/MattKeeley/Spoofy/main/files/Spoofy_logo.png height="375" border="2px solid #555">
<br>
Spoofy
</h1>

[![forthebadge](https://forthebadge.com/images/badges/made-with-python.svg)](https://www.python.org/)
[![forthebadge](https://forthebadge.com/images/badges/contains-tasty-spaghetti-code.svg)](https://www.thewholesomedish.com/spaghetti/)
[![forthebadge](https://forthebadge.com/images/badges/it-works-why.svg)](https://www.youtube.com/watch?v=kyti25ol438)

## WHAT

`Spoofy` is a program that checks if a list of domains can be spoofed based on SPF and DMARC records. You may be asking, "Why do we need another tool that can check if a domain can be spoofed?"

Well, Spoofy is different and here is why:

> 1. Custom, manually tested spoof logic (No guessing or speculating, real world test results)
> 2. Standards-based record discovery: RFC 7208 SPF evaluation and the RFC 9989 DMARC tree walk, including `sp`/`np` for subdomains
> 3. Accurate bulk lookups over a shared, caching resolver with failover (1.1.1.1, 8.8.8.8, 9.9.9.9)
> 4. SPF DNS query and void lookup counter, plus detection of unregistered SPF include domains
> 5. Optional DKIM selector enumeration via API

## PASSING TESTS

[![Spoofy CI](https://github.com/MattKeeley/Spoofy/actions/workflows/ci.yml/badge.svg)](https://github.com/MattKeeley/Spoofy/actions/workflows/ci.yml)

## HOW TO USE

`Spoofy` requires **Python 3.9+**. Install it from PyPI:

```console
pip3 install spoofy
spoofy -d example.com
```

Or run it from a clone with `pip3 install -r requirements.txt` and `./spoofy.py` in place of `spoofy`. Usage is shown below:

```console
Usage:
    spoofy -d [DOMAIN] -o [stdout, xls or json] -t [NUMBER_OF_THREADS] [--dkim] [--dns-server IP]
    OR
    spoofy -iL [DOMAIN_LIST] -o [stdout, xls or json] -t [NUMBER_OF_THREADS] [--dkim] [--dns-server IP]

Options:
    -d            : Process a single domain.
    -iL           : Provide a file containing a list of domains to process (blank lines and # comments are skipped).
    -o            : Specify the output format: stdout (default), xls, or json.
    -t            : Set the number of threads to use (default: 4).
    --dkim        : Enable DKIM selector enumeration via API (optional).
    --dns-server  : Query this resolver instead of 1.1.1.1, 8.8.8.8 and 9.9.9.9.

Examples:
    spoofy -d example.com -t 10
    spoofy -d example.com --dkim
    spoofy -iL domains.txt -o xls
    spoofy -iL domains.txt -o json --dkim
```

## HOW DO YOU KNOW ITS SPOOFABLE

(The spoofability table lists every combination of SPF and DMARC configurations that impact deliverability to the inbox, except for DKIM modifiers.)
[Download Here](https://raw.githubusercontent.com/MattKeeley/Spoofy/main/files/Master_Table.xlsx)

| Code | Result | `SPOOFING_POSSIBLE` |
| ---- | ------ | ------------------- |
| 0 | Spoofing possible | `true` |
| 1 | Subdomain spoofing possible | `true` |
| 2 | Organizational domain spoofing possible | `true` |
| 3 | Spoofing might be possible (`p=quarantine` with `pct` < 100) | `null` |
| 4 | Spoofing might be possible (mailbox dependent) | `null` |
| 5 | Organizational domain spoofing might be possible (mailbox dependent) | `null` |
| 6 | Subdomain spoofing might be possible (mailbox dependent) | `null` |
| 7 | Subdomain spoofing possible, organizational domain spoofing might be possible | `true` |
| 8 | Spoofing is not possible | `false` |
| 9 | Unable to determine (a DNS lookup failed) | `null` |

The verdict is the tested code for the domain's SPF `all` mechanism and the DMARC `p`, `sp` and `aspf` tags as the record writes them. `spoofy/master_table.py` holds the spreadsheet as data (`python3 -m spoofy.master_table` rewrites it after the spreadsheet changes), and `test.py` checks that every row is reproduced. Inputs the table does not cover are handled as follows:

- **An enforcing `p` with `aspf` but no `sp`** (24 untested combinations): `sp` defaults to `p`, so the tested row with `sp` written out is used.
- **A DMARC record inherited from a parent domain** (a subdomain without its own `_dmarc` record): the subdomain outcome tested for the parent's SPF and DMARC records, with `np` in place of `sp` when the subdomain does not exist.
- **`pct` below 100 with `p=quarantine`**: code 3, since the unsampled mail gets `p=none`. With `p=reject` the unsampled mail is still quarantined, so `pct` does not change the verdict.
- **`t=y`** (RFC 9989 testing mode): the policy drops one level (`reject` to `quarantine`, `quarantine` to `none`) before the lookup.
- **A failed DNS lookup**: code 9 instead of treating the record as missing.

## METHODOLOGY

The creation of the spoofability table involved listing every relevant SPF and DMARC configuration, combining them, and then conducting SPF and DMARC information collection using an early version of Spoofy on a large number of US government domains. Testing if an SPF and DMARC combination was spoofable or not was done using the email security pentesting suite at [emailspooftest](https://emailspooftest.com/) using Microsoft 365. However, the initial testing was conducted using Protonmail and Gmail, but these services were found to utilize reverse lookup checks that affected the results, particularly for subdomain spoof testing. As a result, Microsoft 365 was used for the testing, as it offered greater control over the handling of mail.

After the initial testing using Microsoft 365, some combinations were retested using Protonmail and Gmail due to the differences in their handling of banners in emails. Protonmail and Gmail can place spoofed mail in the inbox with a banner or in spam without a banner, leading to some SPF and DMARC combinations being reported as "Mailbox Dependent" when using Spoofy. In contrast, Microsoft 365 places both conditions in spam. The testing and data collection process took several days to complete, after which a good master table was compiled and used as the basis for the Spoofy spoofability logic.

## DISCLAIMER

> This tool is only for testing and academic purposes and can only be used where
> strict consent has been given. Do not use it for illegal purposes! It is the
> end user’s responsibility to obey all applicable local, state and federal laws.
> Developers assume no liability and are not responsible for any misuse or damage
> caused by this tool and software.

## LICENSE

This project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License - see the [LICENSE](https://github.com/MattKeeley/Spoofy/blob/main/LICENSE) file for details
