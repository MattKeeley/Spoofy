<h1 align="center">
<br>
<img src=/files/spoofy.png height="310" border="2px solid #555">
<br>
Spoofy
</h1>


[![forthebadge](https://forthebadge.com/images/badges/made-with-python.svg)](https://www.python.org/)
[![forthebadge](https://forthebadge.com/images/badges/contains-tasty-spaghetti-code.svg)](https://www.thewholesomedish.com/spaghetti/)
[![forthebadge](https://forthebadge.com/images/badges/it-works-why.svg)](https://www.youtube.com/watch?v=kyti25ol438)

## WHAT
`Spoofy` is a program that checks if a list of domains can be spoofed based on SPF and DMARC records. You may be asking, "Why do we need another tool that can check if a domain can be spoofed?"

Well, Spoofy is different and here is why:
> 1. Authoritative lookups on all lookups with known fallback (Cloudflare DNS)
> 2. Accurate bulk lookups
> 3. Custom, manually tested spoof logic (No guessing or speculating, real world test results) 
> 4. SPF lookup counter

## HOW TO USE
`Spoofy` requires **Python 3+**. Python 2 is not supported. Usage is shown below:

```console
Usage:
    ./spoofy.py -d [DOMAIN]
    OR
    ./spoofy.py -iL [DOMAIN_LIST]
    
Install Dependencies:
    pip3 install -r requirements.txt
```

## HOW DO YOU KNOW ITS SPOOFABLE
(The spoofability table lists every combination of SPF and DMARC configurations that impact deliverability to the inbox, except for DKIM modifiers.)
[Download Here](/files/Master_Table.xlsx)

## METHODOLOGY 
The creation of the spoofability table involved listing every relevant SPF and DMARC configuration, combining them, and then conducting spoofability testing using the early version of Spoofy. The testing was conducted on a large number of US government and local government domains, using Microsoft 365. However, the initial testing was conducted using Protonmail and Gmail, but these services were found to utilize reverse lookup checks that affected the results, particularly for subdomain spoof testing. As a result, Microsoft 365 was used for the testing, as it offered greater control over the handling of mail.

After the initial testing using Microsoft 365, some combinations were retested using Protonmail and Gmail due to the differences in their handling of banners in emails. Protonmail and Gmail can place spoofed mail in the inbox with a banner or in spam without a banner, leading to some SPF and DMARC combinations being reported as "Mailbox Dependent" when using Spoofy. In contrast, Microsoft 365 places both conditions in spam. The testing and data collection process took several days to complete, after which a good master table was compiled and used as the basis for the Spoofy spoofability logic.


## ROADMAP
The team proposed the idea of making the tool more widely accessible by developing a web application. To do this in a secure and cost-effective manner, the team is considering using an interpreter to run the Python client-side in the browser. This would be particularly useful in corporate environments where administrators are prohibited from using Python or do not have access to virtual machines. This solution would allow for broader use of the tool, particularly in government settings.


## DISCLAIMER

> This tool is only for testing and academic purposes and can only be used where
> strict consent has been given. Do not use it for illegal purposes! It is the
> end user’s responsibility to obey all applicable local, state and federal laws.
> Developers assume no liability and are not responsible for any misuse or damage
> caused by this tool and software.

## CREDIT
Tool was inspired by [Bishop Fox's](https://github.com/BishopFox/) project called [spoofcheck](https://github.com/BishopFox/spoofcheck/).

Lead / Only programmer & spoofability logic comprehension upgrades & lookup resiliency system / fix (main issue with other tools) & multithreading & feature additions: [Matt Keeley](https://github.com/MattKeeley/)

DMARC, SPF, DNS insights & Spoofability table creation/confirmation/testing & application accuracy/quality assurance: calamity#6391



## LICENSE

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE)
file for details
