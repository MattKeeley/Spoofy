<h1 align="center">
<br>
<img src=/files/Spoofy.png height="310" border="2px solid #555">
<br>
Spoofy
</h1>


[![forthebadge](https://forthebadge.com/images/badges/made-with-python.svg)](https://www.python.org/)
[![forthebadge](https://forthebadge.com/images/badges/contains-tasty-spaghetti-code.svg)](https://www.thewholesomedish.com/spaghetti/)
[![forthebadge](https://forthebadge.com/images/badges/it-works-why.svg)](https://www.youtube.com/watch?v=kyti25ol438)

## WHAT
`Spoofy` is a program that checks if a list of domains can be spoofed based on SPF and DMARC records. You may be asking, "Why do we need another tool that can check if a domain can be spoofed?"

Well, Spoofy is different and here is why:
> 1. Authoritative lookups on all lookups with known good fallback (Cloudflare DNS)
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

## WHY

Hi all, Calamity here; You might be wondering, why do we need ANOTHER bulk lookup tool when there are so many out there? Well, have you tried any of them? I did, I tried ALL of them; Every single one that I could find. A trend I noticed was that singular lookups were doing great and reporting correctly on most tools, whereas bulk lookups were reporting bad results (No DMARC record when there actually was a record, etc…). I tried most of the tools on GitHub and even online paid webapps like MXtoolbox’s bulk lookup tool, and all of them were giving bad results.   

I found myself at the bottom of the barrel with no solution for doing bulk lookups. So I presented my issue to some communities I frequent online for a possible solution. That’s when [Matt](https://twitter.com/Nightbanes) offered to help me create a solution. At the time we didn’t know why the other tools were not working, but we had some ideas. Bishop Fox's project spoofcheck had consistent singular lookups so we thought just adding the ability to scan lists of domains would just work. It did not, we were running into the same issue the other tools were. So, Matt started troubleshooting and I started thinking about what we had to do to get it working for bulk lookups. After an entire codebase rework, we found that performing authoritative lookups on anything but Google’s DNS was how to get the most accurate reports. 

Other existing tools seem to save on resources and to preserve speed over all else when doing bulk lookups, which creates inconsistent results. Also when testing lookup functionality we found that Google’s DNS is extremely bad for performing lookups and is completely inconsistent, but other free DNS providers performed lookups as expected.


## HOW DO YOU KNOW ITS SPOOFABLE
(The spoofability table contains every combination of SPF and DMARC configuration with bearing on deliverability to the inbox, except DKIM modifiers.)
[Download Here](/files/Master_Table.xlsx)

## METHODOLOGY 
Hi all, it's Calamity again; the creation of the spoofability table was done by first listing out every possible SPF and DMARC configuration with bearing on deliverability (except DKIM), then creating every combination of each SPF and DMARC configuration together. Once the SPF and DMARC combinations were created, I was able to start my spoofability testing. 

The tools used to do this were an early version of Spoofy that could scan SPF and DMARC records and display the records correctly in bulk, Microsoft 365 enterprise mailbox, and my own HTML spoofer webapp I host [here](https://emailspooftest.com/toolbox.aspx) (“Spoofer” isn’t free sorry, but the “[Phishbot](https://emailspooftest.com/)” is free to try). I found out quickly that using my own domains to create every SPF and DMARC configuration to test if it was spoofable or not would take way too long because the SMTP servers honor the record time of 1 hour, therefore I would need to wait an hour between each test for the headers of the mail to correctly be represented during testing. 

So instead I used the early version of Spoofy to scan 10k+ US government / local government domains I found on the internet, and why not, the government likes free vulnerability tests right :stuck_out_tongue_winking_eye:? After the scan finished, I searched the scan results for domains with the specific combination I needed to test. At first, I was trying to use Protonmail and Gmail to do the testing, but I quickly found that they both utilize some reverse lookup checks on the backend that was messing up my results, especially for subdomain spoof testing. So I used Microsoft 365 which I have full control of, and how it handles mail. 

After mapping out the results using Microsoft 365, I retested using some of the combinations I suspected would behave differently from mailbox to mailbox using Protonmail and Gmail due to Microsoft 365 not really utilizing banners in the email besides “You don’t often get email from ‘sender address’ ”. Protonmail and Gmail can put spoof mail in the inbox with a banner and in spam without a banner which is why some SPF and DMARC combinations are reported as “(Mailbox Dependent)” when using Spoofy, whereas in Microsoft 365 both conditions would land in spam. 

So after about 5 days of getting bad results, then finally taking 2 days to log good results -_-, I finally had a good master table put together we would base the Spoofy spoofability logic on.

## ROADMAP
Matt had the excellent idea of making the tool more widely accessible in the form of a web application. We are thinking about using some interpreter to run python client-side in the browser for security and cost effectiveness reasons. This would be especially useful in corporate environments where admins are prohibited from using python or somehow don’t have VM access #government.

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
