import unittest
from modules.spoofing import Spoofing


class TestSpoofy(unittest.TestCase):
    def test_spoofing_is_possible(self):
        spoofing = Spoofing(
            domain="test_0.com", 
            dmarc_record="v=DMARC1; p=none;", 
            p="none", 
            aspf="r", 
            spf_record="v=spf1 include:fake.gov", 
            spf_all="~all", 
            spf_dns_queries=3, 
            sp=None, 
            pct=100
        )
        self.assertEqual(spoofing.spoofable, 0)

    def test_subdomain_spoofing(self):
        spoofing = Spoofing(
            domain="test_1.com",
            dmarc_record="v=DMARC1; p=reject;",
            p="none",
            aspf=None,
            spf_record="v=spf1 include:fakest.domain.com",
            spf_all="-all",
            spf_dns_queries=3,
            sp="none",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 1)

    def test_organizational_domain_spoofing(self):
        spoofing = Spoofing(
            domain="test_2.com",
            dmarc_record="v=DMARC1; p=none;",
            p="none",
            aspf="r",
            spf_record="v=spf1 include:fakest.domain.com include:faker.domain.com",
            spf_all="-all",
            spf_dns_queries=2,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 2)

    def test_spoofing_might_be_possible(self):
        spoofing = Spoofing(
            domain="test_3.com",
            dmarc_record="v=DMARC1; p=none;",
            p="none",
            aspf=None,
            spf_record="v=spf1 include:fakest.domain.com",
            spf_all="~all",
            spf_dns_queries=1,
            sp="quarantine",
            pct=90,
        )
        self.assertEqual(spoofing.spoofable, 3)

    def test_spoofing_might_be_possible_mbd(self):
        spoofing = Spoofing(
            domain="test_4.com",
            dmarc_record="v=DMARC1; p=none;",
            p="none",
            aspf=None,
            spf_record="v=spf1 include:fakest.domain.com",
            spf_all="-all",
            spf_dns_queries=1,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 4)

    def test_org_domain_spoofing_might_be_possible(self):
        spoofing = Spoofing(
            domain="test_5.com",
            dmarc_record="v=DMARC1; p=none;",
            p="none",
            aspf=None,
            spf_record="v=spf1 include:fakest.domain.com",
            spf_all="-all",
            spf_dns_queries=1,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 5)

    def test_subdomain_spoofing_might_be_possible_mbd(self):
        spoofing = Spoofing(
            domain="test_6.com",
            dmarc_record="v=DMARC1; p=reject;",
            p="reject",
            aspf="r",
            spf_record="v=spf1 include:fakest.domain.com",
            spf_all="?all",
            spf_dns_queries=1,
            sp="none",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 6)

    def test_subdomain_spoofing_and_org_spoofing_might_be_possible(self):
        spoofing = Spoofing(
            domain="test_7.com",
            dmarc_record="v=DMARC1; p=none;",
            p="none",
            aspf=None,
            spf_record="v=spf1 include:fakest.domain.com",
            spf_all="~all",
            spf_dns_queries=3,
            sp="none",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 7)

    def test_spoofing_not_possible(self):
        spoofing = Spoofing(
            domain="test_8.com",
            dmarc_record="v=DMARC1; p=none;",
            p="none",
            aspf="s",
            spf_record="v=spf1 include:domain.com",
            spf_all="-all",
            spf_dns_queries=1,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)


if __name__ == "__main__":
    unittest.main()
