import unittest
from modules.spoofing import Spoofing


class TestSpoofy(unittest.TestCase):
    def test_case_0(self):
        spoofing = Spoofing(
            domain="test_case_0.com",
            dmarc_record="No DMARC",
            p=None,
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 0)

    def test_case_1(self):
        spoofing = Spoofing(
            domain="test_case_1.com",
            dmarc_record="p=none, sp=none, aspf=r",
            p="none",
            aspf="r",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="none",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 1)

    def test_case_2(self):
        spoofing = Spoofing(
            domain="test_case_2.com",
            dmarc_record="p=none, sp=quarantine, aspf=r",
            p="none",
            aspf="r",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 2)

    def test_case_3(self):
        spoofing = Spoofing(
            domain="test_case_3.com",
            dmarc_record="p=none",
            p="none",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 4)

    def test_case_4(self):
        spoofing = Spoofing(
            domain="test_case_4.com",
            dmarc_record="p=none",
            p="none",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 4)

    def test_case_5(self):
        spoofing = Spoofing(
            domain="test_case_5.com",
            dmarc_record="p=none, sp=quarantine",
            p="none",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 5)

    def test_case_7(self):
        spoofing = Spoofing(
            domain="test_case_7.com",
            dmarc_record="p=none, sp=none, aspf=r",
            p="none",
            aspf="r",
            spf_record="v=spf1 ~all",
            spf_all="~all",
            spf_dns_queries=0,
            sp="none",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 7)

    def test_case_8(self):
        spoofing = Spoofing(
            domain="test_case_8.com",
            dmarc_record="p=none, sp=reject, aspf=s",
            p="none",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_9(self):
        spoofing = Spoofing(
            domain="test_case_9.com",
            dmarc_record="p=none",
            p="none",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 4)

    def test_case_10(self):
        spoofing = Spoofing(
            domain="test_case_10.com",
            dmarc_record="p=none, aspf=r",
            p="none",
            aspf="r",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 4)

    def test_case_11(self):
        spoofing = Spoofing(
            domain="test_case_11.com",
            dmarc_record="p=none, aspf=s",
            p="none",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 4)

    def test_case_12(self):
        spoofing = Spoofing(
            domain="test_case_12.com",
            dmarc_record="p=none, sp=quarantine",
            p="none",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 5)

    def test_case_13(self):
        spoofing = Spoofing(
            domain="test_case_13.com",
            dmarc_record="p=none, sp=reject",
            p="none",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 5)

    def test_case_14(self):
        spoofing = Spoofing(
            domain="test_case_14.com",
            dmarc_record="p=none, sp=none",
            p="none",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="none",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 7)

    def test_case_15(self):
        spoofing = Spoofing(
            domain="test_case_15.com",
            dmarc_record="p=quarantine",
            p="quarantine",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_16(self):
        spoofing = Spoofing(
            domain="test_case_16.com",
            dmarc_record="p=reject",
            p="reject",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_17(self):
        spoofing = Spoofing(
            domain="test_case_17.com",
            dmarc_record="p=quarantine, sp=quarantine",
            p="quarantine",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_18(self):
        spoofing = Spoofing(
            domain="test_case_18.com",
            dmarc_record="p=quarantine, sp=reject",
            p="quarantine",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_19(self):
        spoofing = Spoofing(
            domain="test_case_19.com",
            dmarc_record="p=reject, sp=quarantine",
            p="reject",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_20(self):
        spoofing = Spoofing(
            domain="test_case_20.com",
            dmarc_record="p=reject, sp=reject",
            p="reject",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_21(self):
        spoofing = Spoofing(
            domain="test_case_21.com",
            dmarc_record="p=none, sp=quarantine, aspf=s",
            p="none",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_22(self):
        spoofing = Spoofing(
            domain="test_case_22.com",
            dmarc_record="p=none, sp=reject, aspf=s",
            p="none",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_23(self):
        spoofing = Spoofing(
            domain="test_case_23.com",
            dmarc_record="p=quarantine, sp=none, aspf=s",
            p="quarantine",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="none",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_24(self):
        spoofing = Spoofing(
            domain="test_case_24.com",
            dmarc_record="p=quarantine, sp=quarantine, aspf=r",
            p="quarantine",
            aspf="r",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_25(self):
        spoofing = Spoofing(
            domain="test_case_25.com",
            dmarc_record="p=reject, sp=reject, aspf=s",
            p="reject",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_26(self):
        spoofing = Spoofing(
            domain="test_case_26.com",
            dmarc_record="p=reject, sp=none, aspf=s",
            p="reject",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="none",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_27(self):
        spoofing = Spoofing(
            domain="test_case_27.com",
            dmarc_record="p=reject, sp=quarantine, aspf=r",
            p="reject",
            aspf="r",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_28(self):
        spoofing = Spoofing(
            domain="test_case_28.com",
            dmarc_record="p=reject, sp=quarantine, aspf=s",
            p="reject",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_29(self):
        spoofing = Spoofing(
            domain="test_case_29.com",
            dmarc_record="p=reject, sp=reject, aspf=r",
            p="reject",
            aspf="r",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_30(self):
        spoofing = Spoofing(
            domain="test_case_30.com",
            dmarc_record="p=none, sp=none, aspf=r",
            p="none",
            aspf="r",
            spf_record="v=spf1 ?all",
            spf_all="?all",
            spf_dns_queries=0,
            sp="none",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 0)


if __name__ == "__main__":
    unittest.main()
