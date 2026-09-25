#! /usr/bin/env python3

import itertools
import json
import os
import unittest
from types import SimpleNamespace
from unittest import mock

import dns.exception
import dns.resolver

import spoofy
from modules.dmarc import DMARC, POLICIES, parse_tags, tree_walk_targets
from modules.master_table import TABLE as MASTER_TABLE
from modules.master_table import load_spreadsheet
from modules.resolver import DNSResult, Resolver, txt_to_str
from modules.spf import SPF, parse_terms
from modules.spoofing import SPF_STATES, Spoofing, lookup

SPREADSHEET = os.path.join(os.path.dirname(__file__), "files", "Master_Table.xlsx")


class FakeResolver:
    """Answers from a dict; every other name is NXDOMAIN."""

    nameservers = ("fake",)

    def __init__(self, txt=None, other=None):
        self.records = {name: DNSResult("ok", tuple(v)) for name, v in (txt or {}).items()}
        self.other = other or {}
        self.queries = []

    def txt(self, name):
        return self.query(name, "TXT")

    def query(self, name, rdtype):
        self.queries.append((name, rdtype))
        if rdtype == "TXT" and name in self.records:
            return self.records[name]
        return self.other.get((name, rdtype), DNSResult("nxdomain"))


def spoof(dmarc_record=None, spf_record="v=spf1 -all", spf_all="-all", **kw):
    tags = parse_tags(dmarc_record) if dmarc_record else {}
    return Spoofing(
        kw.pop("domain", "example.com"),
        dmarc_record,
        tags.get("p"),
        tags.get("aspf"),
        spf_record,
        spf_all,
        0,
        tags.get("sp"),
        tags.get("pct"),
        np=tags.get("np"),
        t=tags.get("t"),
        **kw,
    ).spoofable


class TestDMARCParsing(unittest.TestCase):
    def test_sp_before_p_is_not_read_as_p(self):
        tags = parse_tags("v=DMARC1; sp=none; p=reject")
        self.assertEqual((tags["p"], tags["sp"]), ("reject", "none"))

    def test_np_is_not_read_as_p(self):
        self.assertEqual(parse_tags("v=DMARC1; np=reject; p=none")["p"], "none")

    def test_case_and_whitespace(self):
        self.assertEqual(parse_tags("v=DMARC1; P = reject ")["p"], "reject")

    def test_tree_walk_targets(self):
        self.assertEqual(
            tree_walk_targets("a.b.example.com"),
            ["a.b.example.com", "b.example.com", "example.com", "com"],
        )
        long = "1.2.3.4.5.6.7.8.9.example.com"
        self.assertEqual(tree_walk_targets(long)[1], "5.6.7.8.9.example.com")


class TestDMARCDiscovery(unittest.TestCase):
    def test_subdomain_own_record_wins(self):
        r = FakeResolver(
            {
                "_dmarc.mail.example.com": ["v=DMARC1; p=none"],
                "_dmarc.example.com": ["v=DMARC1; p=reject"],
            }
        )
        d = DMARC("mail.example.com", resolver=r)
        self.assertEqual((d.record_domain, d.applicable_policies()), ("mail.example.com", ("none", "none")))

    def test_inherited_record_applies_sp(self):
        r = FakeResolver(
            {"_dmarc.example.com": ["v=DMARC1; p=reject; sp=none"]},
            {("mail.example.com", "A"): DNSResult("ok", ("192.0.2.1",))},
        )
        d = DMARC("mail.example.com", resolver=r)
        self.assertTrue(d.inherited)
        self.assertEqual(d.applicable_policies(), ("none", "none"))

    def test_inherited_record_applies_np_to_nonexistent_domain(self):
        r = FakeResolver({"_dmarc.example.com": ["v=DMARC1; p=reject; sp=none; np=quarantine"]})
        d = DMARC("ghost.example.com", resolver=r)
        self.assertFalse(d.domain_exists)
        self.assertEqual(d.applicable_policies(), ("quarantine", "none"))

    def test_public_suffix_domain_uses_its_own_record(self):
        r = FakeResolver({"_dmarc.gov.uk": ["v=DMARC1;p=reject;sp=none;np=reject"]})
        self.assertEqual(DMARC("gov.uk", resolver=r).policy, "reject")

    def test_multiple_records_are_discarded(self):
        r = FakeResolver(
            {
                "_dmarc.mail.example.com": ["v=DMARC1; p=none", "v=DMARC1; p=reject"],
                "_dmarc.example.com": ["v=DMARC1; p=quarantine"],
            }
        )
        d = DMARC("mail.example.com", resolver=r)
        self.assertEqual((d.record_domain, d.policy), ("example.com", "quarantine"))

    def test_organizational_domain_beats_intermediate_record(self):
        r = FakeResolver(
            {
                "_dmarc.b.example.com": ["v=DMARC1; p=none"],
                "_dmarc.example.com": ["v=DMARC1; p=reject"],
            }
        )
        d = DMARC("a.b.example.com", resolver=r)
        self.assertEqual((d.record_domain, d.policy), ("example.com", "reject"))

    def test_only_intermediate_record_is_used(self):
        r = FakeResolver({"_dmarc.b.example.com": ["v=DMARC1; p=quarantine"]})
        self.assertEqual(DMARC("a.b.example.com", resolver=r).record_domain, "b.example.com")

    def test_psd_n_marks_organizational_domain(self):
        r = FakeResolver(
            {
                "_dmarc.b.example.com": ["v=DMARC1; p=quarantine; psd=n"],
                "_dmarc.example.com": ["v=DMARC1; p=reject"],
            }
        )
        self.assertEqual(DMARC("a.b.example.com", resolver=r).record_domain, "b.example.com")

    def test_psd_y_falls_back_to_psd_record(self):
        r = FakeResolver({"_dmarc.gov": ["v=DMARC1; p=reject; np=reject; psd=y"]})
        d = DMARC("a.example.gov", resolver=r)
        self.assertEqual((d.record_domain, d.inherited), ("gov", True))
        r.records["_dmarc.example.gov"] = DNSResult("ok", ("v=DMARC1; p=none",))
        self.assertEqual(DMARC("a.example.gov", resolver=r).record_domain, "example.gov")

    def test_version_is_case_sensitive(self):
        r = FakeResolver({"_dmarc.example.com": ["v=dmarc1; p=reject"]})
        d = DMARC("example.com", resolver=r)
        self.assertIsNone(d.dmarc_record)
        self.assertTrue(any("malformed" in w for w in d.warnings))
        r = FakeResolver({"_dmarc.example.com": ["V = DMARC1; p=reject"]})
        self.assertEqual(DMARC("example.com", resolver=r).policy, "reject")

    def test_non_dmarc_txt_ignored(self):
        r = FakeResolver({"_dmarc.example.com": ["google-site-verification=DMARC1", "v=DMARC1; p=reject"]})
        self.assertEqual(DMARC("example.com", resolver=r).policy, "reject")

    def test_invalid_policy_with_rua_is_none(self):
        r = FakeResolver({"_dmarc.example.com": ["v=DMARC1; p=rejected; rua=mailto:a@example.com"]})
        self.assertEqual(DMARC("example.com", resolver=r).policy, "none")

    def test_invalid_policy_without_rua_is_ignored(self):
        r = FakeResolver({"_dmarc.example.com": ["v=DMARC1; p=rejected"]})
        self.assertIsNone(DMARC("example.com", resolver=r).policy)

    def test_lookup_error_is_not_no_dmarc(self):
        r = FakeResolver()
        r.records["_dmarc.example.com"] = DNSResult("error", error="Timeout")
        d = DMARC("example.com", resolver=r)
        self.assertTrue(d.lookup_error)
        self.assertEqual(spoof(None, lookup_error=d.lookup_error), 9)


class TestResolver(unittest.TestCase):
    def test_errors_are_not_cached(self):
        r = Resolver(["192.0.2.1"])
        answers = [dns.exception.Timeout(), dns.resolver.NXDOMAIN()]

        def fake_resolve(*args, **kwargs):
            raise answers.pop(0)

        with mock.patch.object(r._resolver, "resolve", side_effect=fake_resolve):
            self.assertEqual(r.txt("example.com").status, "error")
            self.assertEqual(r.txt("example.com").status, "nxdomain")
            self.assertEqual(r.txt("example.com").status, "nxdomain")  # now cached


class TestSPF(unittest.TestCase):
    def spf(self, record, extra=None, other=None):
        records = {"example.com": [record]}
        records.update(extra or {})
        return SPF("example.com", resolver=FakeResolver(records, other))

    def test_hyphenated_include_is_not_an_all(self):
        self.assertEqual(self.spf("v=spf1 include:mail-allow.example.net ~all",
                                  {"mail-allow.example.net": ["v=spf1 -all"]}).all_mechanism, "~all")

    def test_bare_all_is_pass(self):
        self.assertEqual(self.spf("v=spf1 mx all").all_mechanism, "+all")

    def test_uppercase_all(self):
        self.assertEqual(self.spf("v=spf1 mx -ALL").all_mechanism, "-all")

    def test_first_all_wins(self):
        self.assertEqual(self.spf("v=spf1 -all ~all").all_mechanism, "-all")

    def test_redirect_followed_only_without_all(self):
        extra = {"_spf.example.net": ["v=spf1 ~all"]}
        self.assertEqual(self.spf("v=spf1 redirect=_spf.example.net", extra).all_mechanism, "~all")
        self.assertEqual(self.spf("v=spf1 -all redirect=_spf.example.net", extra).all_mechanism, "-all")

    def test_lookup_counting(self):
        for record, want in [
            ("v=spf1 a mx -all", 2),
            ("v=spf1 -all a", 0),  # never evaluated after 'all'

            ("v=spf1 mx", 1),
            ("v=spf1 ~a ?mx -all", 2),
            ("v=spf1 a/24 mx/24 -all", 2),
            ("v=spf1 ptr:example.com -all", 1),
            ("v=spf1 a:x.com mx:y.com ptr exists:%{i}.z.com ip4:192.0.2.0/24 -all", 4),
        ]:
            self.assertEqual(self.spf(record).spf_dns_query_count, want, record)

    def test_ip_mechanism_without_address_is_permerror(self):
        self.assertTrue(self.spf("v=spf1 ip4 -all").permerror)

    def test_terms_after_all_not_evaluated_but_still_validated(self):
        s = self.spf("v=spf1 -all include:never.example.net redirect=never.example.net bogus")
        self.assertEqual((s.all_mechanism, s.spf_dns_query_count), ("-all", 0))
        self.assertTrue(any("bogus" in e for e in s.errors))

    def test_nested_includes_counted(self):
        s = self.spf(
            "v=spf1 include:a.example.net -all",
            {"a.example.net": ["v=spf1 include:b.example.net mx ~all"], "b.example.net": ["v=spf1 a ~all"]},
        )
        self.assertEqual(s.spf_dns_query_count, 4)
        self.assertFalse(s.permerror)

    def test_include_loop_terminates(self):
        s = self.spf("v=spf1 include:loop.example.net -all",
                     {"loop.example.net": ["v=spf1 include:example.com ~all"]})
        self.assertTrue(any("loop" in e for e in s.errors))

    def test_too_many_lookups(self):
        includes = " ".join(f"include:i{n}.example.net" for n in range(11))
        extra = {f"i{n}.example.net": ["v=spf1 ip4:192.0.2.1 -all"] for n in range(11)}
        s = self.spf(f"v=spf1 {includes} -all", extra)
        self.assertTrue(s.too_many_dns_queries and s.permerror)

    def test_void_lookups_and_dangling_include(self):
        s = self.spf(
            "v=spf1 include:gone1.example.net include:gone2.example.net include:expired-vendor.net -all",
            other={("example.net", "NS"): DNSResult("ok", ("ns.example.net.",))},
        )
        self.assertEqual(s.void_lookups, 3)
        self.assertEqual(s.dangling_includes, ["expired-vendor.net"])
        self.assertTrue(s.permerror)

    def test_failed_include_is_not_fatal_but_failed_record_is(self):
        r = FakeResolver({"example.com": ["v=spf1 include:flaky.example.net -all"]})
        r.records["flaky.example.net"] = DNSResult("error", error="Timeout")
        self.assertFalse(SPF("example.com", resolver=r).lookup_error)
        r.records["example.com"] = DNSResult("error", error="Timeout")
        self.assertTrue(SPF("example.com", resolver=r).lookup_error)
        self.assertEqual(spoof("v=DMARC1; p=reject", None, None, spf_lookup_error=True), 8)
        self.assertEqual(spoof("v=DMARC1; p=none", None, None, spf_lookup_error=True), 9)

    def test_multiple_spf_records_is_permerror(self):
        s = SPF("example.com", resolver=FakeResolver({"example.com": ["v=spf1 -all", "v=spf1 ~all"]}))
        self.assertTrue(s.permerror)

    def test_txt_strings_joined_without_spaces(self):
        rdata = SimpleNamespace(strings=[b"v=spf1 include:_spf.goo", b"gle.com ~all"])
        self.assertEqual(txt_to_str(rdata), "v=spf1 include:_spf.google.com ~all")

    def test_parse_terms(self):
        terms = parse_terms("v=spf1 -ip4:192.0.2.0/24 a/24 redirect=x.example")
        self.assertEqual([(t.qualifier, t.name, t.value) for t in terms],
                         [("-", "ip4", "192.0.2.0/24"), ("+", "a", ""), (None, "redirect", "x.example")])


SPF_RECORDS = {
    "-all": ("v=spf1 -all", "-all"),
    "~all": ("v=spf1 ~all", "~all"),
    "?all": ("v=spf1 ?all", "?all"),
    "+all": ("v=spf1 +all", "+all"),
    "noall": ("v=spf1 include:_spf.example.net", None),
    "nospf": (None, None),
}


def record_for(dmarc):
    """DMARC record for a table key: ('none', 'reject', None) -> 'v=DMARC1; p=none; sp=reject'."""
    if dmarc is None:
        return None
    tags = zip(("p", "sp", "aspf"), dmarc)
    return "v=DMARC1; " + "; ".join(f"{tag}={value}" for tag, value in tags if value)


class TestMasterTable(unittest.TestCase):
    def test_module_matches_spreadsheet(self):
        self.assertEqual(list(load_spreadsheet(SPREADSHEET).items()), list(MASTER_TABLE.items()))

    def test_every_row_is_reproduced(self):
        for (state, dmarc), code in MASTER_TABLE.items():
            spf_record, spf_all = SPF_RECORDS[state]
            self.assertEqual(spoof(record_for(dmarc), spf_record, spf_all), code, (state, dmarc))

    def test_every_record_resolves_to_a_tested_row(self):
        for state in SPF_STATES:
            self.assertEqual(lookup(state), MASTER_TABLE[(state, None)])
            for p, sp, aspf in itertools.product(POLICIES, (None,) + POLICIES, (None, "r", "s")):
                expected = MASTER_TABLE.get((state, (p, sp, aspf)), MASTER_TABLE.get((state, (p, p, aspf))))
                self.assertIsNotNone(expected, (state, p, sp, aspf))
                self.assertEqual(lookup(state, p, sp, aspf), expected)

    def test_real_records_key_on_p_sp_aspf_as_written(self):
        record = "v=DMARC1; sp=none; rua=mailto:d@example.com; P=Reject; fo=1; adkim=s"
        self.assertEqual(spoof(record), MASTER_TABLE[("-all", ("reject", "none", None))])

    def test_common_configurations(self):
        self.assertEqual(spoof("v=DMARC1; p=none", "v=spf1 ~all", "~all"), 0)
        self.assertEqual(spoof("v=DMARC1; p=none"), 4)
        self.assertEqual(spoof("v=DMARC1; p=none", "v=spf1 ?all", "?all"), 4)
        self.assertEqual(spoof("v=DMARC1; p=reject; sp=none"), 1)
        self.assertEqual(spoof("v=DMARC1; p=none; sp=reject", "v=spf1 ~all", "~all"), 2)
        self.assertEqual(spoof("v=DMARC1; p=reject"), 8)
        self.assertEqual(spoof(None), 0)
        self.assertEqual(spoof("v=DMARC1; p=reject", "v=spf1 +all", "+all"), 4)

    def test_invalid_pct_passed_directly_does_not_crash(self):
        self.assertEqual(spoof("v=DMARC1; p=quarantine; pct=abc"), 8)

    def test_pct_and_testing_mode(self):
        self.assertEqual(spoof("v=DMARC1; p=quarantine; pct=50"), 3)
        self.assertEqual(spoof("v=DMARC1; p=reject; pct=50"), 8)
        self.assertEqual(spoof("v=DMARC1; p=reject; t=y"), 8)
        self.assertEqual(spoof("v=DMARC1; p=quarantine; t=y", "v=spf1 ~all", "~all"), 0)
        self.assertEqual(spoof("v=DMARC1; p=none; pct=0", "v=spf1 ~all", "~all"), 0)

    def test_inherited_record_uses_the_tested_subdomain_outcome(self):
        record = "v=DMARC1; p=reject; sp=none"  # table code 1: subdomain spoofing possible
        self.assertEqual(spoof(record, domain="mail.example.com"), 1)
        self.assertEqual(spoof(record, domain="mail.example.com", inherited=True, org_spf_state="-all"), 0)
        self.assertEqual(spoof("v=DMARC1; p=none; sp=reject", domain="mail.example.com", inherited=True), 8)
        self.assertEqual(spoof("v=DMARC1; p=reject; sp=quarantine; pct=50", inherited=True), 3)

    def test_inherited_record_is_judged_with_the_parents_spf(self):
        record = "v=DMARC1; p=reject; sp=none"
        self.assertEqual(spoof(record, None, None, inherited=True, org_spf_state="-all"), 0)
        self.assertEqual(spoof(record, None, None, inherited=True), 8)  # No SPF | p=reject, sp=none

    def test_np_applies_to_a_nonexistent_domain(self):
        record = "v=DMARC1; p=reject; sp=none; np=reject"
        self.assertEqual(spoof(record, inherited=True, org_spf_state="-all"), 0)
        self.assertEqual(spoof(record, inherited=True, org_spf_state="-all", domain_exists=False), 8)

    def test_spoofing_possible_flag(self):
        s = Spoofing("example.com", "v=DMARC1; p=none; sp=reject", "none", None,
                     "v=spf1 ~all", "~all", 0, "reject", None)
        self.assertEqual((s.spoofable, s.spoofing_possible), (2, True))


class TestCLI(unittest.TestCase):
    def test_worker_errors_do_not_escape(self):
        with mock.patch.object(spoofy, "process_domain", side_effect=RuntimeError("boom")):
            result = spoofy.safe_process_domain("example.com")
        self.assertEqual((result["SPOOFING_CODE"], result["ERROR"]), (9, "RuntimeError: boom"))

    def test_result_is_json_serializable(self):
        fake = FakeResolver(
            {
                "example.com": ["v=spf1 -all"],
                "_dmarc.example.com": ["v=DMARC1; p=reject"],
                "default._bimi.example.com": ["v=BIMI1; l=https://example.com/logo.svg; a="],
            }
        )
        with mock.patch.object(spoofy, "get_resolver", return_value=fake):
            result = spoofy.process_domain("example.com")
        json.dumps(result)
        self.assertEqual((result["BIMI_LOCATION"], result["SPOOFING_CODE"]),
                         ("https://example.com/logo.svg", 8))

    def test_inherited_record_judged_with_parent_spf_end_to_end(self):
        fake = FakeResolver(
            {
                "example.com": ["v=spf1 -all"],
                "_dmarc.example.com": ["v=DMARC1; p=reject; sp=none"],
            },
            {("mail.example.com", "A"): DNSResult("ok", ("192.0.2.1",))},
        )
        with mock.patch.object(spoofy, "get_resolver", return_value=fake):
            result = spoofy.process_domain("mail.example.com")
        self.assertEqual((result["DMARC_RECORD_DOMAIN"], result["SPOOFING_CODE"]), ("example.com", 0))

    def test_domain_list_normalization(self):
        path = os.path.join(os.path.dirname(__file__), ".test_domains.txt")
        with open(path, "w") as f:
            f.write("Example.com\n\nhttps://example.com/path\nexample.org. # comment\n# only comment\n")
        try:
            args = SimpleNamespace(d=None, iL=path)
            self.assertEqual(spoofy.read_domains(args), ["example.com", "example.org"])
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
