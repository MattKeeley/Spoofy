import unittest
from libs import logic

class TestSpoofy(unittest.TestCase):

    '''
      0: Indicates that spoofing is possible for the domain.
      1: Indicates that subdomain spoofing is possible for the domain.
      2: Indicates that organizational domain spoofing is possible for the domain.
      3: Indicates that spoofing might be possible for the domain.
      4: Indicates that spoofing might be possible (mailbox dependent) for the domain.
      5: Indicates that organizational domain spoofing may be possible for the domain.
      6: Indicates that subdomain spoofing might be possible (mailbox dependent) for the domain.
      7: Indicates that subdomain spoofing is possible, and organizational domain spoofing might be possible.
      8: Indicates that spoofing is not possible for the domain.
    '''

    def test_spoofing_is_possible(self):
        unittest.TestCase().assertEqual(logic.is_spoofable('test_0.com', 'none', 'r', 'v=spf1 include:fake.gov', '~all', 3, None, 100), 0)

    def test_subdomain_spoofing(self):
        unittest.TestCase().assertEqual(logic.is_spoofable("test_1.com", "reject", None, "v=spf1 include:fakest.domain.com", "-all", 3, "none", None), 1)
 
    def test_organizational_domain_spoofing(self):
        unittest.TestCase().assertEqual(logic.is_spoofable('test_2.com', 'none', 'r', 'v=spf1 include:fakest.domain.com include:faker.domain.com', '-all', 2, 'reject', 100), 2)
    
    def test_spoofing_might_be_possible(self):
        unittest.TestCase().assertEqual(logic.is_spoofable('test_3.com', 'none', None, 'v=spf1 include:fakest.domain.com', '~all', 1, 'quarantine', 90), 3)

    def test_spoofing_might_be_possible_mbd(self):
        unittest.TestCase().assertEqual(logic.is_spoofable('test_4.com', 'none', None, 'v=spf1 include:fakest.domain.com', '-all', 1, None, 100), 4)

    def test_org_domain_spoofing_might_be_possible(self):
        unittest.TestCase().assertEqual(logic.is_spoofable('test_5.com', 'none', None, 'v=spf1 include:fakest.domain.com', '-all', 1, 'reject', 100), 5)

    def test_subdomain_spoofing_might_be_possible_mbd(self):
        unittest.TestCase().assertEqual(logic.is_spoofable('test_6.com', 'reject', 'r', 'v=spf1 include:fakest.domain.com', '?all', 1, 'none', 100), 6)

    def test_subdomain_spoofing_and_org_spoofing_might_be_possible(self):
        unittest.TestCase().assertEqual(logic.is_spoofable('test_7.com', 'none', 'none', 'v=spf1 include:fakest.domain.com', '~all', 3, 'none', 100), 7)

    def test_spoofing_not_possible(self):
        unittest.TestCase().assertEqual(logic.is_spoofable('test_8.com', 'none', 's', 'v=spf1 include:fakest.domain.com', '~all', 1, 'quarantine', 100), 8)

    def test_possible_bug_fix1(self):
        unittest.TestCase().assertEqual(logic.is_spoofable('sub.test_9.com', None, None, None, None, None, None, None), 0)

if __name__ == '__main__':
    unittest.main()