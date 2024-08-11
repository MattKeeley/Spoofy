import unittest
from modules.spoofing import Spoofing

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
        spoofing = Spoofing('test_0.com', 'none', 'r', 'v=spf1 include:fake.gov', '~all', 3, None, 100)
        self.assertEqual(spoofing.spoofable, 0)

    def test_subdomain_spoofing(self):
        spoofing = Spoofing("test_1.com", 'reject', None, 'v=spf1 include:fakest.domain.com', '-all', 3, 'none', None)
        self.assertEqual(spoofing.spoofable, 1)
 
    def test_organizational_domain_spoofing(self):
        spoofing = Spoofing('test_2.com', 'none', 'r', 'v=spf1 include:fakest.domain.com include:faker.domain.com', '-all', 2, 'reject', 100)
        self.assertEqual(spoofing.spoofable, 2)
    
    def test_spoofing_might_be_possible(self):
        spoofing = Spoofing('test_3.com', 'none', None, 'v=spf1 include:fakest.domain.com', '~all', 1, 'quarantine', 90)
        self.assertEqual(spoofing.spoofable, 3)

    def test_spoofing_might_be_possible_mbd(self):
        spoofing = Spoofing('test_4.com', 'none', None, 'v=spf1 include:fakest.domain.com', '-all', 1, None, 100)
        self.assertEqual(spoofing.spoofable, 4)

    def test_org_domain_spoofing_might_be_possible(self):
        spoofing = Spoofing('test_5.com', 'none', None, 'v=spf1 include:fakest.domain.com', '-all', 1, 'reject', 100)
        self.assertEqual(spoofing.spoofable, 5)

    def test_subdomain_spoofing_might_be_possible_mbd(self):
        spoofing = Spoofing('test_6.com', 'reject', 'r', 'v=spf1 include:fakest.domain.com', '?all', 1, 'none', 100)
        self.assertEqual(spoofing.spoofable, 6)

    def test_subdomain_spoofing_and_org_spoofing_might_be_possible(self):
        spoofing = Spoofing('test_7.com', 'none', None, 'v=spf1 include:fakest.domain.com', '~all', 3, 'none', 100)
        self.assertEqual(spoofing.spoofable, 7)

    def test_spoofing_not_possible(self):
        spoofing = Spoofing('test_8.com', 'none', 's', 'v=spf1 include:fakest.domain.com', '~all', 1, 'quarantine', 100)
        self.assertEqual(spoofing.spoofable, 8)

    def test_possible_bug_fix1(self):
        spoofing = Spoofing('sub.test_9.com', None, None, None, None, None, None, None)
        self.assertEqual(spoofing.spoofable, 0)

if __name__ == '__main__':
    unittest.main()
