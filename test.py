import unittest
from libs import logic

class TestSpoofy(unittest.TestCase):
    def test_if_spoofable(self):
        unittest.TestCase().assertEqual(logic.is_spoofable("fireeye.com", "reject", None, "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email include:mktomail.com include:stspg-customer.com -all", "-all", 3, "none", None),1)
        unittest.TestCase().assertEqual(logic.is_spoofable('google.com', 'reject', None, 'v=spf1 include:_spf.google.com ~all', '~all', 4, None, None), 7)

if __name__ == '__main__':
    unittest.main()