import unittest
from tests import BaseNetParserTest

from net_parser.config.FortiGateConfigParser import *
from net_parser.utils import ObjectQuery


SAMPLE_CONFIG = """
config firewall address
  edit "Service-01"
    set subnet 1.1.1.1/32
    set comment "Cloudflare-DNS"
  next
end
"""

TEST_CONFIG = FortiGateConfigParser(config=SAMPLE_CONFIG, verbosity=5)




class BaseFortiGateTest(BaseNetParserTest):

    pass

class TestFortiGateServiceCustom(BaseFortiGateTest):

    
    def test_01(self):
        ObjectQuery

        TEST_CONFIG = FortiGateConfigParser(config=SAMPLE_CONFIG, verbosity=5)
        TEST_CONFIG.parse()
        print(list(TEST_CONFIG.firewall_addresses()))


if __name__ == "__main__":
    unittest.main()
