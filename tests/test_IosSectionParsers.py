import pathlib
import re
import unittest
from tests import BaseNetParserTest

from net_parser.config import (
    BaseConfigParser, IosConfigParser, BaseConfigLine,
    IosVrfDefinitionParser
)

VERBOSITY = 5


class TestIosVrfDefinitionParser(BaseNetParserTest):

    VENDOR = 'ios'
    TEST_CLASS = IosVrfDefinitionParser

    def test_01(self):
        data_path, results_path = self.get_test_resources(test_name='vrf_definition_01')
        want = self.load_resource_yaml(path=results_path)
        config = IosConfigParser(config=data_path, verbosity=VERBOSITY)
        config.parse()
        have = [x.serial_dict(exclude_none=True) for x in config.vrfs]

del BaseNetParserTest

if __name__ == '__main__':
    unittest.main()