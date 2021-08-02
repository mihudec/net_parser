import pathlib
import unittest
from tests import BaseNetParserTest

from net_parser.config import BaseConfigParser, IosConfigParser
VERBOSITY = 5

class TestIosConfigParser(BaseNetParserTest):

    VENDOR = 'ios'

    def test_load_path(self):
        path = self.RESOURCES_DIR.joinpath(self.VENDOR).joinpath('data').joinpath('test_load_01.txt')
        config = BaseConfigParser(config=path, verbosity=VERBOSITY)
        config.parse()
        print(config.lines)

    def test_load_path(self):
        path = self.RESOURCES_DIR.joinpath(self.VENDOR).joinpath('data').joinpath('test_load_01.txt')
        config = BaseConfigParser(config=str(path), verbosity=VERBOSITY)
        config.parse()
        print(config.lines)

del BaseNetParserTest

if __name__ == '__main__':
    unittest.main()