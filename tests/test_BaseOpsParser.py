import unittest

from net_parser.ops.BaseOpsParsers import IosCdpNeighborDetailParser

from tests import BaseNetParserTest


class TestBaseOpsParser(BaseNetParserTest):

    pass


class TestCdpNeighborDetailParser(BaseNetParserTest):

    pass

del BaseNetParserTest

if __name__ == '__main__':
    unittest.main()