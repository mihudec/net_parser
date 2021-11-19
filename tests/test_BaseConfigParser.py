import unittest
from tests import BaseNetParserTest

from net_parser.config import BaseConfigParser

class TestBaseConfigParser(BaseNetParserTest):

    def test_multiple_parse(self):
        config = [
            '! Just a single line'
        ]
        parser = BaseConfigParser(config=config)
        with self.subTest(msg="Not yet parsed config"):
            self.assertEqual(len(parser.lines), 0)
        with self.subTest(msg="Parsed once"):
            parser.parse()
            self.assertEqual(len(parser.lines), 1)
        with self.subTest(msg="Parsed twice"):
            parser.parse()
            self.assertEqual(len(parser.lines), 1)

del BaseNetParserTest

if __name__ == '__main__':
    unittest.main()