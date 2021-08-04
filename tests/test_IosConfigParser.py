import pathlib
import unittest
from tests import BaseNetParserTest

from net_parser.config import BaseConfigParser, IosConfigParser, BaseConfigLine
VERBOSITY = 5

class TestIosConfigParserLoading(BaseNetParserTest):

    VENDOR = 'ios'
    TEST_CLASS = IosConfigParser

    def test_load_path(self):
        path = self.RESOURCES_DIR.joinpath(self.VENDOR).joinpath('data').joinpath('test_load_01.txt')
        config = self.TEST_CLASS(config=path, verbosity=VERBOSITY)
        config.parse()

    def test_load_string_path(self):
        path = self.RESOURCES_DIR.joinpath(self.VENDOR).joinpath('data').joinpath('test_load_01.txt')
        config = self.TEST_CLASS(config=str(path), verbosity=VERBOSITY)
        config.parse()

    def test_load_string_config(self):
        path = self.RESOURCES_DIR.joinpath(self.VENDOR).joinpath('data').joinpath('test_load_01.txt')
        config = self.TEST_CLASS(config=path.read_text())
        config.parse()

    def test_load_string_list(self):
        path = self.RESOURCES_DIR.joinpath(self.VENDOR).joinpath('data').joinpath('test_load_01.txt')
        config = self.TEST_CLASS(config=path.read_text().split('\n'), verbosity=VERBOSITY)
        config.parse()

    def test_load_single_line_config(self):
        config = self.TEST_CLASS(config="! This might be a config but not a path")
        config.parse()

    def test_load_nonexistent_path(self):
        path = pathlib.Path('/path/does/not/exist.txt')
        config = self.TEST_CLASS(config=path, verbosity=VERBOSITY)
        with self.assertRaises(FileNotFoundError):
            config.parse()


class TestIosConfigParser(BaseNetParserTest):

    TEST_CLASS = IosConfigParser
    VENDOR = "ios"

    def get_config(self) -> IosConfigParser:
        return self.TEST_CLASS(self.RESOURCES_DIR.joinpath(self.VENDOR).joinpath('data').joinpath('test_load_01.txt'))

    def test_find_objects_01(self):
        config = self.get_config()
        config.parse()
        candidates = config.find_objects(regex=r'^hostname (?P<hostname>.*)')
        self.assertIsInstance(candidates, list)
        self.assertEqual(len(candidates), 1)
        self.assertIsInstance(candidates[0], BaseConfigLine)

    def test_find_objects_01(self):
        config = self.get_config()
        config.parse()
        candidates = config.find_objects(regex=r'^hostname (?P<hostname>.*)', group=1)
        self.assertIsInstance(candidates, list)
        self.assertEqual(len(candidates), 1)
        self.assertIsInstance(candidates[0], str)


class TestIosInterfaceParser(BaseNetParserTest):
    pass


del BaseNetParserTest

if __name__ == '__main__':
    unittest.main()