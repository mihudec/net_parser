import pathlib
import re
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
        return self.TEST_CLASS(
            self.RESOURCES_DIR.joinpath(self.VENDOR).joinpath('data').joinpath('test_load_01.txt'),
            verbosity=VERBOSITY
        )

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

    def test_hostname(self):
        config = self.get_config()
        config.parse()
        self.assertIsInstance(config.hostname, str)

    def test_interfaces(self):
        config = self.get_config()
        config.parse()

    def test_interface_01(self):
        data_path, results_path = self.get_test_resources(test_name='interface_01')
        config = self.TEST_CLASS(config=data_path, verbosity=VERBOSITY)
        config.parse()
        interface_lines = list(config.interface_lines)
        for i in interface_lines:
            i.isis
        interfaces_models = list(config.interfaces)


class TestIosInterfaceParser(BaseNetParserTest):

    VENDOR = "ios"

    def test_ospf_01(self):
        data_path, results_path = self.get_test_resources(test_name='interface_ospf_01')
        config = IosConfigParser(config=data_path, verbosity=VERBOSITY)
        config.parse()
        want = self.load_resource_yaml(path=results_path)
        have = [x.serial_dict(exclude_none=True) for x in config.interfaces]
        self.assertEqual(want, have)


class TestIosAaaParser(BaseNetParserTest):

    VENDOR = "ios"

    def test_load_aaa_01(self):
        data_path, results_path = self.get_test_resources(test_name='aaa_config-01')
        config = IosConfigParser(config=data_path, verbosity=VERBOSITY)
        config.parse()

del BaseNetParserTest

if __name__ == '__main__':
    unittest.main()