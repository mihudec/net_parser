import pathlib
import unittest
from net_parser.utils.common import (check_path, load_text, re_search_lines, raw_match_lines)
from net_parser.utils.get_logger import get_logger
from net_parser.exceptions import *

from net_parser.config import BaseConfigParser

from tests import RESOURCES_DIR, BaseNetParserTest

TEST_LOGGER = get_logger(name="TEST-LOGGER", verbosity=5)

class TestCheckPath(unittest.TestCase):


    def test_invalid_path_01(self):
        with self.assertRaises(expected_exception=FileNotFoundError):
            check_path(path=r"This is not a valid path.txt", logger=TEST_LOGGER)

    def test_invalid_path_02(self):
        with self.assertRaises(expected_exception=FileNotFoundError):
            check_path(path=r"\nonexistent.txt", logger=TEST_LOGGER)

    def test_invalid_path_03(self):
        with self.assertRaises(expected_exception=(InvalidPathSyntax, FileNotFoundError)):
            check_path(
                path="This is not\n"
                     "a\n"
                     "valid path",
                logger=TEST_LOGGER
            )

    def test_valid_path_01(self):
        path = check_path(
            path=RESOURCES_DIR.joinpath('ios').joinpath('data').joinpath('test_load_01.txt'),
            logger=TEST_LOGGER
        )
        self.assertIsInstance(path, pathlib.Path)

    def test_valid_path_02(self):
        path = check_path(
            path=str(RESOURCES_DIR.joinpath('ios').joinpath('data').joinpath('test_load_01.txt')),
            logger=TEST_LOGGER
        )
        self.assertIsInstance(path, pathlib.Path)


class TestLoadText(unittest.TestCase):

    def test_load_singleline(self):
        lines = load_text(obj="Singleline string", logger=TEST_LOGGER)
        self.assertIsInstance(lines, list)
        self.assertEqual(len(lines), 1)

    def test_load_multiline(self):
        with self.subTest(msg="Simple Multilile"):
            lines = load_text(obj="Multiline\nstring", logger=TEST_LOGGER)
            self.assertIsInstance(lines, list)
            self.assertEqual(len(lines), 2)
        with self.subTest(msg="Long multiline"):
            multiline_string = "\n".join(['abc'] * 10000)
            lines = load_text(obj=multiline_string, logger=TEST_LOGGER)

    def test_load_valid_list(self):
        test_lines = [
            "interface Loopback0",
            " description Test"
        ]
        lines = load_text(obj=test_lines, logger=TEST_LOGGER)
        self.assertIsInstance(lines, list)
        self.assertEqual(len(lines), 2)

    def test_load_invalid_list(self):
        test_lines = [
            "interface Loopback0",
            0,
            None
        ]
        with self.assertRaises(expected_exception=AssertionError):
            lines = load_text(obj=test_lines, logger=TEST_LOGGER)


    def test_load_valid_path(self):
        lines = load_text(
            obj=RESOURCES_DIR.joinpath('ios').joinpath('data').joinpath('test_load_01.txt'),
            logger=TEST_LOGGER
        )
        self.assertIsInstance(lines, list)

    def test_load_valid_path_str(self):
        lines = load_text(
            obj=str(RESOURCES_DIR.joinpath('ios').joinpath('data').joinpath('test_load_01.txt')),
            logger=TEST_LOGGER
        )
        self.assertIsInstance(lines, list)
        self.assertTrue(len(lines) > 0)

    def test_load_invalid_path(self):
        with self.assertRaises(expected_exception=FileNotFoundError):
            lines = load_text(
                obj=pathlib.Path("nonexistent\path"),
                logger=TEST_LOGGER
            )



class CommonUtilsTest(unittest.TestCase):

    SAMPLE_CONFIG = BaseConfigParser(config=RESOURCES_DIR.joinpath('ios').joinpath('data').joinpath('sample_config_01.txt'))
    SAMPLE_CONFIG.parse()


class TestReSearchLines(CommonUtilsTest):

    def test_re_search_lines(self):

        lines = re_search_lines(lines=self.SAMPLE_CONFIG.lines, regex=r"interface Vlan1")
        want = [x for x in self.SAMPLE_CONFIG.lines if x.text == "interface Vlan1"][0]
        have = lines[0]
        self.assertTrue(want is have)


class TestRawMatchLines(CommonUtilsTest):

    def test_raw_match_lines(self):

        lines = raw_match_lines(lines=self.SAMPLE_CONFIG.lines, text=r"interface Vlan1")
        want = "interface Vlan1"
        have = lines[0].text
        self.assertEqual(want, have)


if __name__ == '__main__':
    unittest.main()