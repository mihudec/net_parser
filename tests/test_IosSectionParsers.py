import pathlib
import re
import unittest
from tests import BaseNetParserTest

from net_models.models.services.cisco_ios.IosLineModels import *
from net_models.models.services.cisco_ios.AaaMethods import *

from net_parser.config import (
    BaseConfigParser, IosConfigParser, BaseConfigLine, IosConfigLine,
    IosVrfDefinitionParser, IosInterfaceParser, IosLoggingLine, IosAaaParser,
    IosLineParser
)


VERBOSITY = 5


class TestIosConfigLine(BaseNetParserTest):

    VENDOR = 'ios'
    TEST_CLASS = IosConfigLine

    def test_return_types(self):
        test_cases = {
            "interface Vlan1": IosInterfaceParser,
            "vrf definition TEST": IosVrfDefinitionParser,
            "ip vrf definition TEST": IosVrfDefinitionParser,
            "logging host 192.0.2.1": IosLoggingLine,
            "aaa authentication login default local": IosAaaParser

        }
        config = IosConfigParser(config=[])
        for text, subclass in test_cases.items():
            line = self.TEST_CLASS(number=1, text=text, config=config)
            with self.subTest(msg=text):
                self.assertIsInstance(line, subclass)


class TestIosVrfDefinitionParser(BaseNetParserTest):

    VENDOR = 'ios'
    TEST_CLASS = IosVrfDefinitionParser

    def test_01(self):
        data_path, results_path = self.get_test_resources(test_name='vrf_definition_01')
        want = self.load_resource_yaml(path=results_path)
        config = IosConfigParser(config=data_path, verbosity=VERBOSITY)
        config.parse()
        have = [x.serial_dict(exclude_none=True) for x in config.vrfs]
        self.assertEqual(want, have)


class TestIosLineParser(BaseNetParserTest):

    VENDOR = 'ios'
    TEST_CLASS = IosLineParser

    def test_line_type_and_range(self):
        test_cases = [
            {
                "test_name": "Test-Console-01",
                "config": "line con 0",
                "result": ['console', [0]]
            },
            {
                "test_name": "Test-Vty-01",
                "config": "line vty 0 4",
                "result": ['vty', [0, 4]]
            },
            {
                "test_name": "Test-Aux-01",
                "config": "line aux 0",
                "result": ['aux', [0]]
            }
        ]
        config = IosConfigParser(config=[])
        config.parse()
        for test_case in test_cases:
            with self.subTest(msg=f"Type_{test_case['test_name']}"):
                line = self.TEST_CLASS(number=1, text=test_case['config'], config=config)
                want = test_case['result'][0]
                have = line.line_type
                self.assertEqual(want, have)
            with self.subTest(msg=f"Range_{test_case['test_name']}"):
                line = self.TEST_CLASS(number=1, text=test_case['config'], config=config)
                want = test_case['result'][1]
                have = line.line_range
                self.assertEqual(want, have)

    def test_exec_timeout(self):
        test_cases = [
            {
                "test_name": "Test-Exec_timeout-01",
                "config": (
                    "line con 0\n"
                    " exec-timeout 10 0"
                ),
                "result": 600
            },
            {
                "test_name": "Test-Exec_timeout-None",
                "config": (
                    "line con 0\n"
                ),
                "result": None
            },
            {
                "test_name": "Test-Exec_timeout-0",
                "config": (
                    "line con 0\n"
                    " exec-timeout 0 0"
                ),
                "result": 0
            }
        ]
        for test_case in test_cases:
            config = IosConfigParser(config=test_case['config'])
            config.parse()
            with self.subTest(msg=f"{test_case['test_name']}"):
                text_line = test_case['config'].split('\n')[0]
                line = [x for x in config.lines if x.text == text_line][0]
                want = test_case['result']
                have = line.exec_timeout
                self.assertEqual(want, have)

    def test_transport(self):
        test_cases = [
            {
                "test_name": "Test-Transport-01",
                "config": (
                    "line vty 0 4\n"
                    " transport input all\n"
                    " transport output none\n"
                    " transport preferred ssh"
                ),
                "result": IosLineTransport(input='all', output='none', preferred='ssh')
            },
            {
                "test_name": "Test-Transport-02",
                "config": (
                    "line vty 0 4\n"
                    " transport input ssh\n"
                ),
                "result": IosLineTransport(input='ssh')
            }
        ]
        for test_case in test_cases:
            config = IosConfigParser(config=test_case['config'])
            config.parse()
            with self.subTest(msg=f"{test_case['test_name']}"):
                text_line = test_case['config'].split('\n')[0]
                line = [x for x in config.lines if x.text == text_line][0]
                want = test_case['result']
                have = line.transport
                self.assertEqual(want, have)


    def test_acl(self):
        test_cases = [
            {
                "test_name": "Test-ACL-01",
                "config": (
                    "line vty 0 4\n"
                    " access-class 1 in\n"
                ),
                "result": [IosLineAccessClass(name=1, direction='in', vrf_also=False)]
            }
        ]
        for test_case in test_cases:
            config = IosConfigParser(config=test_case['config'])
            config.parse()
            with self.subTest(msg=f"{test_case['test_name']}"):
                text_line = test_case['config'].split('\n')[0]
                line = [x for x in config.lines if x.text == text_line][0]
                want = test_case['result']
                have = line.acls
                self.assertEqual(want, have)

    def test_exec_enabled(self):
        test_cases = [
            {
                "test_name": "Test-Exec-enabled-01",
                "config": (
                    "line aux 0\n"
                    " no exec\n"
                ),
                "result": False
            },
            {
                "test_name": "Test-Exec-enabled-02",
                "config": (
                    "line aux 0\n"
                ),
                "result": True
            }
        ]
        for test_case in test_cases:
            config = IosConfigParser(config=test_case['config'])
            config.parse()
            with self.subTest(msg=f"{test_case['test_name']}"):
                text_line = test_case['config'].split('\n')[0]
                line = [x for x in config.lines if x.text == text_line][0]
                want = test_case['result']
                have = line.exec_enabled
                self.assertEqual(want, have)

    def test_aaa(self):
        test_cases = [
            {
                "test_name": "Test-Exec-enabled-01",
                "config": (
                    "line vty 0 4\n"
                    " login authentication TEST\n"
                    " authorization exec TEST\n"
                    " authorization commands 15 TEST\n"
                ),
                "result": IosLineAaaConfig(
                    authentication='TEST',
                    authorization=IosAaaLineAuthorization(
                        exec='TEST',
                        commands=[
                            IosAaaLineCommands(
                                name='TEST',
                                level=15
                            )
                        ]
                    )
                )
            }
        ]
        for test_case in test_cases:
            config = IosConfigParser(config=test_case['config'])
            config.parse()
            with self.subTest(msg=f"{test_case['test_name']}"):
                text_line = test_case['config'].split('\n')[0]
                line = [x for x in config.lines if x.text == text_line][0]
                want = test_case['result']
                have = line.aaa
                print(have.yaml(exclude_none=True))
                self.assertEqual(want, have)

    def test_to_model(self):
        test_cases = [
            {
                "test_name": "Test-Model-01",
                "config": (
                    "line vty 0 4\n"
                    " login authentication TEST\n"
                    " authorization exec TEST\n"
                    " authorization commands 15 TEST\n"
                    " access-class ACL-VTY in vrf-also\n"
                    " transport input ssh\n"
                    " transport output none\n"
                ),
                "result": IosLineConfig(
                    line_type='vty',
                    line_range=[0, 4],
                    aaa_config=IosLineAaaConfig(
                        authentication='TEST',
                        authorization=IosAaaLineAuthorization(
                            exec='TEST',
                            commands=[
                                IosAaaLineCommands(
                                    name='TEST',
                                    level=15
                                )
                            ]
                        )
                    ),
                    access_classes=[
                        IosLineAccessClass(name='ACL-VTY', vrf_also=True, direction='in')
                    ],
                    transport=IosLineTransport(input='ssh', output='none')
                )
            }
        ]
        for test_case in test_cases:
            config = IosConfigParser(config=test_case['config'])
            config.parse()
            with self.subTest(msg=f"{test_case['test_name']}"):
                text_line = test_case['config'].split('\n')[0]
                line = [x for x in config.lines if x.text == text_line][0]
                want = test_case['result']
                have = line.to_model()
                print(have.yaml(exclude_none=True))
                self.assertEqual(want, have)


del BaseNetParserTest

if __name__ == '__main__':
    unittest.main()