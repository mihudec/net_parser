import pathlib
import re
import unittest
from tests import BaseNetParserTest


from net_models.models.interfaces.InterfaceCommon import *
from net_models.models.interfaces.L3InterfaceModels import *
from net_models.models.interfaces.SpModels import *
from net_models.models.services.ServerModels import *

from net_parser.config import BaseConfigParser, IosConfigParser, BaseConfigLine, IosInterfaceParser, IosServiceInstance
from net_models.inventory import ConfigDefaults
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


    def test_get_formal_config(self):
        config = self.TEST_CLASS(
            config=self.RESOURCES_DIR.joinpath('ios_xr').joinpath('data').joinpath('isis_config_01.txt'),
            verbosity=VERBOSITY
        )
        config.parse()
        have = config.get_formal()
        # with self.RESOURCES_DIR.joinpath('ios_xr').joinpath('results').joinpath('isis_config_01.txt').open(mode='w') as f:
        #     f.writelines([f"{x}\n" for x in have])
        want = self.RESOURCES_DIR.joinpath('ios_xr').joinpath('results').joinpath('isis_config_01.txt').read_text().splitlines()
        self.assertEqual(want, have)

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

    def test_global_proxy_arp(self):
        default_config = self.TEST_CLASS(config=[])
        default_config.parse()
        full_default_config = self.TEST_CLASS(config=["no ip arp proxy disable"])
        full_default_config.parse()
        disabled_config = self.TEST_CLASS(config=["ip arp proxy disable"])
        disabled_config.parse()
        self.assertEqual(default_config.proxy_arp_enabled, True)
        self.assertEqual(full_default_config.proxy_arp_enabled, True)
        self.assertEqual(disabled_config.proxy_arp_enabled, False)

    def test_ntp(self):
        data_path, results_path = self.get_test_resources(test_name='ntp-01')
        config = self.TEST_CLASS(config=data_path, verbosity=VERBOSITY)
        config.parse()
        want = NtpConfig.parse_obj(self.load_resource_yaml(path=results_path))
        have = config.ntp
        self.assertEqual(want, have)


    def test_logging(self):
        data_path, results_path = self.get_test_resources(test_name='logging-01')
        config = self.TEST_CLASS(config=data_path, verbosity=VERBOSITY)
        config.parse()
        want = LoggingConfig.parse_obj(self.load_resource_yaml(path=results_path))
        have = config.logging
        print(have.yaml(exclude_none=True))
        self.assertEqual(want, have)

    def test_banner(self):
        test_cases = [
            {
                "test_name": "Singleline-01",
                "config": (
                    "banner motd ^CTest Banner^C"
                ),
                "result": None
            },
            {
                "test_name": "Multiline-01",
                "config": (
                    "banner motd ^CHello\n"
                    "World\n"
                    "^C"
                ),
                "result": None
            },
            {
                "test_name": "Multiline-02",
                "config": (
                    "banner motd ^CHello\n"
                    "World\n"
                    "End^C\n"
                    "banner login ^CWoo\n"
                    "Foo^C\n"
                ),
                "result": None
            }
        ]
        for test_case in test_cases:
            with self.subTest(msg=test_case['test_name']):
                config = IosConfigParser(config=test_case['config'])
                config.parse()
                print(config.banner)
                #TODO: Make proper evaluation

    def test_password_encryption(self):
        test_cases = [
            {
                "test_name": "Default",
                "config": (
                    "!"
                ),
                "result": False

            },
            {
                "test_name": "Disabled",
                "config": (
                    "no service password-encryption"
                ),
                "result": False

            },
            {
                "test_name": "Enabled",
                "config": (
                    "service password-encryption"
                ),
                "result": True

            }

        ]
        for test_case in test_cases:
            with self.subTest(msg=test_case['test_name']):
                config = IosConfigParser(config=test_case['config'])
                config.parse()
                want = test_case['result']
                have = config.password_encryption_enabled
                print(have)
                self.assertEqual(want, have)

    def test_pad(self):
        test_cases = [
            {
                "test_name": "Default",
                "config": (
                    "!"
                ),
                "result": True

            },
            {
                "test_name": "Disabled",
                "config": (
                    "no service pad"
                ),
                "result": False

            },
            {
                "test_name": "Enabled",
                "config": (
                    "service pad"
                ),
                "result": True

            }

        ]
        for test_case in test_cases:
            with self.subTest(msg=test_case['test_name']):
                config = IosConfigParser(config=test_case['config'])
                config.parse()
                want = test_case['result']
                have = config.service_pad_enabled
                print(have)
                self.assertEqual(want, have)

    def test_ip_finger(self):
        test_cases = [
            {
                "test_name": "Default",
                "config": (
                    "!"
                ),
                "result": True

            },
            {
                "test_name": "Disabled",
                "config": (
                    "no ip finger"
                ),
                "result": False

            },
            {
                "test_name": "Enabled",
                "config": (
                    "ip finger"
                ),
                "result": True

            }

        ]
        for test_case in test_cases:
            with self.subTest(msg=test_case['test_name']):
                config = IosConfigParser(config=test_case['config'])
                config.parse()
                want = test_case['result']
                have = config.ip_finger_enabled
                print(have)
                self.assertEqual(want, have)



class TestIosInterfaceParser(BaseNetParserTest):

    VENDOR = "ios"
    TEST_CLASS = IosConfigParser

    def test_ospf_01(self):
        data_path, results_path = self.get_test_resources(test_name='interface_ospf_01')
        config = IosConfigParser(config=data_path, verbosity=VERBOSITY)
        config.parse()
        want = self.load_resource_yaml(path=results_path)
        have = [x.serial_dict(exclude_none=True) for x in config.interfaces]
        self.assertEqual(want, have)

    def test_is_routed_or_switched(self):
        config_lines = [
            "interface Loopback0",
            " no ip address",
            "interface Vlan100",
            " ip address 192.168.100.1 255.255.255.0",

        ]
        want = {
            "Loopback0": True,
            "Vlan100": True
        }
        config = IosConfigParser(config=config_lines, verbosity=VERBOSITY)
        config.parse()
        for interface_name, result in want.items():
            interface = config.get_interface_line(interface_name=interface_name)
            self.assertEqual(interface.is_routed, result)
            self.assertEqual(interface.is_switched, not result)

    def test_switchport_mode(self):
        config_lines = [
            "interface GigabitEthernet1/0/1",
            " switchport mode access",
            "interface TenGigabitEthernet1/0/1",
            " switchport mode trunk",
        ]
        config = IosConfigParser(config=config_lines)
        config.parse()
        access_interface = [x for x in config.interface_lines if x.name == "GigabitEthernet1/0/1"][0]
        trunk_interface = [x for x in config.interface_lines if x.name == "TenGigabitEthernet1/0/1"][0]
        self.assertEqual(access_interface.switchport_mode, 'access')
        self.assertEqual(trunk_interface.switchport_mode, 'trunk')

    def test_switchport_nonegotiate(self):
        config_lines = [
            "interface GigabitEthernet1/0/1",
            " switchport mode access",
            "interface TenGigabitEthernet1/0/1",
            " switchport mode trunk",
            " switchport nonegotiate"
        ]
        config = IosConfigParser(config=config_lines)
        config.parse()
        access_interface = [x for x in config.interface_lines if x.name == "GigabitEthernet1/0/1"][0]
        trunk_interface = [x for x in config.interface_lines if x.name == "TenGigabitEthernet1/0/1"][0]
        self.assertEqual(access_interface.switchport_negotiation, True)
        self.assertEqual(trunk_interface.switchport_negotiation, False)

    def test_access_vlan(self):
        config_lines = [
            "interface GigabitEthernet1/0/1",
            " switchport access vlan 10"
        ]
        config = IosConfigParser(config=config_lines)
        config.parse()
        interface_line = [x for x in config.interface_lines if x.name == "GigabitEthernet1/0/1"][0]
        self.assertEqual(interface_line.access_vlan, 10)

    def test_voice_vlan(self):
        config_lines = [
            "interface GigabitEthernet1/0/1",
            " switchport voice vlan 10"
        ]
        config = IosConfigParser(config=config_lines)
        config.parse()
        interface_line = [x for x in config.interface_lines if x.name == "GigabitEthernet1/0/1"][0]
        self.assertEqual(interface_line.voice_vlan, 10)

    def test_trunk_allowed_vlans(self):
        config_lines = [
            "interface Port-channel1",
            " switchport trunk allowed vlan 10-20,21,22",
            " switchport trunk allowed vlan add 30-35,40-50"
        ]
        config = IosConfigParser(config=config_lines)
        config.parse()
        interface_line = [x for x in config.interface_lines if x.name == "Port-channel1"][0]
        want = [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 30, 31, 32, 33, 34, 35, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50]
        have = interface_line.trunk_allowed_vlans
        self.assertEqual(want, have)

    def test_mtu(self):
        config_lines = [
            "interface TenGigabitEthernet1/0/1",
            " mtu 9000"
        ]
        config = IosConfigParser(config=config_lines)
        config.parse()
        interface_line = [x for x  in config.interface_lines if x.name == "TenGigabitEthernet1/0/1"][0]
        want = 9000
        have = interface_line.mtu
        self.assertEqual(want, have)

    def test_ip_mtu(self):
        config_lines = [
            "interface TenGigabitEthernet1/0/1",
            " ip mtu 9000"
        ]
        config = IosConfigParser(config=config_lines)
        config.parse()
        interface_line = [x for x  in config.interface_lines if x.name == "TenGigabitEthernet1/0/1"][0]
        want = 9000
        have = interface_line.ip_mtu
        self.assertEqual(want, have)

    def test_isis(self):
        config_lines = [
            "interface TenGigabitEthernet1/0/1",
            " ip router isis test",
            " isis circuit-type level-2-only",
            " isis network point-to-point",
            " isis metric 10 level-1",
            " isis metric 10 level-2",
            " isis authentication mode md5",
            " isis authentication key-chain ISIS-KEY"
        ]
        config = IosConfigParser(config=config_lines)
        config.parse()
        interface_line = [x for x  in config.interface_lines if x.name == "TenGigabitEthernet1/0/1"][0]
        want = InterfaceIsisConfig(
            process_id='test',
            network_type='point-to-point',
            circuit_type='level-2-only',
            authentication=IsisInterfaceAuthentication(
                mode='md5',
                keychain='ISIS-KEY'
            ),
            metric=[
                IsisMetricField(level='level-1', metric=10),
                IsisMetricField(level='level-2', metric=10),
            ]
        )
        have = interface_line.isis
        self.assertEqual(want, have)

    def test_service_policy(self):
        config_lines = [
            "interface Port-channel1",
            " service-policy input PM-IN",
            " service-policy output PM-OUT",
        ]
        config = IosConfigParser(config=config_lines)
        config.parse()
        interface_line = [x for x in config.interface_lines if x.name == "Port-channel1"][0]
        want = InterfaceServicePolicy(input='PM-IN', output='PM-OUT')
        have = interface_line.service_policy
        self.assertEqual(want, have)


    def test_hsrp(self):
        data_path, results_path = self.get_test_resources(test_name='interface_hsrp_01')
        config = IosConfigParser(config=data_path, verbosity=VERBOSITY)
        config.parse()

        want = self.load_resource_yaml(path=results_path)
        want = InterfaceHsrp.parse_obj(want)
        have = config.get_interface_line(interface_name="Vlan1").hsrp
        self.assertEqual(want, have)


    def test_proxy_arp(self):
        config_1 = IosConfigParser(config=["interface Vlan1"], verbosity=VERBOSITY)
        config_1.parse()
        interface = config_1.get_interface_line(interface_name="Vlan1")
        with self.subTest(msg="All Default"):
            self.assertEqual(interface.proxy_arp_enabled, True)
        config_2 = IosConfigParser(config=["interface Vlan1", " no ip proxy-arp"], verbosity=VERBOSITY)
        config_2.parse()
        interface = config_2.get_interface_line(interface_name="Vlan1")
        with self.subTest(msg="Interface Disabled"):
            self.assertEqual(interface.proxy_arp_enabled, False)
        config_3 = IosConfigParser(config=["ip arp proxy disable", "interface Vlan1",], verbosity=VERBOSITY)
        config_3.parse()
        interface = config_3.get_interface_line(interface_name="Vlan1")
        with self.subTest(msg="Global Disabled"):
            self.assertEqual(interface.proxy_arp_enabled, False)


    def test_service_instances(self):
        data_path = self.RESOURCES_DIR.joinpath(f"{self.VENDOR}/data/interface_service_instance_01.txt")
        config = IosConfigParser(config=data_path, verbosity=VERBOSITY)
        config.parse()
        interface_line = config.lines[0]
        service_instance_lines = interface_line.service_instance_lines
        service_instances = interface_line.service_instances
        for i in service_instances:
            self.assertIsInstance(i, ServiceInstance)


class TestIosServiceInstance(BaseNetParserTest):

    VENDOR = 'ios'
    TEST_CLASS = IosServiceInstance




class TestIosAaaParser(BaseNetParserTest):

    VENDOR = "ios"

    def test_load_aaa_01(self):
        data_path, results_path = self.get_test_resources(test_name='aaa_config-01')
        config = IosConfigParser(config=data_path, verbosity=VERBOSITY)
        config.parse()

del BaseNetParserTest

if __name__ == '__main__':
    unittest.main()