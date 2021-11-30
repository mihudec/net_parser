import re
import pathlib
import unittest

from net_parser.config import BaseConfigParser, ConfigDiff, IosConfigDiff, IosConfigParser

from tests import RESOURCES_DIR

VERBOSITY = 4

class TestConfigDiff(unittest.TestCase):

    TEST_CLASS = ConfigDiff

    def test_toplevel_01(self):
        first = BaseConfigParser(config=RESOURCES_DIR.joinpath('ios').joinpath('data').joinpath('sample_config_01.txt'))
        first.parse()
        second = BaseConfigParser(
            config=[
                "interface Vlan1",
                " description Test Interface Vlan1",
                " ip address 192.0.2.1 255.255.255.0",
                "interface GigabitEthernet0",
                " no cdp enable",
                "router ospf 1",
                " network 192.0.2.0 0.0.0.255 area0",
                "router bgp 65535",
                " neighbor 192.0.2.3 remote-as 65535",
                " address-family vpnv4",
                "  neighbor 192.0.2.3 activate",
                " exit-address-family"

            ]
        )
        second.parse()

        diff = ConfigDiff(first=first, second=second, verbosity=VERBOSITY, device_type='cisco_ios')
        with self.subTest(msg="Assert is propper instance"):
            self.assertIsInstance(diff, IosConfigDiff)
        print(diff)
        diff_lines = diff.difference()
        diff.print_diff(diff_lines)
        print(diff.get_update_config(diff_lines))

    def test_toplevel_temp(self):
        first = BaseConfigParser(config=RESOURCES_DIR.joinpath('ios').joinpath('data').joinpath('sample_config_temp.txt'))
        first.parse()
        second = BaseConfigParser(
            config=[
                "interface GigabitEthernet0",
                " shutdown",
                " no cdp enable"

            ]
        )
        second.parse()

        diff = ConfigDiff(first=first, second=second, verbosity=VERBOSITY, device_type='cisco_ios')
        with self.subTest(msg="Assert is propper instance"):
            self.assertIsInstance(diff, IosConfigDiff)
        print(diff)
        diff_lines = diff.difference()
        diff.print_diff(diff_lines)
        print(diff.get_update_config(diff_lines))

    def get_host_by_name(self, host_name):
        present = pathlib.Path(r'C:\SHARE\tsdr_conf\2021-03-08').joinpath(f"{host_name}.conf")
        wanted = pathlib.Path(r'C:\Users\mhudec\Develop\GitHub\tsdr_inventory_loader\config').joinpath(f"{host_name}.conf")
        present, wanted = [BaseConfigParser(config=x, verbosity=5) for x in [present, wanted]]
        [x.parse() for x in [present, wanted]]
        return present, wanted


if __name__ == '__main__':
    unittest.main()