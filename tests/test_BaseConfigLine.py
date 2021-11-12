import unittest
from tests import BaseNetParserTest

from net_parser.config import BaseConfigLine, BaseConfigParser

class TestBaseConfigParser(BaseNetParserTest):

    TEST_CLASS = BaseConfigLine
    SAMPLE_CONFIG = BaseConfigParser(config=BaseNetParserTest.RESOURCES_DIR.joinpath('ios').joinpath('data').joinpath('sample_config_01.txt'))
    SAMPLE_CONFIG.parse()

    def test_get_children(self):
        with self.subTest(msg="Interface Vlan1 - Get Children from Interface"):
            parent_line = [x for x in self.SAMPLE_CONFIG if x.text == "interface Vlan1"][0]
            children = parent_line.get_children()
            print(children)
            # self.assertEqual(description_line.parent, interface_line)

        with self.subTest(msg="Router BGP - Get only direct children"):
            parent_line = [x for x in self.SAMPLE_CONFIG if x.text == "router bgp 65535"][0]
            children = parent_line.get_children(max_depth=1)
            for c in children:
                print(c)

    def test_get_parent(self):

        with self.subTest(msg="Interface Vlan1 - Get Parent from description"):
            description_line = [x for x in self.SAMPLE_CONFIG.lines if x.text == " description Test Interface Vlan1"][0]
            interface_line = [x for x in self.SAMPLE_CONFIG.lines if x.text == "interface Vlan1"][0]
            self.assertEqual(description_line.parent, interface_line)

        with self.subTest(msg="Interface Vlan1 - Get All Parents from description"):
            description_line = [x for x in self.SAMPLE_CONFIG.lines if x.text == " description Test Interface Vlan1"][0]
            interface_line = [x for x in self.SAMPLE_CONFIG.lines if x.text == "interface Vlan1"][0]
            self.assertTrue(len(description_line.get_parents()) == 1)
            self.assertEqual(description_line.get_parents()[0], interface_line)

        with self.subTest(msg="Router BGP - Get All Parents from neighbor activate"):
            neighbor_activate_line = [x for x in self.SAMPLE_CONFIG.lines if x.text == "  neighbor 192.0.2.2 activate"][0]
            print(neighbor_activate_line.get_parents())
            # print(neighbor_activate_line.get_line)
            self.assertTrue(len(neighbor_activate_line.get_parents()) == 2)

    def test_get_path(self):
        with self.subTest(msg="Router BGP - Get path from neighbor activate"):
            neighbor_activate_line = [x for x in self.SAMPLE_CONFIG.lines if x.text == "  neighbor 192.0.2.2 activate"][0]
            self.assertEqual(neighbor_activate_line.get_path, ['router bgp 65535', ' address-family vpnv4'])

    def test_get_line(self):
        with self.subTest(msg="Router BGP - Get line from neighbor activate"):
            neighbor_activate_line = [x for x in self.SAMPLE_CONFIG.lines if x.text == "  neighbor 192.0.2.2 activate"][0]
            self.assertEqual(neighbor_activate_line.get_line, ['router bgp 65535', ' address-family vpnv4', '  neighbor 192.0.2.2 activate'])


    def test_get_section_by_parents(self):
        with self.subTest(msg="Router BGP - Get line from neighbor activate"):
            neighbor_activate_line = [x for x in self.SAMPLE_CONFIG.lines if x.text == "  neighbor 192.0.2.2 activate"][0]
            parent_1 = [x for x in self.SAMPLE_CONFIG if x.text == "router bgp 65535"][0]
            parent_2 = [x for x in self.SAMPLE_CONFIG if x.text == " address-family vpnv4" and x.parent == parent_1][0]
            parents = [parent_1, parent_2]
            print(parents)
            print(self.SAMPLE_CONFIG.get_section_by_parents(parents=[x.text for x in parents]))






del BaseNetParserTest

if __name__ == '__main__':
    unittest.main()