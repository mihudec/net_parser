import re
from pydantic.typing import List
from net_parser.ops import OpsParser
from net_parser.ops.models import *


class FortinetOpsParser(OpsParser, vendor='fortinet'):

    @classmethod
    def __new__(cls, *args, **kwargs):
        return super().__new__(vendor='fortinet', *args, **kwargs)

    @classmethod
    def parse(cls, text: str):
        raise NotImplementedError

    @classmethod
    def get_parser(cls, command: str) -> 'FortinetOpsParser':
        for parser_class, commands in cls._registry[cls.vendor].items():
            if command in commands:
                return parser_class

    @staticmethod
    def filter_valid_keys(data: dict, model: Type[BaseOpsModel]):
        return {k: v for k, v in data.items() if k in model.__fields__}


class FortinetRoutingTableParser(FortinetOpsParser, vendor='fortinet', commands=['get router info routing-table all']):

    @classmethod
    def parse(cls, text: str) -> List[RouteV4OpsModel]:
        pattern = re.compile(
            pattern=r'^(?P<protocol>[A-Z]+)(?:.*?\s)(?P<prefix>\S+)\s(?:\[((?P<distance>\d+)/(?P<metric>\d+))\] via (?P<nexthop>\S+?), |(?:is directly connected, ))(?P<interface>\S+?)(?:$|, (?P<age>\S+)$)',
            flags=re.MULTILINE)
        entries = []
        for m in pattern.finditer(string=text):
            data = cls.build_entry(match=m)
            nexthops = []
            if data['nexthop'] is not None:
                nexthop = NextHopV4OpsModel.parse_obj(cls.filter_valid_keys(data=data, model=NextHopV4OpsModel))
                nexthops.append(nexthop)
            data['nexthops'] = nexthops
            route = RouteV4OpsModel.parse_obj(cls.filter_valid_keys(data=data, model=RouteV4OpsModel))
            entries.append(route)
        return entries


class FortinetInterfaceParser(FortinetOpsParser, vendor='fortinet', commands=['get system interface']):

    @classmethod
    def parse(cls, text: str):
        super().parse()




