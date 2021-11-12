
from pydantic.typing import (Union, List, Dict)
from nuaal.Parsers import CiscoIOSParser


from net_parser.utils import get_logger
from net_parser.ops.models import *


from net_parser.ops import OpsParser


class IosOpsParser(OpsParser, vendor='ios'):

    LEGACY_PARSER = CiscoIOSParser()

    @classmethod
    def translate_legacy_keys(cls, results: List[Dict], translate_mapping: Dict):
        translated_results = [{translate_mapping[k]: v for k,v in x.items() if k in translate_mapping.keys()} for x in results]
        return translated_results

    @classmethod
    def nuaal_parse(cls, text: str):
        results = cls.LEGACY_PARSER.autoparse(text=text, command=cls.commands[0])
        return results

    @classmethod
    def parse(cls, text: str):
        return cls.nuaal_parse(text=text)


class IosCdpNeighborsParser(IosOpsParser, vendor='ios', commands=['show cdp neighbors detail']):

    MODEL = NeighborOpsModel
    LEGACY_MAPPING = {
        'hostname': 'hostname',
        'ipAddress': 'ipv4_address',
        'platform': 'platform',
        'capabilities': 'capabilities',
        'vendor': 'vendor',
        'software': 'sw_family',
        'version': 'sw_version',
        'localInterface': 'local_interface',
        'remoteInterface': 'remote_interface'
    }

    @classmethod
    def parse(cls, text: str) -> List[NeighborOpsModel]:
        results = cls.nuaal_parse(text=text)
        results = cls.translate_legacy_keys(results=results, translate_mapping=cls.LEGACY_MAPPING)
        for entry in results:
            entry.update({'protocol': 'cdp'})
        return [cls.MODEL.parse_obj(x) for x in results]



class IosInterfaceParser(IosOpsParser, vendor='ios', commands=['show interfaces']):

    MODEL = InterafceOpsModel
    LEGACY_MAPPING = {
        'name': 'name',
        'description': 'description',
        # '$1': 'enabled',
        'status': 'status',
        'lineProtocol': 'protocol_status',
    }

    @classmethod
    def parse(cls, text: str) -> List[NeighborOpsModel]:
        results = cls.nuaal_parse(text=text)
        results = cls.translate_legacy_keys(results=results, translate_mapping=cls.LEGACY_MAPPING)
        return [cls.MODEL.parse_obj(x) for x in results]



