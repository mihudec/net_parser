import functools
import re

from net_parser.utils import get_logger
from typing import (Union, List, Dict)

class BaseOpsParser(object):

    logger = get_logger(name="BaseOpsParser", verbosity=4)
    VENDOR = None
    COMANDS = []
    PATTER_MAP = {}

    @classmethod
    def update_class_logger(cls, verbosity: int = 4):
        cls.logger = get_logger(name=cls.__name__, verbosity=verbosity)

    @classmethod
    def max_rounds(cls):
        return max(cls.PATTER_MAP.keys())

    @classmethod
    @functools.lru_cache()
    def _get_group_names(cls, pattern: re.Pattern):
        return [x for x in pattern.groupindex.keys() if isinstance(x, str)]

    @classmethod
    def build_entry(cls, match: re.Match):
        entry = None
        if len(match.groupdict().keys()):
            entry = match.groupdict()
        else:
            entry = match.group(0)
        return entry

    @classmethod
    def update_dict(cls, orig: dict, new: dict, overwrite: bool = False):
        result = dict(orig)
        if overwrite:
            result.update({k:v for k, v in new.items() if v is not None})
        else:
            for k, v in new.items():
                if result.get(k) is None:
                    result[k] = v
        return result

    @classmethod
    def match_single_pattern(cls, string: str, pattern: re.Pattern):
        cls.logger.debug(msg=f"Got {pattern.pattern=} to match {string=}")
        group_names = cls._get_group_names(pattern=pattern)
        for m in re.finditer(pattern=pattern, string=string):
            if len(group_names):
                if len(group_names) == 1 and group_names[0] == '_entry':
                    yield m.group('_entry')
                else:
                    yield m.groupdict()
            else:
                yield m.group(0)

    @classmethod
    def match_multi_pattern(cls, text: str, patterns: List[re.Pattern]):
        entry = {}
        for pattern in patterns:
            entry.update({k:None for k in cls._get_group_names(pattern=pattern)})
        # Populate Named Groups
        for pattern in patterns:
            match = pattern.search(string=text)
            if match:
                entry = cls.update_dict(orig=entry, new=match.groupdict())
                if all(entry.values()):
                    cls.logger.debug(msg=f"All fields matched, stopping search.")
                    break
        cls.logger.debug(msg=f"Returning {entry=}")
        return entry


    def __str__(cls):
        return f"[{cls.__class__.__name__}]"

    def __repr__(cls):
        return cls.__str__()


class IosOpsParser(BaseOpsParser):

    VENDOR = 'ios'


class IosCdpNeighborDetailParser(IosOpsParser):

    COMANDS = ['show cdp neighbors detail']
    PATTER_MAP = {
        1: {
            "_entries": [
                re.compile(
                    pattern=r"^(-{10,})\n(?P<_entry>Device ID:(?:.*(?:\r\n|\r|\n))*?(?=\1|\Z))",
                    flags=re.MULTILINE
                )
            ]
        },
        2: {
            "_entry": [
                re.compile(
                    pattern=r"Device ID: (?P<device_id>\S+)",
                    flags=re.MULTILINE
                )
            ]
        },
        3: {
            "device_id": [
                re.compile(
                    pattern="^(?P<hostname>.*?)(?:\.(?P<domain_name>\S+))?$",
                    flags=re.MULTILINE
                )
            ]
        }
    }





