import re

from . import BaseConfigParser
from . import IosInterfaceParser

class IosConfigParser(BaseConfigParser):

    INTERFACE_LINE_CLASS = IosInterfaceParser

    _hostname_regex = re.compile(pattern=r"^hostname (?P<hostname>\S+)\Z")

    @property
    def hostname(self):
        raise NotImplementedError

    @property
    def interfaces(self):
        raise NotImplementedError

    @property
    def routing(self):
        raise NotImplementedError

    def __repr__(self):
        return f"[IosConfigParser - {len(self.lines)} lines]"

    def __str__(self):
        return self.__repr__()