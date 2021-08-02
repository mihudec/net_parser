from . import BaseConfigParser
from . import IosInterfaceParser

class IosConfigParser(BaseConfigParser):

    INTERFACE_LINE_CLASS = IosInterfaceParser


    def __repr__(self):
        return f"[IosConfigParser - {len(self.lines)} lines]"

    def __str__(self):
        return self.__repr__()