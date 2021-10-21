
from pydantic.typing import (
    Dict, List, Literal, Optional, Union, Type
)

from net_parser.utils import get_logger
from net_parser.config import BaseConfigParser, BaseConfigLine

class ConfigDiff:

    def __init__(self,
                 first: Type[BaseConfigParser],
                 second: Type[BaseConfigParser],
                 verbosity: int = 4):
        self.logger = get_logger(name='ConfigDiff', verbosity=verbosity)
        self.first = first
        self.second = second

    def _check_configs(self):
        for i, config in enumerate([self.first, self.second]):
            if not isinstance(config, BaseConfigParser):
                msg = f"Config {'first' if i == 0 else 'second'} has to be an instance of 'BaseConfigParser', got {type(self.first)=}"
                self.logger.critical(msg=msg)
                raise TypeError(msg)

    def diff(self):
        raise NotImplementedError