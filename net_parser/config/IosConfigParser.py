import dataclasses
import re
import pathlib
import timeit
from typing import Union, List, Generator

from net_models.models.interfaces.InterfaceModels import InterfaceModel
from net_models.models import VRFModel


from net_parser.config import (
    BaseConfigParser, BaseConfigLine,
    IosConfigParser, IosInterfaceParser, IosAaaParser, IosVrfDefinitionParser
)


@dataclasses.dataclass
class IosConfigDefaults:

    INTERFACES_DEFAULT_NO_SHUTDOWN: bool = None
    INTERFACES_DEFAULT_CDP_ENABLED: bool = None
    INTERFACES_DEFAULT_LLDP_ENABLED: bool = None

class IosConfigParser(BaseConfigParser):

    INTERFACE_LINE_CLASS = IosInterfaceParser

    _hostname_regex = re.compile(pattern=r"^hostname (?P<hostname>\S+)\Z")

    def __init__(self, config: Union[pathlib.Path, List[str], str], verbosity: int =4, name: str = "BaseConfigParser", **kwargs):
        super().__init__(config=config, verbosity=verbosity, name="IosConfigParser", **kwargs)
        self.DEFAULTS = IosConfigDefaults()


    def _create_cfg_line_objects(self):
        """
        Function for generating ``self.lines``.

        """
        start = timeit.default_timer()
        for number, text in enumerate(self.config_lines_str):
            if re.match(pattern=r"^interface\s\S+", string=text, flags=re.MULTILINE):
                self.lines.append(IosInterfaceParser(number=number, text=text, config=self, verbosity=self.verbosity).return_obj())
            elif re.match(pattern=r"^aaa.*", string=text, flags=re.MULTILINE):
                self.lines.append(IosAaaParser(number=number, text=text, config=self, verbosity=self.verbosity).return_obj())
            elif re.match(pattern=r"^vrf definition .*", string=text, flags=re.MULTILINE):
                self.lines.append(IosVrfDefinitionParser(number=number, text=text, config=self, verbosity=self.verbosity).return_obj())
            else:
                self.lines.append(BaseConfigLine(number=number, text=text, config=self, verbosity=self.verbosity).return_obj())
        for line in self.lines:
            line.type = line.get_type
        self.logger.debug(msg="Created {} ConfigLine objects in {} ms.".format(len(self.lines), (timeit.default_timer()-start)*1000))

    @property
    def hostname(self):
        candidates = self.find_objects(regex=self._hostname_regex, group="hostname")
        return self.first_candidate_or_none(candidates=candidates)



    @property
    def interface_lines(self) -> Generator[IosInterfaceParser, None, None]:
        return (x for x in self.lines if 'interface' in x.get_type)

    @property
    def interfaces(self) -> Generator[InterfaceModel, None, None]:
        return (x.to_model() for x in self.interface_lines)

    @property
    def vrf_definition_lines(self) -> Generator[IosVrfDefinitionParser, None, None]:
        return (x for x in self.lines if isinstance(x, IosVrfDefinitionParser))

    @property
    def vrfs(self) -> Generator[VRFModel, None, None]:
        return (x.model for x in self.vrf_definition_lines)

    @property
    def routing(self):
        raise NotImplementedError

    def __repr__(self):
        return f"[IosConfigParser - {len(self.lines)} lines]"

    def __str__(self):
        return self.__repr__()