import dataclasses
import functools
import re
import pathlib
import timeit
from typing import Union, List, Generator

from net_models.validators import normalize_interface_name
from net_models.models.interfaces.InterfaceModels import InterfaceModel
from net_models.models import VRFModel
from net_models.inventory import HostConfig


from net_parser.config import (
    BaseConfigParser, BaseConfigLine, IosConfigLine,
    IosConfigParser, IosInterfaceParser, IosAaaParser, IosVrfDefinitionParser
)


@dataclasses.dataclass
class IosConfigDefaults:

    INTERFACES_DEFAULT_NO_SHUTDOWN: bool = None
    INTERFACES_DEFAULT_CDP_ENABLED: bool = None
    INTERFACES_DEFAULT_LLDP_ENABLED: bool = None

class IosConfigParser(BaseConfigParser):

    INTERFACE_LINE_CLASS = IosInterfaceParser
    CONFIG_LINE_CLS = IosConfigLine

    _hostname_regex = re.compile(pattern=r"^hostname (?P<hostname>\S+)\Z")
    _ip_arp_proxy_disable_regex = re.compile(pattern=r"^(?:(?P<no>no) )?ip arp proxy disable$", flags=re.MULTILINE)
    _service_password_encryption_regex = re.compile(pattern=r"^(?:(?P<no>no) )?service password-encryption$", flags=re.MULTILINE)
    _banner_regex = re.compile(pattern=r"^banner (?P<banner_type>\S+)")

    def __init__(self, config: Union[pathlib.Path, List[str], str], verbosity: int =4, name: str = "BaseConfigParser", **kwargs):
        super().__init__(config=config, verbosity=verbosity, name="IosConfigParser", **kwargs)
        self.DEFAULTS = IosConfigDefaults()

    @functools.cached_property
    def hostname(self):
        candidates = self.find_objects(regex=self._hostname_regex, group="hostname")
        return self.first_candidate_or_none(candidates=candidates)

    @property
    def interface_lines(self) -> Generator[IosInterfaceParser, None, None]:
        return (x for x in self.lines if 'interface' in x.get_type)

    @property
    def interfaces(self) -> Generator[InterfaceModel, None, None]:
        return (x.to_model() for x in self.interface_lines)

    def get_interface_line(self, interface_name: str) -> Union[IosInterfaceParser, None]:
        interface_name = normalize_interface_name(interface_name=interface_name, short=False)
        candidates = [x for x in self.interface_lines if x.name == interface_name]
        return self.first_candidate_or_none(candidates=candidates)

    @property
    def vrf_definition_lines(self) -> Generator[IosVrfDefinitionParser, None, None]:
        return (x for x in self.lines if isinstance(x, IosVrfDefinitionParser))

    @property
    def vrfs(self) -> Generator[VRFModel, None, None]:
        return (x.model for x in self.vrf_definition_lines)

    @property
    def routing(self):
        raise NotImplementedError

    @functools.cached_property
    def proxy_arp_enabled(self) -> bool:
        candidates = self.find_objects(regex=self._ip_arp_proxy_disable_regex, group='ALL')
        candidate = self.first_candidate_or_none(candidates=candidates)
        if candidate is not None:
            candidate = self._val_to_bool(entry=candidate, keys=['no'])
            if candidate['no'] is True:
                # no ip arp proxy disable
                return True
            elif candidate['no'] is False:
                # ip arp proxy disable
                return False
        else:
            # Enabled by default
            return True

    @functools.cached_property
    def password_encryption_enabled(self) -> bool:
        candidates = self.find_objects(regex=self._service_password_encryption_regex, group='ALL')
        candidate = self.first_candidate_or_none(candidates=candidates)
        if candidate is not None:
            candidate = self._val_to_bool(entry=candidate, keys=['no'])
            if candidate['no'] is True:
                # no service password-encryption
                return False
            elif candidate['no'] is False:
                # service password-encryption
                return True
        else:
            # Disabled by default
            return False

    @functools.cached_property
    def banner(self):
        banners = {}
        candidates = self.find_objects(regex=self._banner_regex)
        stop_chars = ['^C', chr(3)]
        for candidate in candidates:
            banner_type = candidate.re_search(regex=self._banner_regex, group='banner_type')
            banner_text = None
            # Determine the stopchar
            stop_char_occurences = {candidate.text.count(x):x for x in stop_chars}
            stop_char = stop_char_occurences[max(stop_char_occurences.keys())]
            if max(stop_char_occurences.keys()) == 2: # SingleLine
                banner_text = [x for x in candidate.text.split(stop_char) if x != ''][-1]
            else: # Multiline
                banner_text = []
                # First line
                first_part_candidates = [x for x in candidate.text.split(stop_char) if x != ''][1:]
                if len(first_part_candidates):
                    banner_text.append(first_part_candidates[0])
                for line in self.lines[candidate.number+1:]:
                    if stop_char in line.text:
                        last_part_candidate = [x for x in line.text.split(stop_char) if x != ''][:1]
                        if len(last_part_candidate):
                            banner_text.append(last_part_candidate[0])
                        break
                    else:
                        banner_text.append(line.text)
            if isinstance(banner_text, list):
                banner_text = '\n'.join(banner_text)
            banners[banner_type] = banner_text
        return banners






    def to_model(self):
        model = HostConfig(interfaces={x.name: x for x in self.interfaces})
        return model

    def __repr__(self):
        return f"[IosConfigParser - {len(self.lines)} lines]"

    def __str__(self):
        return self.__repr__()