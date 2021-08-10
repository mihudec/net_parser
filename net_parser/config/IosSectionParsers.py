import functools
import re
from typing import (
    List,
    Union
)


from net_models.models.BaseModels.SharedModels import VRFAddressFamily, VRFModel

from net_parser.config import BaseConfigLine



class IosConfigLine(BaseConfigLine):

    def __init__(self, number: int, text: str, config, verbosity: int, name: str = "IosConfigLine"):
        super().__init__(number=number, text=text, config=config, verbosity=verbosity, name="IosAaaLine")



class IosAaaParser(IosConfigLine):

    def __init__(self, number: int, text: str, config, verbosity: int):
        super().__init__(number=number, text=text, config=config, verbosity=verbosity, name="IosAaaLine")


class IosVrfDefinitionParser(IosConfigLine):

    _name_regex = re.compile(pattern=r"^(?:ip )?vrf definition (?P<name>\S+)", flags=re.MULTILINE)
    _description_regex = re.compile(pattern=r"^ description (?P<description>.*?)\Z", flags=re.MULTILINE)
    _rd_regex = re.compile(pattern=r"^ rd (?P<rd>\S+)\Z", flags=re.MULTILINE)
    _address_family_regex = re.compile(pattern=r"^ address-family (?P<afi>\S+)(?: (?P<safi>\S+))?\Z")
    _route_target_regex = re.compile(pattern=r"^  route-target (?P<action>import|export) (?P<rt>\S+)(?: (?P<rt_type>\S+))?", flags=re.MULTILINE)

    def __init__(self, number: int, text: str, config, verbosity: int):
        super().__init__(number=number, text=text, config=config, verbosity=verbosity, name="IosVrfDefinitionLine")

    @property
    def get_type(self):
        types = super().get_type
        types.append('vrf')
        return types

    @property
    def name(self) -> Union[str, None]:
        return self.re_match(regex=self._name_regex, group=1)

    @property
    def description(self) -> Union[str, None]:
        candidates = self.re_search_children(regex=self._description_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates)

    @property
    def rd(self) -> bool:
        candidates = self.re_search_children(regex=self._rd_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates)

    @property
    def address_families(self) -> Union[List[VRFAddressFamily], None]:
        address_families = []
        af_lines = self.re_search_children(regex=self._address_family_regex)
        for af_line in af_lines:
            data = {}
            data.update(af_line.re_search(regex=self._address_family_regex, group="ALL"))
            # Route Targets
            rt_candidates = af_line.re_search_children(regex=self._route_target_regex, group="ALL")
            print(rt_candidates)
            if len(rt_candidates):
                data['route_targets'] = rt_candidates
            if not any(data.values()):
                continue
            else:
                model = VRFAddressFamily(**data)
                address_families.append(model)
        if len(address_families):
            self.logger.debug(f"Found {len(address_families)} AFs for VRF {self.name}")
            return address_families
        else:
            self.logger.debug(f"Found no AFs for VRF {self.name}")
            return None

    @property
    @functools.lru_cache()
    def model(self):
        data = {
            'name': self.name,
            'description': self.description,
            'address_families': self.address_families,
        }
        model = VRFModel(**{k:v for k, v in data if v is not None})
        return model



class IosLoggingParser(IosConfigLine):

    def __init__(self, number: int, text: str, config, verbosity: int):
        super().__init__(number=number, text=text, config=config, verbosity=verbosity, name="IosLoggingLine")

    @property
    def get_type(self):
        types = super().get_type
        types.append('logging')
        return types