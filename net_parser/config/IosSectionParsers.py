import functools
import re
from pydantic.typing import (
    List,
    Union,
    Literal
)


from net_models.models.BaseModels.SharedModels import VRFAddressFamily, VRFModel
from net_models.models.services.cisco_ios.IosLineModels import *
from net_models.models.services.cisco_ios.AaaMethods import *

from net_parser.utils import re_search
from net_parser.config import BaseConfigLine

AAA_SECTION_REGEX = re.compile(pattern=r'^aaa \S+.*$', flags=re.MULTILINE)
VRF_SECTION_REGEX = re.compile(pattern=r'^(?:ip )?vrf definition \S+.*$', flags=re.MULTILINE)
LOGGING_SECTION_REGEX = re.compile(pattern=r'^logging \S+.*$', flags=re.MULTILINE)
LINE_SECTION_REGEX = re.compile(pattern=r'^line [a-z]+ \d+(?: \d+)?$')
BANNER_REGEX = re.compile(pattern=r"^banner (?P<banner_type>\S+)", flags=re.MULTILINE)



class IosConfigLine(BaseConfigLine):
    _registry = {}

    comment_regex = re.compile(pattern=r"^\s*!.*", flags=re.MULTILINE)

    def __init_subclass__(cls, regex: re.Pattern = None, **kwargs):
        super().__init_subclass__(**kwargs)
        if regex is not None:
            cls._registry[regex] = cls

    def __new__(cls, *args, **kwargs):
        text = kwargs.get('text')
        subclass = None
        for pattern, subclass_candidate in cls._registry.items():
            # print(f"Testing {pattern=} against {text=}")
            if pattern.match(string=text):
                # print("Pattern matched")
                subclass = subclass_candidate
                break
        if subclass is None:
            subclass = cls
        instance = object.__new__(subclass)
        instance.__init__(*args, **kwargs)
        return instance

    def __init__(self, number: int, text: str, config, verbosity: int = 4, name: str = "IosConfigLine"):
        super().__init__(number=number, text=text, config=config, verbosity=verbosity, name=name)




class IosAaaParser(IosConfigLine, regex=AAA_SECTION_REGEX):

    def __init__(self, number: int, text: str, config: 'IosConfigParser', verbosity: int = 4):
        super().__init__(number=number, text=text, config=config, verbosity=verbosity, name="IosAaaLine")


class IosVrfDefinitionParser(IosConfigLine, regex=VRF_SECTION_REGEX):

    _name_regex = re.compile(pattern=r"^(?:ip )?vrf definition (?P<name>\S+)", flags=re.MULTILINE)
    _description_regex = re.compile(pattern=r"^ description (?P<description>.*?)\Z", flags=re.MULTILINE)
    _rd_regex = re.compile(pattern=r"^ rd (?P<rd>\S+)\Z", flags=re.MULTILINE)
    _address_family_regex = re.compile(pattern=r"^ address-family (?P<afi>\S+)(?: (?P<safi>\S+))?\Z")
    _route_target_regex = re.compile(pattern=r"^  route-target (?P<action>import|export) (?P<rt>\S+)(?: (?P<rt_type>\S+))?", flags=re.MULTILINE)

    def __init__(self, number: int, text: str, config, verbosity: int = 4):
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
            'rd': self.rd,
            'description': self.description,
            'address_families': self.address_families,
        }
        model = VRFModel(**{k:v for k, v in data.items() if v is not None})
        return model



class IosLoggingLine(IosConfigLine, regex=LOGGING_SECTION_REGEX):

    def __init__(self, number: int, text: str, config, verbosity: int = 4):
        super().__init__(number=number, text=text, config=config, verbosity=verbosity, name="IosLoggingLine")

    @property
    def get_type(self):
        types = super().get_type
        types.append('logging')
        return types


class IosLineParser(IosConfigLine, regex=LINE_SECTION_REGEX):

    _line_base_regex = re.compile(pattern=r"^line (?P<line_type>\S+) (?P<range_start>\d+)(?: (?P<range_stop>\d+))?", flags=re.MULTILINE)
    _exec_timeout_regex = re.compile(pattern=r"^ exec-timeout (?P<minutes>\d+) (?P<seconds>\d+)")
    _transport_regex = re.compile(pattern=r"^ transport (?P<direction>input|output|preferred) (?P<protocol>\S+)$")
    _acl_regex = re.compile(pattern=r"^ access-class (?P<name>\S+) (?P<direction>in|out)(?: (?P<vrf_also>vrf-also)|(?: vrf (?P<vrf>\S+)))?", flags=re.MULTILINE)
    _acl_ipv6_regex = re.compile(pattern=r"^ ipv6 access-class (?P<name>\S+) (?P<direction>in|out)(?: (?P<vrf_also>vrf-also)|(?: vrf (?P<vrf>\S+)))?", flags=re.MULTILINE)
    _exec_disabled_regex = re.compile(pattern=r"^ no exec", flags=re.MULTILINE)
    _authentication_regex = re.compile(pattern=r"^ login authentication (?P<authentication>\S+)")
    _authorization_exec_regex = re.compile(pattern=r"^ authorization exec (?P<authorization>\S+)")
    _authorization_commands_regex = re.compile(pattern=r"^ authorization commands (?P<level>\d+) (?P<authorization>\S+)")
    _priv_level_regex = re.compile(pattern=r"^ privilege level (?P<priv_level>\d+)$", flags=re.MULTILINE)
    _session_timeout_regex = re.compile(pattern=r"^ session-timeout (?P<minutes>\d+)(?: +(?P<output>output))?", flags=re.MULTILINE)



    def __init__(self, number: int, text: str, config, verbosity: int = 4):
        super().__init__(number=number, text=text, config=config, verbosity=verbosity, name="IosLineLine")

    @functools.cached_property
    def get_type(self):
        types = super().get_type
        types.append('management_line')
        return types

    @functools.cached_property
    def line_type(self) -> Literal['aux', 'console', 'vty']:
        candidate = self.re_search(regex=self._line_base_regex, group='line_type')
        if candidate == 'con':
            candidate = 'console'
        return candidate

    @functools.cached_property
    def line_range(self) -> List[int]:
        range_start = self.re_search(regex=self._line_base_regex, group='range_start')
        range_stop = self.re_search(regex=self._line_base_regex, group='range_stop')
        line_range = [range_start]
        if range_stop is not None:
            line_range.append(range_stop)
        return [int(x) for x in line_range]

    @functools.cached_property
    def exec_timeout(self) -> Union[int, None]:
        candidate = self.first_candidate_or_none(
            candidates=self.re_search_children(regex=self._exec_timeout_regex, group='ALL')
        )
        if candidate is None:
            return None
        else:
            return int(candidate['minutes'])*60 + int(candidate['seconds'])

    @functools.cached_property
    def transport(self) -> IosLineTransport:
        candidates = self.re_search_children(regex=self._transport_regex, group='ALL')
        data = {}
        for candidate in candidates:
            data[candidate['direction']] = candidate['protocol']
        if len(data):
            model = IosLineTransport.parse_obj(data)
            return model

    @functools.cached_property
    def has_ssh_enabled(self) -> bool:
        transport = self.transport
        if transport.input in ['all', 'ssh']:
            return True
        else:
            return False

    @functools.cached_property
    def has_telnet_enabled(self) -> bool:
        transport = self.transport
        if transport.input in ['all', 'telnet']:
            return True
        else:
            return False

    def has_output_enabled(self):
        transport = self.transport
        if transport.output in ['none']:
            return False
        else:
            return True

    @functools.cached_property
    def acls(self) -> List[IosLineAccessClass]:
        candidates = self.re_search_children(regex=self._acl_regex, group="ALL")
        if len(candidates) == 0:
            return None
        candidates = [self._val_to_bool(entry=x, keys=['vrf_also']) for x in candidates]
        acls = []
        for candidate in candidates:
            acl = IosLineAccessClass.parse_obj(candidate)
            acls.append(acl)
        if len(acls):
            return acls

    @functools.cached_property
    def acls_ipv6(self) -> List[IosLineAccessClass]:
        candidates = self.re_search_children(regex=self._acl_ipv6_regex, group="ALL")
        if len(candidates) == 0:
            return None
        candidates = [self._val_to_bool(entry=x, keys=['vrf_also']) for x in candidates]
        acls = []
        for candidate in candidates:
            acl = IosLineAccessClass.parse_obj(candidate)
            acls.append(acl)
        return acls

    @functools.cached_property
    def acl_inbound(self) -> IosLineAccessClass:
        acls = self.acls
        return [x for x in acls if x.direction == 'in']

    @functools.cached_property
    def acl_outbound(self) -> IosLineAccessClass:
        acls = self.acls
        return [x for x in acls if x.direction == 'out']

    @functools.cached_property
    def exec_enabled(self):
        candidates = self.re_search_children(regex=self._exec_disabled_regex)
        if len(candidates):
            return False
        else:
            return True

    @functools.cached_property
    def priv_level(self) -> int:
        candidates = self.re_search_children(regex=self._priv_level_regex, group='priv_level')
        return self.first_candidate_or_none(candidates=candidates, wanted_type=int)

    @functools.cached_property
    def session_timeout(self) -> dict:
        #TODO: Map to model
        candidates = self.re_search_children(regex=self._session_timeout_regex, group='ALL')
        candidates = [self._val_to_bool(entry=x, keys=['output'])]
        return self.first_candidate_or_none(candidates=candidates)

    @functools.cached_property
    def aaa(self) -> IosLineAaaConfig:
        # TODO: Add accounting
        # Authentication
        authentication_candidates = self.re_search_children(regex=self._authentication_regex, group='authentication')
        authentication = self.first_candidate_or_none(candidates=authentication_candidates)
        if authentication is None:
            authentication = 'default'
        # Authorization
        authorization_exec_candidates = self.re_search_children(regex=self._authorization_exec_regex, group='authorization')
        authorization_exec = self.first_candidate_or_none(candidates=authorization_exec_candidates)
        if authorization_exec is None:
            authorization_exec = 'default'
        authorization = IosAaaLineAuthorization(exec=authorization_exec)
        authorization_commands_candidates = self.re_search_children(regex=self._authorization_commands_regex, group='ALL')
        if len(authorization_commands_candidates):
            authorization.commands = []
        for c in authorization_commands_candidates:
            authorization.commands.append(IosAaaLineCommands(name=c['authorization'], level=c['level']))

        model = IosLineAaaConfig(
            authentication=authentication,
            authorization=authorization
        )
        return model

    def to_model(self):
        mapping = {
            'line_type': self.line_type,
            'line_range': self.line_range,
            'aaa_config': self.aaa,
            'exec_timeout': self.exec_timeout,
            'access_classes': self.acls,
            'transport': self.transport
        }
        data = {k:v for k,v in mapping.items() if v is not None}
        model = IosLineConfig.parse_obj(data)
        return model


class IosBannerLine(IosConfigLine, regex=BANNER_REGEX):

    def __init__(self, number: int, text: str, config, verbosity: int = 4):
        super().__init__(number=number, text=text, config=config, verbosity=verbosity, name="IosBannerLine")

    @property
    def get_type(self):
        types = super().get_type
        types.append('banner')
        return types