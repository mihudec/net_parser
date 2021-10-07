import dataclasses
import functools
import re
import pathlib
import timeit
from typing import Union, List, Generator

from net_models.validators import normalize_interface_name
from net_models.models.interfaces.InterfaceModels import InterfaceModel
from net_models.models import VRFModel
from net_models.models.services.ServerModels import *
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

    _interface_pattern = r"[A-z]{2,}(?:[A-z\-])?\d+(?:\/\d+)?(?:\:\d+)?(?:\.\d+)?"
    _ip_address_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"
    _host_pattern = r"[A-z0-9\-\_\.]+"
    _source_interface_regex = re.compile(pattern=r"source (?P<src_interface>{0})".format(_interface_pattern))
    _source_vrf_regex = re.compile(pattern=r"vrf (?P<vrf>\S+)")

    _hostname_regex = re.compile(pattern=r"^hostname (?P<hostname>\S+)\Z")
    _ip_arp_proxy_disable_regex = re.compile(pattern=r"^(?:(?P<no>no) )?ip arp proxy disable$", flags=re.MULTILINE)
    _service_password_encryption_regex = re.compile(pattern=r"^(?:(?P<no>no) )?service password-encryption$", flags=re.MULTILINE)
    _banner_regex = re.compile(pattern=r"^banner (?P<banner_type>\S+)")
    _service_pad_regex = re.compile(pattern=r"^(?:(?P<no>no) )?service pad$", flags=re.MULTILINE)
    _ip_finger_regex = re.compile(pattern=r"^(?:(?P<no>no) )?ip finger(?: (?P<rfc_compliant>rfc-compliant))?$", flags=re.MULTILINE)
    _ip_source_route_regex = re.compile(pattern=r"^(?:(?P<no>no) )?ip source-route$", flags=re.MULTILINE)

    _ntp_server_base_regex = re.compile(pattern=r"^ntp server(?: vrf \S+)? (?P<server>{0}|{1})".format(_ip_address_pattern, _host_pattern), flags=re.MULTILINE)
    _ntp_peer_base_regex = re.compile(pattern=r"^ntp peer(?: vrf \S+)? (?P<server>{0}|{1})".format(_ip_address_pattern, _host_pattern), flags=re.MULTILINE)
    _ntp_authentication_keys_regex = re.compile(pattern=r"^ntp authentication-key (?P<key_id>\d+) (?P<method>\S+) (?P<value>\S+)(?: (?P<encryption_type>\d+))?", flags=re.MULTILINE)
    _ntp_trusted_key_regex = re.compile(pattern=r"^ntp trusted-key (?P<key_id>\d+)", flags=re.MULTILINE)

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

    @functools.cached_property
    def ntp(self) -> NtpConfig:
        ntp = NtpConfig()
        # Servers Section
        candidate_pattern = self._ntp_server_base_regex
        patterns = [
            self._ntp_server_base_regex,
            self._source_interface_regex,
            self._source_vrf_regex,
            re.compile("key (?P<key_id>\d+)"),
            re.compile("(?P<prefer>prefer)")
        ]

        ntp_servers = self.property_autoparse(candidate_pattern=candidate_pattern, patterns=patterns)
        ntp_servers = [self._val_to_bool(entry=x, keys=['prefer']) for x in ntp_servers]
        ntp_servers = [NtpServer.parse_obj(x) for x in ntp_servers]
        print(ntp_servers)
        if len(ntp_servers):
            ntp.servers = ntp_servers
        # Peers
        candidate_pattern = self._ntp_peer_base_regex
        patterns = [
            self._ntp_peer_base_regex,
            self._source_interface_regex,
            self._source_vrf_regex,
            re.compile("key (?P<key_id>\d+)"),
            re.compile("(?P<prefer>prefer)")
        ]
        ntp_peers = self.property_autoparse(candidate_pattern=candidate_pattern, patterns=patterns)
        ntp_peers = [self._val_to_bool(entry=x, keys=['prefer']) for x in ntp_peers]
        ntp_peers = [NtpServer.parse_obj(x) for x in ntp_peers]
        print(ntp_peers)
        if len(ntp_peers):
            ntp.peers = ntp_peers
        authenticate = self._globals_check(
            regex=re.compile(
                pattern=r"^(?:(?P<no>no) )?ntp authenticate$",
                flags=re.MULTILINE
            ),
            default=False
        )
        ntp.authenticate = authenticate
        # Keys
        ntp_auth_keys = self.find_objects(regex=self._ntp_authentication_keys_regex, group='ALL')
        ntp_auth_keys = [NtpKey.parse_obj(x) for x in ntp_auth_keys]
        ntp_trusted_keys = [int(x) for x in self.find_objects(regex=self._ntp_trusted_key_regex, group='key_id')]
        for ntp_key in ntp_auth_keys:
            if ntp_key.key_id in ntp_trusted_keys:
                ntp_key.trusted = True
        if len(ntp_auth_keys):
            ntp.ntp_keys = ntp_auth_keys
        # Access Lists
        # TODO: Finish Access Lists
        return ntp
        


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

    def _globals_check(self, regex: re.Pattern, default: bool) -> bool:
        """
        This function looks for given `regex`, if found and prefixed with 'no', returns False. If not prefixed with no,
        returns True. Returns 'default' otherwise.
        Args:
            regex: re.Pattern with 'no' groups specified
            default: bool - which value to return if regex did not match

        Returns:

        """
        candidates = self.find_objects(regex=regex, group='ALL')
        candidate = self.first_candidate_or_none(candidates=candidates)
        if candidate is not None:
            candidate = self._val_to_bool(entry=candidate, keys=['no'])
            if candidate['no'] is True:
                # Negated
                return False
            elif candidate['no'] is False:
                return True
        else:
            return default

    @functools.cached_property
    def password_encryption_enabled(self) -> bool:
        return self._globals_check(regex=self._service_password_encryption_regex, default=False)

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


    @functools.cached_property
    def ip_source_routing_enabled(self):
        return self._globals_check(regex=self._ip_source_route_regex, default=True)

    @functools.cached_property
    def ip_finger_enabled(self):
        return self._globals_check(regex=self._ip_finger_regex, default=True)


    @functools.cached_property
    def service_pad_enabled(self) -> bool:
        """
        Packet Assembler Disassembler service

        Returns: bool

        """
        return self._globals_check(regex=self._service_pad_regex, default=True)


    @functools.cached_property
    def service_tcp_keepalives_in(self):
        self._globals_check(regex=self._service_tcp_keepalives_in, default=False)

    @functools.cached_property
    def service_tcp_keepalives_in(self):
        self._globals_check(regex=self._service_tcp_keepalives_in, default=False)


    def to_model(self):
        model = HostConfig(interfaces={x.name: x for x in self.interfaces})
        return model

    def __repr__(self):
        return f"[IosConfigParser - {len(self.lines)} lines]"

    def __str__(self):
        return self.__repr__()