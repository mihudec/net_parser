import functools
import re
from .IosSectionParsers import IosConfigLine
from net_models.models.interfaces.InterfaceCommon import *
from net_models.models.interfaces.InterfaceModels import *
from net_models.models.interfaces.L2InterfaceModels import *
from net_models.models.interfaces.L3InterfaceModels import *
from net_models.models.interfaces.SpModels import *

from net_models.validators import expand_vlan_range

from pydantic.typing import (
    Generator,
    Union
)

from net_parser.utils import compile_regex, re_search, re_search_lines, re_filter_lines

INTERFACE_SECTION_REGEX = re.compile(pattern=r'^interface \S+$', flags=re.MULTILINE)
SERVICE_INSTANCE_REGEX = re.compile(pattern=r"^ service instance .*$", flags=re.MULTILINE)

class IosInterfaceParser(IosConfigLine, regex=INTERFACE_SECTION_REGEX):

    _name_regex = re.compile(pattern=r"^interface (?P<name>.*)\Z", flags=re.MULTILINE)
    _description_regex = re.compile(pattern=r"^ description (?P<description>.*?)\Z", flags=re.MULTILINE)
    _ipv4_addr_regex = re.compile(pattern=r"^ ip address (?P<address>(?:\d{1,3}\.){3}\d{1,3}) (?P<mask>(?:\d{1,3}\.){3}\d{1,3})(?: (?P<secondary>secondary))?", flags=re.MULTILINE)
    _vrf_regex = re.compile(pattern=r"^(?:\sip)?\svrf\sforwarding\s(?P<vrf>\S+)", flags=re.MULTILINE)
    _shutdown_regex = re.compile(pattern=r"^ (?P<shutdown>shutdown)\Z", flags=re.MULTILINE)
    _no_shutdown_regex = re.compile(pattern=r"^ (?P<no_shutdown>no shutdown)\Z", flags=re.MULTILINE)
    _cdp_regex = re.compile(pattern=r"^ (?P<cdp_enabled>cdp enable)", flags=re.MULTILINE)
    _no_cdp_regex = re.compile(pattern=r"^ (?P<no_cdp_enabled>no cdp enable)", flags=re.MULTILINE)
    _lldp_transmit_regex = re.compile(pattern=r"^ lldp transmit", flags=re.MULTILINE)
    _no_lldp_transmit_regex = re.compile(pattern=r"^ no lldp transmit", flags=re.MULTILINE)
    _lldp_receive_regex = re.compile(pattern=r"^ lldp receive", flags=re.MULTILINE)
    _no_lldp_receive_regex = re.compile(pattern=r"^ no lldp receive", flags=re.MULTILINE)
    _mtu_regex = re.compile(pattern=r"^ mtu (?P<mtu>\d+)", flags=re.MULTILINE)
    _ip_mtu_regex = re.compile(pattern=r"^ ip mtu (?P<ip_mtu>\d+)", flags=re.MULTILINE)
    _bandwidth_regex = re.compile(pattern=r"^ bandwidth (?P<bandwidth>\d+)", flags=re.MULTILINE)
    _delay_regex = re.compile(pattern=r"^ delay (?P<delay>\d+)", flags=re.MULTILINE)
    _load_interval_regex = re.compile(pattern=r"^ load-interval (?P<load_interval>\d+)")


    _ospf_process_regex = re.compile(pattern=r"^ ip ospf (?P<process_id>\d+) area (?P<area>\d+)$", flags=re.MULTILINE)
    _ospf_network_type_regex = re.compile(pattern=r"^ ip ospf network (?P<network_type>\S+)", flags=re.MULTILINE)
    _ospf_priority_regex = re.compile(pattern=r"^ ip ospf priority (?P<priority>\d+)", flags=re.MULTILINE)
    _ospf_cost_regex = re.compile(pattern=r"^ ip ospf cost (?P<cost>\d+)", flags=re.MULTILINE)
    _ospf_bfd_regex = re.compile(pattern=r"^ ip ospf bfd(?: (?:(?P<disable>disable)|(?P<strict_mode>strict-mode)))?", flags=re.MULTILINE)
    _ospf_timers = re.compile(pattern=r"^ ip ospf (?P<timer>\S+?)-interval (?P<interval>\d+)\Z", flags=re.MULTILINE)
    _ospf_authentication_method = re.compile(pattern=r"^ ip ospf authentication (?P<method>\S+)(?: (?P<keychain>\S+))?", flags=re.MULTILINE)
    _ospf_authentication_key = re.compile(pattern=r"^ ip ospf authentication-key(?: (?P<encryption_type>\d))? (?P<value>\S+)", flags=re.MULTILINE)


    _isis_process_regex = re.compile(pattern=r"^ ip router isis (?P<process_id>\S+)\Z")
    _isis_network_type_regex = re.compile(pattern=r"^ isis network (?P<network_type>\S+)", flags=re.MULTILINE)
    _isis_circuit_type_regex = re.compile(pattern=r"^ isis circuit-type (?P<circuit_type>\S+)", flags=re.MULTILINE)
    _isis_metric_regex = re.compile(pattern=r"^ isis metric (?P<metric>\d+) (?P<level>\S+)", flags=re.MULTILINE)
    _isis_authentication_mode = re.compile(pattern=r"^ isis authentication mode (?P<mode>md5|text)$", flags=re.MULTILINE)
    _isis_authentication_keychain = re.compile(pattern=r"^ isis authentication key-chain (?P<keychain>\S+)$", flags=re.MULTILINE)



    _native_vlan_regex = re.compile(pattern=r"^ switchport trunk native vlan (?P<native_vlan>\d+)", flags=re.MULTILINE)
    _trunk_encapsulation_regex = re.compile(pattern=r"^ switchport trunk encapsulation (?P<encapsulation>dot1q|isl|negotiate)", flags=re.MULTILINE)
    _switchport_mode_regex = re.compile(pattern=r"^ switchport mode (?P<switchport_mode>access|trunk|dot1q-tunnel|private-vlan|dynamic)")
    _switchport_nonegotiate_regex = re.compile(pattern=r"^ switchport nonegotiate")
    _trunk_allowed_vlans_regex = re.compile(pattern=r"^ switchport trunk allowed vlan(?: add)? (?P<allowed_vlans>\S+)", flags=re.MULTILINE)
    _access_vlan_regex = re.compile(pattern=r"^ switchport access vlan (?P<access_vlan>\d+)", flags=re.MULTILINE)
    _voice_vlan_regex = re.compile(pattern=r"^ switchport voice vlan (?P<voice_vlan>\d+)")

    _hsrp_version_regex = re.compile(pattern=r"^ standby version (?P<version>\d)", flags=re.MULTILINE)
    _hsrp_ipv4_regex = re.compile(pattern=r"^ standby (?P<group_id>\d+) ip (?P<address>\S+)(?: (?P<secondary>secondary))?", flags=re.MULTILINE)
    _hsrp_priority_regex = re.compile(pattern=r"^ standby (?P<group_id>\d+) priority (?P<priority>\S+)", flags=re.MULTILINE)
    _hsrp_preemption_regex = re.compile(pattern=r"^ standby (?P<group_id>\d+) (?P<preemption>preempt)", flags=re.MULTILINE)
    _hsrp_timers_regex = re.compile(pattern=r"^ standby (?P<group_id>\d+) timers (?:(?P<milliseconds>msec) )?(?P<hello>\d+) (?P<hold>\d+)", flags=re.MULTILINE)
    _hsrp_track_regex = re.compile(pattern=r"^ standby (?P<group_id>\d+) track (?P<track_id>\d+) (?P<action>shutdown|decrement)(?: (?P<decrement_value>\d+))?", flags=re.MULTILINE)
    _hsrp_authentication_regexes = [
        re.compile(pattern=r"^ standby (?P<group_id>\d+) authentication (?:(?P<method>md5|text) )?(?:key-string )?(?:(?P<encryption_type>\d) )?(?P<value>\S+)$", flags=re.MULTILINE),
        re.compile(pattern=r"^ standby (?P<group_id>\d+) authentication md5 (?P<method>key-chain) (?P<keychain>\S+)$", flags=re.MULTILINE)
    ]
    _hsrp_name_regex = re.compile(pattern=r"^ standby (?P<group_id>\d+) name (?P<name>\S+)$", flags=re.MULTILINE)

    _proxy_arp_regex = re.compile(pattern=r"^ (?:(?P<no>no) )?ip proxy-arp$", flags=re.MULTILINE)

    _service_policy_regex = re.compile(pattern=r"^ service-policy (?P<direction>input|output) (?P<name>\S+$)", flags=re.MULTILINE)

    _ethernet_uni_id = re.compile(pattern=r"^ ethernet uni id (?P<uni_id>\S+)$", flags=re.MULTILINE)




    def __init__(self, number: int, text: str, config, verbosity: int = 4):
        super().__init__(number=number, text=text, config=config, verbosity=verbosity, name="IosInterfaceLine")

    @property
    def get_type(self):
        types = super().get_type
        types.append('interface')
        return types


    @functools.cached_property
    def name(self) -> Union[str, None]:
        return self.re_match(regex=self._name_regex, group=1)

    @functools.cached_property
    def description(self) -> Union[str, None]:
        candidates = self.re_search_children(regex=self._description_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates)

    @functools.cached_property
    def is_enabled(self) -> Union[bool, None]:
        shutdown_candidates = self.re_search_children(regex=self._shutdown_regex, group='shutdown')
        no_shutdown_candidates = self.re_search_children(regex=self._no_shutdown_regex, group='no_shutdown')
        if len(shutdown_candidates) == 1:
            return False
        elif len(no_shutdown_candidates):
            return True
        else:
            if self.config.DEFAULTS.INTERFACES_DEFAULT_NO_SHUTDOWN is not None:
                self.logger.debug(msg=f"Interface {self.name}: Using platform default value for interface admin state.")
                return self.config.DEFAULTS.INTERFACES_DEFAULT_NO_SHUTDOWN
            else:
                self.logger.debug(msg=f"Interface {self.name}: Platform default for interface admin state not set.")
                return None

    @functools.cached_property
    def is_routed(self):
        candidates = self.re_search_children(regex=re.compile(pattern="(?:no )?ip address"))
        self.logger.debug(msg=f"Interface {self.name}: {candidates=}")
        if len(candidates):
            return True
        else:
            return False

    @functools.cached_property
    def is_switched(self):
        candidates = self.re_search_children(regex=re.compile(pattern="(?:no )?ip address"))
        self.logger.debug(msg=f"Interface {self.name}: {candidates=}")
        if len(candidates):
            return False
        else:
            return True



    @functools.cached_property
    def cdp(self) -> Union[InterfaceCdpConfig, None]:
        cdp_candidates = self.re_search_children(regex=self._cdp_regex, group=1)
        no_cdp_candidates = self.re_search_children(regex=self._no_cdp_regex, group=1)
        if len(cdp_candidates) == 1:
            return InterfaceCdpConfig(enabled=True)
        elif len(no_cdp_candidates):
            return InterfaceCdpConfig(enabled=True)
        else:
            if self.config.DEFAULTS.INTERFACES_DEFAULT_CDP_ENABLED is None:
                self.logger.debug("Platform default for CDP not set.")
                return None
            else:
                self.logger.debug(msg="Using platform default value for interface CDP.")
                return InterfaceCdpConfig(enabled=self.config.DEFAULTS.INTERFACES_DEFAULT_CDP_ENABLED)


    @functools.cached_property
    def lldp(self) -> Union[InterfaceLldpConfig, None]:
        lldp_transmit_candidates = self.re_search_children(regex=self._lldp_transmit_regex)
        no_lldp_transmit_candidates = self.re_search_children(regex=self._no_lldp_transmit_regex)
        lldp_receive_candidates = self.re_search_children(regex=self._lldp_receive_regex)
        no_lldp_receive_candidates = self.re_search_children(regex=self._no_lldp_receive_regex)
        data = {}

        if len(lldp_transmit_candidates):
            data["transmit"] = True
        elif len(no_lldp_transmit_candidates):
            data["transmit"] = False
        elif self.config.DEFAULTS.INTERFACES_DEFAULT_LLDP_ENABLED is not None:
            self.logger.debug(msg="Using platform default value for interface LLDP transmit.")
            data["transmit"] = self.config.DEFAULTS.INTERFACES_DEFAULT_LLDP_ENABLED

        if len(lldp_receive_candidates):
            data["receive"] = True
        elif len(no_lldp_receive_candidates):
            data["receive"] = False
        elif self.config.DEFAULTS.INTERFACES_DEFAULT_LLDP_ENABLED is not None:
            self.logger.debug(msg="Using platform default value for interface LLDP receive.")
            data["receive"] = self.config.DEFAULTS.INTERFACES_DEFAULT_LLDP_ENABLED

        if any(data.values()):
            return InterfaceLldpConfig(**data)
        else:
            self.logger.debug("Platform default for LLDP not set.")
            return None

    @functools.cached_property
    def mtu(self) -> Union[int, None]:
        candidates = self.re_search_children(regex=self._mtu_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates, wanted_type=int)

    @functools.cached_property
    def ip_mtu(self) -> Union[int, None]:
        candidates = self.re_search_children(regex=self._ip_mtu_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates, wanted_type=int)

    @functools.cached_property
    def bandwidth(self) -> Union[int, None]:
        candidates = self.re_search_children(regex=self._bandwidth_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates, wanted_type=int)

    @functools.cached_property
    def delay(self) -> Union[int, None]:
        candidates = self.re_search_children(regex=self._delay_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates, wanted_type=int)

    @functools.cached_property
    def load_interval(self) -> Union[int, None]:
        candidates = self.re_search_children(regex=self._load_interval_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates, wanted_type=int)

    @functools.cached_property
    def vrf(self) -> Union[str, None]:
        candidates = self.re_search_children(regex=self._vrf_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates)

    @functools.cached_property
    def uni_id(self) -> Union[str, None]:
        candidates = self.re_search_children(regex=self._ethernet_uni_id, group=1)
        return self.first_candidate_or_none(candidates=candidates)

    @functools.cached_property
    def service_policy(self) -> Union[InterfaceServicePolicy, None]:
        candidates = self.re_search_children(regex=self._service_policy_regex, group='ALL')
        if len(candidates) == 0:
            return None

        data = {x['direction']: x['name'] for x in candidates}
        model = InterfaceServicePolicy.parse_obj(data)
        return model


    @functools.cached_property
    def ipv4_addresses(self) -> Union[InterfaceIPv4Container, None]:
        candidates = self.re_search_children(regex=self._ipv4_addr_regex, group='ALL')
        if len(candidates) == 0:
            return None
        else:
            candidates = [self._val_to_bool(entry=x, keys=['secondary']) for x in candidates]
            candidates = [{'address': f"{x['address']}/{x['mask']}", 'secondary': x['secondary']} for x in candidates]
            return InterfaceIPv4Container(addresses=[InterfaceIPv4Address(**x) for x in candidates])

    @functools.cached_property
    def hsrp(self):
        unprocessed_lines = self.re_search_children(regex=self.compile_regex(pattern=r"^ standby .*"))
        if not len(unprocessed_lines):
            return None
        data = InterfaceHsrp(version=1)
        version, unprocessed_lines = re_filter_lines(lines=unprocessed_lines, regex=self._hsrp_version_regex, group='version', pop_matches=True)
        version = self.first_candidate_or_none(candidates=version, wanted_type=int)
        if version is not None:
            data.version = version
        ip_candidates, unprocessed_lines = re_filter_lines(lines=unprocessed_lines, regex=self._hsrp_ipv4_regex, group='ALL', pop_matches=True)
        ip_candidates = [self._val_to_bool(entry=x, keys=['secondary']) for x in ip_candidates]
        # print(f"{ip_candidates=}")
        priority_candidates, unprocessed_lines = re_filter_lines(lines=unprocessed_lines, regex=self._hsrp_priority_regex, group="ALL")
        # print(f"{priority_candidates=}")
        preemtion_candidates, unprocessed_lines = re_filter_lines(lines=unprocessed_lines, regex=self._hsrp_preemption_regex, group="ALL")
        preemtion_candidates = [self._val_to_bool(entry=x, keys=['preemption']) for x in preemtion_candidates]
        # print(f"{preemtion_candidates=}")
        timers_candidates, unprocessed_lines = re_filter_lines(lines=unprocessed_lines, regex=self._hsrp_timers_regex, group="ALL")
        timers_candidates = [self._val_to_bool(entry=x, keys=['milliseconds']) for x in timers_candidates]
        # print(f"{timers_candidates=}")
        track_candidates, unprocessed_lines = re_filter_lines(lines=unprocessed_lines, regex=self._hsrp_track_regex, group="ALL")
        # print(f"{track_candidates=}")
        authentication_candidates = self.re_search_children_multipattern(regexes=self._hsrp_authentication_regexes, group="ALL")
        # print(f"{authentication_candidates=}")
        name_candidates, unprocessed_lines = re_filter_lines(lines=unprocessed_lines, regex=self._hsrp_name_regex, group="ALL")
        # print(f"{name_candidates=}")


        # Get list of all group_ids
        group_ids = set()
        for candidates in [
            ip_candidates, priority_candidates, preemtion_candidates, timers_candidates, track_candidates,
            authentication_candidates, name_candidates
        ]:
            group_ids = group_ids | set([x['group_id'] for x in candidates])
        group_ids = sorted(list(group_ids), key=lambda x: int(x))

        # Populate Group Models
        for group_id in group_ids:
            group = InterfaceHsrpGroup(group_id=group_id)
            for c in [x for x in ip_candidates if x['group_id'] == group_id]:
                if group.ipv4 is None:
                    group.ipv4 = []
                include_keys = {k:v for k,v in c.items() if k in HsrpIpv4Address.__fields__.keys()}
                group.ipv4.append(HsrpIpv4Address.parse_obj({k:v for k,v in c.items() if k in include_keys }))
            # Priority
            for c in [x for x in priority_candidates if x['group_id'] == group_id]:
                group.priority = c['priority']
            # Preemption
            for c in [x for x in preemtion_candidates if x['group_id'] == group_id]:
                group.preemption = c['preemption']
            # Timers
            for c in [x for x in timers_candidates if x['group_id'] == group_id]:
                include_keys = {k:v for k,v in c.items() if k in HsrpTimers.__fields__.keys()}
                group.timers = HsrpTimers.parse_obj({k:v for k,v in c.items() if k in include_keys})
            # Tracks
            for c in [x for x in track_candidates if x['group_id'] == group_id]:
                include_keys = {k:v for k,v in c.items() if k in HsrpTrack.__fields__.keys()}
                if group.tracks is None:
                    group.tracks = []
                group.tracks.append(HsrpTrack.parse_obj({k:v for k,v in c.items() if k in include_keys and v is not None}))
            # Authentication
            for c in [x for x in authentication_candidates if x['group_id'] == group_id]:
                authentication = None
                if c['method'] is None:
                    c['method'] = 'text'
                if c['method'] in ['text', 'md5']:
                    include_keys = {k:v for k,v in c.items() if k in KeyBase.__fields__.keys()}
                    key = KeyBase.parse_obj({k:v for k,v in c.items() if k in include_keys and v is not None})
                    authentication = HsrpAuthentication(method=c['method'], key=key)
                elif c['method'] == 'key-chain':
                    authentication = HsrpAuthentication(method=c['method'], keychain=c['keychain'])
                group.authentication = authentication
            # Name
            for c in [x for x in name_candidates if x['group_id'] == group_id]:
                group.name = c['name']
            if data.groups is None:
                data.groups = []
            data.groups.append(group)

        if len(unprocessed_lines):
            pass
            # data.extra_config = [x.text for x in unprocessed_lines]
        data = data.copy()
        return data

    @functools.cached_property
    def switchport_mode(self):
        candidates = self.re_search_children(regex=self._switchport_mode_regex, group='switchport_mode')
        return self.first_candidate_or_none(candidates=candidates)

    @functools.cached_property
    def switchport_negotiation(self) -> bool:
        """
        Returns boolean representation whether negotiation (such as DTP) is enabled (True) or disabled (False)
        Returns: bool

        """
        candidates = self.re_search_children(regex=self._switchport_nonegotiate_regex)
        if self.first_candidate_or_none(candidates=candidates) is None:
            return True # Negotiation is NOT disabled
        else:
            return False # Negotiation is disabled


    @functools.cached_property
    def access_vlan(self) -> Union[int, None]:
        candidates = self.re_search_children(regex=self._access_vlan_regex, group='access_vlan')
        return self.first_candidate_or_none(candidates=candidates, wanted_type=int)

    @functools.cached_property
    def voice_vlan(self) -> Union[int, None]:
        candidates = self.re_search_children(regex=self._voice_vlan_regex, group='voice_vlan')
        return self.first_candidate_or_none(candidates=candidates, wanted_type=int)

    @functools.cached_property
    def trunk_allowed_vlans(self) -> Union[List[int], Literal['all', 'none'], None]:
        candidates = self.re_search_children(regex=self._trunk_allowed_vlans_regex, group='allowed_vlans')
        print(candidates)
        allowed_vlans = None
        if not len(candidates):
            pass
        else:
            if len(candidates) == 1:
                if candidates[0] in ['all', 'none']:
                    return candidates[0]
            allowed_vlans = []
            for candidate in candidates:
                allowed_vlans.extend(candidate.split(','))
            allowed_vlans = expand_vlan_range(vlan_range=allowed_vlans)
        return allowed_vlans

    @functools.cached_property
    def proxy_arp_enabled(self) -> bool:
        candidates = self.re_search_children(regex=self._proxy_arp_regex, group='ALL')
        candidate = self.first_candidate_or_none(candidates=candidates)

        if candidate is not None:
            candidate = self._val_to_bool(entry=candidate, keys=['no'])
            if candidate['no'] is True:
                # no ip proxy-arp
                return False
            elif candidate['no'] is False:
                # ip proxy-arp
                return True
        else:
            self.logger.debug(msg=f"Interface {self.name}: Using global value for Proxy ARP: {self.config.proxy_arp_enabled}")
            # If not specified, return global value
            return self.config.proxy_arp_enabled

    @functools.cached_property
    def ospf(self) -> Union[InterfaceOspfConfig, None]:
        data = {}
        process_candidates = self.first_candidate_or_none(self.re_search_children(regex=self._ospf_process_regex, group='ALL'))
        network_type = self.first_candidate_or_none(self.re_search_children(regex=self._ospf_network_type_regex, group='ALL'))
        cost = self.first_candidate_or_none(self.re_search_children(regex=self._ospf_cost_regex, group='ALL'))
        priority = self.first_candidate_or_none(self.re_search_children(regex=self._ospf_cost_regex, group='ALL'))
        bfd = self.first_candidate_or_none(self.re_search_children(regex=self._ospf_bfd_regex, group="ALL"))
        timers = self.re_search_children(regex=self._ospf_timers, group="ALL")
        authentication_method = self.first_candidate_or_none(self.re_search_children(regex=self._ospf_authentication_method, group="ALL"))
        authentication_key = self.first_candidate_or_none(self.re_search_children(regex=self._ospf_authentication_key, group="ALL"))

        if process_candidates is not None:
            data.update(process_candidates)
        if network_type is not None:
            data.update(network_type)
        if cost is not None:
            data.update(cost)
        if priority is not None:
            data.update(priority)
        # BFD
        if bfd is not None:
            bfd = self._val_to_bool(entry=bfd, keys=['disable', 'strict_mode'])
            if bfd['disable']:
                data.update({"bfd": False})
            elif bfd['strict_mode']:
                data.update({"bfd": 'strict-mode'})
            else:
                data.update({"bfd": True})
        # Timers
        if len(timers):
            timers = InterfaceOspfTimers(**{x["timer"]:x['interval'] for x in timers})
            data['timers'] = timers
        # Authentication
        if any([authentication_key, authentication_method]):
            authentication_data = {}
            if authentication_method:
                authentication_data.update({k:v for k, v in authentication_method.items() if v is not None})
            if authentication_key:
                if authentication_key['encryption_type'] is None:
                    authentication_key['encryption_type'] = 0
                authentication_data.update({'key': authentication_key})
            authentication = InterfaceOspfAuthentication(**authentication_data)
            data['authentication'] = authentication
        # Convert to model
        if len(data) == 0:
            return None
        else:
            return InterfaceOspfConfig(**data)


    @functools.cached_property
    def isis(self):
        # TODO: Complete
        data = {}
        patterns = [
            self._isis_process_regex,
            self._isis_network_type_regex,
            self._isis_circuit_type_regex
        ]
        results = self.re_search_children_multipattern(regexes=patterns, group="ALL")
        for entry in results:
            data.update(entry)

        # Metrics section
        results = self.re_search_children(regex=self._isis_metric_regex, group="ALL")
        if len(results):
            data['metric'] = list(results)

        # Authentication section
        auth_data = {}
        patterns = [
            self._isis_authentication_mode,
            self._isis_authentication_keychain
        ]
        results = self.re_search_children_multipattern(regexes=patterns, group="ALL")
        for entry in results:
            auth_data.update(entry)
        if len(auth_data):
            data['authentication'] = auth_data

        # Convert to model
        if len(data) == 0:
            return None
        else:
            return InterfaceIsisConfig.parse_obj(data)

    @property
    def service_instance_lines(self) -> Generator['IosServiceInstance', None, None]:
        return (x for x in self.get_children(max_depth=1) if isinstance(x, IosServiceInstance))

    @property
    def service_instances(self) -> Generator['ServiceInstance', None, None]:
        return (x.to_model() for x in self.service_instance_lines)

    def to_model(self) -> InterfaceModel:
        self.logger.debug(msg=f"Building model for interface {self.name}")
        model = InterfaceModel(
            name=self.name,
        )
        if self.is_enabled is not None:
            model.enabled = self.is_enabled

        if self.description is not None:
            model.description = self.description


        l3_parameters = [
            self.ipv4_addresses,
            self.ip_mtu,
            self.vrf,
            self.ospf,
            self.isis
        ]
        if any(l3_parameters):
            if model.l3_port is None:
                model.l3_port = InterfaceRouteportModel()

        discovery_protocols = [
            self.cdp,
            self.lldp
        ]
        if any(discovery_protocols):
            self.logger.debug(msg=f"Discovery Protocols: {discovery_protocols}")
            if model.discovery_protocols is None:
                model.discovery_protocols = InterfaceDiscoveryProtocols()

        # Service instances
        service_instance_list = list(self.service_instances)
        if len(service_instance_list):
            model.service_instances = service_instance_list

        if self.load_interval is not None:
            model.load_interval = self.load_interval
        if self.delay is not None:
            model.delay = self.delay
        if self.bandwidth is not None:
            model.bandwidth = self.bandwidth

        if self.cdp is not None:
            model.discovery_protocols.cdp = self.cdp

        if self.lldp is not None:
            model.discovery_protocols.lldp = self.lldp

        if self.mtu is not None:
            model.mtu = self.mtu

        if self.service_policy is not None:
            model.service_policy = self.service_policy


        if self.ipv4_addresses is not None:
            model.l3_port.ipv4 = self.ipv4_addresses
        if self.vrf is not None:
            model.l3_port.vrf = self.vrf
        if self.ip_mtu is not None:
            model.l3_port.ip_mtu = self.ip_mtu


        # Dynamic Routing Protocols
        if self.ospf is not None:
            model.l3_port.ospf = self.ospf

        if self.isis is not None:
            model.l3_port.isis = self.isis

        if self.hsrp is not None:
            model.l3_port.hsrp = self.hsrp


        return model


class IosServiceInstance(IosConfigLine, regex=SERVICE_INSTANCE_REGEX):

    _service_instance_regex = re.compile(pattern=r"^ service instance (?P<si_id>\d+) (?P<si_type>ethernet)(?: (?P<evc>\S+))?$")
    _description_regex = re.compile(pattern=r"^  description (?P<description>.*?)\Z", flags=re.MULTILINE)


    @property
    def si_id(self):
        return self.re_search(regex=self._service_instance_regex, group='si_id')

    @property
    def si_type(self):
        return self.re_search(regex=self._service_instance_regex, group='si_type')

    @property
    def evc(self):
        return self.re_search(regex=self._service_instance_regex, group='evc')

    @functools.cached_property
    def description(self) -> Union[str, None]:
        candidates = self.re_search_children(regex=self._description_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates)


    def to_model(self):
        MODEL_CLASS = ServiceInstance
        data = {}
        if self.si_id is not None:
            data['si_id'] = self.si_id
        if self.si_type is not None:
            # TODO: Model field
            pass
        if self.evc is not None:
            data['evc'] = self.evc

        if self.description is not None:
            data['description'] = self.description


        model = MODEL_CLASS.parse_obj(
            {k:v for k,v in self.re_search(regex=self._service_instance_regex, group="ALL").items() if k in MODEL_CLASS.__fields__.keys() and v is not None}
        )
        return model