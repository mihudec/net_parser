import functools
import re
from . import BaseConfigLine
from net_models.models.interfaces.InterfaceModels import *
from net_models.models.interfaces.L2InterfaceModels import *
from net_models.models.interfaces.L3InterfaceModels import *

from typing import (
    Union
)

class IosInterfaceParser(BaseConfigLine):

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
    _mtu_regex = re.compile(pattern=r"r^ mtu (?P<mtu>\d+)", flags=re.MULTILINE)
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


    _isis_process_regex = re.compile(pattern=r"^ ip router isis (?P<name>\S+)\Z")
    _isis_network_type_regex = re.compile(pattern=r"^ isis network (?P<network_type>\S+)", flags=re.MULTILINE)
    _isis_circuit_type_regex = re.compile(pattern=r"^ isis circuit-type (?P<circuit_type>\S+)", flags=re.MULTILINE)
    _isis_metric_regex = re.compile(pattern=r"^ isis metric (?P<metric>\d+) (?P<level>\S+)", flags=re.MULTILINE)


    def __init__(self, number: int, text: str, config, verbosity: int):
        super().__init__(number=number, text=text, config=config, verbosity=verbosity, name="IosInterfaceLine")

    @property
    def name(self) -> Union[str, None]:
        return self.re_match(regex=self._name_regex, group=1)

    @property
    def description(self) -> Union[str, None]:
        candidates = self.re_search_children(regex=self._description_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates)

    @property
    def is_enabled(self) -> Union[bool, None]:
        shutdown_candidates = self.re_search_children(regex=self._shutdown_regex, group='shutdown')
        no_shutdown_candidates = self.re_search_children(regex=self._no_shutdown_regex, group='no_shutdown')
        if len(shutdown_candidates) == 1:
            return False
        elif len(no_shutdown_candidates):
            return True
        else:
            if self.config.DEFAULTS.INTERFACES_DEFAULT_NO_SHUTDOWN is not None:
                self.logger.warning(msg="Using platform default value for interface admin state.")
                return self.config.DEFAULTS.INTERFACES_DEFAULT_NO_SHUTDOWN
            else:
                self.logger.debug("Platform default for interface admin state not set.")
                return None

    @property
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
                self.logger.warning(msg="Using platform default value for interface CDP.")
                return InterfaceCdpConfig(enabled=self.config.DEFAULTS.INTERFACES_DEFAULT_CDP_ENABLED)


    @property
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
            self.logger.warning(msg="Using platform default value for interface LLDP transmit.")
            data["transmit"] = self.config.DEFAULTS.INTERFACES_DEFAULT_LLDP_ENABLED

        if len(lldp_receive_candidates):
            data["receive"] = True
        elif len(no_lldp_receive_candidates):
            data["receive"] = False
        elif self.config.DEFAULTS.INTERFACES_DEFAULT_LLDP_ENABLED is not None:
            self.logger.warning(msg="Using platform default value for interface LLDP receive.")
            data["receive"] = self.config.DEFAULTS.INTERFACES_DEFAULT_LLDP_ENABLED

        if any(data.values()):
            return InterfaceLldpConfig(**data)
        else:
            self.logger.debug("Platform default for LLDP not set.")
            return None

    @property
    def mtu(self) -> Union[int, None]:
        candidates = self.re_search_children(regex=self._mtu_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates, wanted_type=int)

    @property
    def ip_mtu(self) -> Union[int, None]:
        candidates = self.re_search_children(regex=self._ip_mtu_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates, wanted_type=int)

    @property
    def bandwidth(self) -> Union[int, None]:
        candidates = self.re_search_children(regex=self._bandwidth_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates, wanted_type=int)

    @property
    def delay(self) -> Union[int, None]:
        candidates = self.re_search_children(regex=self._delay_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates, wanted_type=int)

    @property
    def load_interval(self) -> Union[int, None]:
        candidates = self.re_search_children(regex=self._load_interval_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates, wanted_type=int)

    @property
    def vrf(self) -> Union[str, None]:
        candidates = self.re_search_children(regex=self._vrf_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates)

    @property
    def ipv4_addresses(self) -> Union[InterfaceIPv4Container, None]:
        candidates = self.re_search_children(regex=self._ipv4_addr_regex, group='ALL')
        if len(candidates) == 0:
            return None
        else:
            candidates = [self._val_to_bool(entry=x, keys=['secondary']) for x in candidates]
            candidates = [{'address': f"{x['address']}/{x['mask']}", 'secondary': x['secondary']} for x in candidates]
            return InterfaceIPv4Container(addresses=[InterfaceIPv4Address(**x) for x in candidates])

    @property
    @functools.lru_cache()
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


    @property
    @functools.lru_cache()
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
        results = self.re_search_children(regex=self._isis_metric_regex, group="ALL")
        if len(results):
            data['metric'] = list(results)



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


        return model


