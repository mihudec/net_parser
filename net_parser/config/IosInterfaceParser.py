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
    _lldp_transmit_regex = re.compile(pattern="^ lldp transmit\Z", flags=re.MULTILINE)
    _no_lldp_transmit_regex = re.compile(pattern="^ no lldp transmit\Z", flags=re.MULTILINE)
    _lldp_receive_regex = re.compile(pattern="^ lldp receive\Z", flags=re.MULTILINE)
    _no_lldp_receive_regex = re.compile(pattern="^ no lldp receive\Z", flags=re.MULTILINE)
    _mtu_regex = re.compile(pattern=r"^ mtu (?P<mtu>\d+)", flags=re.MULTILINE)
    _ip_mtu_regex = re.compile(pattern=r"^ ip mtu (?P<ip_mtu>\d+)", flags=re.MULTILINE)
    _bandwidth_regex = re.compile(pattern=r"^ bandwidth (?P<bandwidth>\d+)", flags=re.MULTILINE)
    _delay_regex = re.compile(pattern=r"^ delay (?P<delay>\d+)", flags=re.MULTILINE)
    _load_interval_regex = re.compile(pattern=r"^ load-interval (?P<load_interval>\d+)")


    _ospf_process_regex = re.compile(pattern=r"^ ip ospf (?P<process_id>\d+) area (?P<area>\d+)$", flags=re.MULTILINE)
    _ospf_network_type_regex = re.compile(pattern=r"^ ip ospf network (?P<network_type>\S+)", flags=re.MULTILINE)
    _ospf_priority_regex = re.compile(pattern=r"^ ip ospf priority (?P<priority>\d+)", flags=re.MULTILINE)
    _ospf_cost_regex = re.compile(pattern=r"^ ip ospf cost (?P<cost>\d+)", flags=re.MULTILINE)



    def __init__(self, number: int, text: str, config, verbosity: int):
        super().__init__(number=number, text=text, config=config, verbosity=verbosity, name="IosInterfaceLine")

    def first_candidate_or_none(self, candidates: list, wanted_type=None):
        if len(candidates) == 0:
            return None
        elif len(candidates) == 1:
            if wanted_type is None:
                return candidates[0]
            else:
                return wanted_type(candidates[0])
        else:
            self.logger.error(msg='Multiple candidates found.')
            return None

    @property
    def name(self) -> bool:
        return self.re_match(regex=self._name_regex, group=1)

    @property
    def description(self) -> bool:
        candidates = self.re_search_children(regex=self._description_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates)

    def is_enabled(self, platform_default_enabled: bool = True) -> bool:
        shutdown_candidates = self.re_search_children(regex=self._shutdown_regex, group='shutdown')
        no_shutdown_candidates = self.re_search_children(regex=self._no_shutdown_regex, group='no_shutdown')
        if len(shutdown_candidates) == 1:
            return False
        elif len(no_shutdown_candidates):
            return True
        else:
            self.logger.warning(msg="Using platform default value for interface admin state.")
            return platform_default_enabled

    def cdp(self, platform_default_enabled: bool = None):
        cdp_candidates = self.re_search_children(regex=self._cdp_regex, group=1)
        no_cdp_candidates = self.re_search_children(regex=self._no_cdp_regex, group=1)
        if len(cdp_candidates) == 1:
            return InterfaceCdpConfig(enabled=True)
        elif len(no_cdp_candidates):
            return InterfaceCdpConfig(enabled=True)
        else:
            self.logger.warning(msg="Using platform default value for interface CDP.")
            return InterfaceCdpConfig(enabled=platform_default_enabled)

    def lldp(self, platform_default_enabled: bool = True) -> Union[InterfaceLldpConfig, None]:
        lldp_transmit_candidates = self.re_search_children(regex=self._lldp_transmit_regex)
        no_lldp_transmit_candidates = self.re_search_children(regex=self._no_lldp_transmit_regex)
        lldp_receive_candidates = self.re_search_children(regex=self._lldp_receive_regex)
        no_lldp_receive_candidates = self.re_search_children(regex=self._no_lldp_receive_regex)

        lldp = InterfaceLldpConfig()

        if len(lldp_transmit_candidates):
            lldp.transmit = True
        elif len(no_lldp_transmit_candidates):
            lldp.transmit = False
        else:
            lldp.transmit = platform_default_enabled

        if len(lldp_receive_candidates):
            lldp.receive = True
        elif len(no_lldp_receive_candidates):
            lldp.receive = False
        else:
            lldp.receive = platform_default_enabled

        return lldp

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
    def ospf(self) -> Union[InterfaceOspfConfig, None]:
        ospf = {}
        process_candidates = self.first_candidate_or_none(self.re_search_children(regex=self._ospf_process_regex, group='ALL'))
        network_type = self.first_candidate_or_none(self.re_search_children(regex=self._ospf_network_type_regex, group='ALL'))
        cost = self.first_candidate_or_none(self.re_search_children(regex=self._ospf_cost_regex, group='ALL'))
        priority = self.first_candidate_or_none(self.re_search_children(regex=self._ospf_cost_regex, group='ALL'))
        if process_candidates is not None:
            ospf.update(process_candidates)
        if network_type is not None:
            ospf.update(network_type)
        if cost is not None:
            ospf.update(cost)
        if priority is not None:
            ospf.update(priority)

        if len(ospf) == 0:
            return None
        else:
            return InterfaceOspfConfig(**ospf)


    def to_model(self) -> InterfaceModel:
        model = InterfaceModel(
            name=self.name,
            description=self.description,
            enabled=self.is_enabled()
        )


        l3_parameters = [
            self.ipv4_addresses,
            self.ip_mtu,
            self.vrf
        ]
        if any(l3_parameters):
            if model.l3_port is None:
                model.l3_port = InterfaceRouteportModel()

        discovery_parameters = [
            self.cdp(),
            self.lldp()
        ]
        if any(discovery_parameters):
            if model.discovery_protocols is None:
                model.discovery_protocols = InterfaceDiscoveryProtocols()


        if self.load_interval is not None:
            model.load_interval = self.load_interval
        if self.delay is not None:
            model.delay = self.delay
        if self.bandwidth is not None:
            model.bandwidth = self.bandwidth
        if self.cdp() is not None:
            model.discovery_protocols.cdp = self.cdp()
        if self.lldp() is not None:
            model.discovery_protocols.lldp = self.lldp()

        if self.mtu is not None:
            model.mtu = self.mtu



        if self.ipv4_addresses is not None:
            model.l3_port.ipv4 = self.ipv4_addresses
        if self.vrf is not None:
            model.l3_port.vrf = self.vrf
        if self.ip_mtu is not None:
            model.l3_port.ip_mtu = self.ip_mtu
        return model


