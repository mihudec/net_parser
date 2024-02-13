import functools
import ipaddress
import re
import pathlib
import timeit
from typing import Union, List, Generator, Type

from net_models.validators import normalize_interface_name
from net_models.models.interfaces.InterfaceModels import InterfaceModel
from net_models.models import VRFModel
from net_models.models.services.ServerModels import *
from net_models.inventory import HostConfig, ConfigDefaults


from net_parser.utils import re_search_lines, re_filter_lines, compile_regex, property_autoparse, ObjectQuery, query_filter
from net_parser.config import (
    BaseConfigParser, BaseConfigLine
)
from net_parser.utils.common import compile_regex

FG_OBJECT_REGEX = compile_regex(pattern=r"^\s+edit\s+(?P<object_id>.*?)$")


class FortinetConfigLine(BaseConfigLine):
    _registry = {}

    comment_regex = re.compile(pattern=r"^\s*#.*", flags=re.MULTILINE)

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

    def __init__(self, number: int, text: str, config, verbosity: int = 4, name: str = "FortinetConfigLine"):
        super().__init__(number=number, text=text, config=config, verbosity=verbosity, name=self.__class__.__name__)

    @classmethod
    def from_line_obj(cls, line: 'FortinetConfigLine'):
        return cls(number=line.number, text=line.text, config=line.config, verbosity=line.verbosity)


class FortinetGenericObject(FortinetConfigLine, regex=FG_OBJECT_REGEX):

    _attributes = ['object_id', 'uuid', 'comment']
    _object_regex = FG_OBJECT_REGEX
    _uuid_regex = compile_regex(pattern=r"^\s+set uuid (?P<uuid>\S+)$")
    _comment_regex = compile_regex(pattern=r"^\s+set comment(?:s)? (?P<comment>.+?)$")
    _quoted_string_regex = compile_regex(pattern=r'"(?P<content>.+?)"')

    def __init__(self, number: int, text: str, config: 'FortinetConfigParser', verbosity: int = 4):
        super().__init__(number=number, text=text, config=config, verbosity=verbosity)
        self.refs = list()
        self.refs_by = list()

    def add_ref(self, target: 'FortinetGenericObject'):
        ref = FortinetObjectReference.get_ref(source=self, target=target)
        self.refs.append(ref)
        target.refs_by.append(ref)

    def update_refs(self):
        pass

    @functools.cached_property
    def object_id(self) -> Union[str, None]:
        object_id = self.re_match(regex=self._object_regex, group=1)
        if object_id is not None:
            object_id = object_id.strip('"')
        return object_id

    @functools.cached_property
    def uuid(self):
        candidates = self.re_search_children(regex=self._uuid_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates)

    @functools.cached_property
    def comment(self):
        candidates = self.re_search_children(regex=self._comment_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates)

    def to_dict(self, exclude_none: bool = False):
        data = {}
        for attribute in self._attributes:
            try:
                value = getattr(self, attribute)
                if exclude_none and value is None:
                    continue
                data[attribute] = value
            except AttributeError as e:
                pass
        return data


class FortinetCustomObject(FortinetGenericObject):

    def __new__(cls, *args, **kwargs):
        return object.__new__(cls)

    @functools.cached_property
    def raw_data(self):
        set_statements = self.re_search_children(regex=compile_regex(pattern=r"^\s+set (?P<key>\S+) (?P<value>.*?)$"), group="ALL")
        data = dict()
        for statement in set_statements:
            key = statement['key']
            value = statement['value'].strip()
            if ' ' in value:
                value = [x.strip('"') for x in value.split(' ')]
            else:
                value = value.strip('"')
            data[key] = value
        return data

    def __str__(self):
        return f"[{self.__class__.__name__}: {self.name}]"


class FortiGateCustomObject(FortinetCustomObject):
    
    _attributes = FortinetGenericObject._attributes + ['name', 'comments']

    @property
    def name(self):
        return self.object_id


class FortiAdcCustomObject(FortinetCustomObject):

    _attributes = FortinetGenericObject._attributes + ['name', 'status', 'comments', 'description']
    _attributes.remove('object_id')
    _attributes.remove('comment')
    _attributes.remove('uuid')
    _status_regex = compile_regex(pattern=r"^\s+set status (?P<status>\S+)$")
    _type_regex = compile_regex(pattern=r"^\s+set type (?P<type>\S+)$")
    _comments_regex = compile_regex(pattern=r"^\s+set comments (?:\")?(?P<comments>\S+)(?:\")?$")
    _description_regex = compile_regex(pattern=r"^\s+set description (?P<description>\S+)$")
    _ip_regex = compile_regex(pattern=r"^\s+set ip (?P<ip>\S+)$")

    def parse_objects(self):
        pass

    @property
    def name(self):
        return self.object_id

    @functools.cached_property
    def comments(self):
        candidates = self.re_search_children(regex=self._comments_regex, group=1, max_depth=1)
        return self.first_candidate_or_none(candidates=candidates)

    @functools.cached_property
    def status(self):
        candidates = self.re_search_children(regex=self._status_regex, group=1, max_depth=1)
        return self.first_candidate_or_none(candidates=candidates)

    @functools.cached_property
    def description(self):
        candidates = self.re_search_children(regex=self._description_regex, group=1, max_depth=1)
        return self.first_candidate_or_none(candidates=candidates)



class FortinetObjectReference:

    _cache = {}

    @classmethod
    def get_ref(cls, source: FortinetGenericObject, target: FortinetGenericObject):
        key = (source, target)
        if key not in cls._cache:
            cls._cache[key] = cls(source=source, target=target)
        return cls._cache[key]

    def __init__(self, source: FortinetGenericObject, target: FortinetGenericObject):
        self.source = source
        self.target = target

    def __str__(self):
        return f"{self.source.__class__.__name__}: {self.source.name} -> {self.target.__class__.__name__}: {self.target.name}"

    def __repr__(self):
        return self.__str__()


class FortinetConfigSection(FortinetConfigLine):

    REGEX = None
    MEMBER_CLS = None

    def __new__(cls, *args, **kwargs):
        return object.__new__(cls)

    def __init__(self, number: int, text: str, config: 'FortinetConfigParser', verbosity: int = 4):
        super().__init__(number=number, text=text, config=config, verbosity=verbosity, name=self.__class__.__name__)

    def parse_objects(self):
        children = [x for x in self.get_children(max_depth=1) if isinstance(x, FortinetGenericObject)]
        for child in children:
            self.logger.debug(msg=f"Converting Line #{child.number} to {self.MEMBER_CLS.__name__}")
            child = self.MEMBER_CLS.from_line_obj(line=child)
            self.config.lines[child.number] = child
            # Parse children objects
            if hasattr(child, 'parse_objects'):
                child.parse_objects()

    def get_objects(self):
        for obj in self.get_children(max_depth=1):
            if not isinstance(obj, self.MEMBER_CLS):
                continue
            yield obj


class FortiAdcVirtualServer(FortiAdcCustomObject):
    _attributes = FortiAdcCustomObject._attributes + [
        'type',
        'interface',
        'ip',
        'port',
        'load_balance_profile',
        'load_balance_pool',
        'content_routing_list',
        'waf_profile'
    ]

    def update_refs(self):
        if self.load_balance_pool_obj is not None:
            self.add_ref(target=self.load_balance_pool_obj)
        if self.waf_profile_obj is not None:
            self.add_ref(target=self.waf_profile_obj)
        if self.content_routing_list_obj is not None:
            for cr in self.content_routing_list_obj:
                self.add_ref(target=cr)


    @functools.cached_property
    def type(self):
        return self.raw_data.get('type')

    @functools.cached_property
    def interface(self):
        return self.raw_data.get('interface')

    @functools.cached_property
    def ip(self):
        ip = self.raw_data.get('ip')
        if ip is not None:
            ip = ipaddress.IPv4Address(ip)
            return ip

    @functools.cached_property
    def port(self):
        port = self.raw_data.get('port')
        # if port is not None:
            # if isinstance(port, list):
            #     port = [int(x) for x in port]
            # else:
            #     port = int(port)
        return port

    @functools.cached_property
    def load_balance_profile(self):
        return self.raw_data.get('load-balance-profile')

    @functools.cached_property
    def client_ssl_profile(self):
        return self.raw_data.get('client-ssl-profile')

    @functools.cached_property
    def load_balance_pool(self):
        return self.raw_data.get('load-balance-pool')

    @functools.cached_property
    def load_balance_pool_obj(self):
        query = ObjectQuery(
            key='name',
            operator='Eq',
            value=self.load_balance_pool
        )
        candidates = list(self.config.real_server_pools(query=query))
        real_server_pool = self.first_candidate_or_none(candidates=candidates)
        return real_server_pool

    @functools.cached_property
    def content_routing_list(self):
        content_routing_list = None
        raw = self.raw_data.get('content-routing-list')
        if raw is None:
            pass
        if isinstance(raw, list):
            content_routing_list = raw
        if isinstance(raw, str):
            content_routing_list = [raw]
        return content_routing_list


    @functools.cached_property
    def content_routing_list_obj(self):
        query = ObjectQuery(
            key='name',
            operator='In',
            value=self.content_routing_list
        )
        if self.content_routing_list is None:
            return None
        candidates = list(self.config.content_routings(query=query))
        return candidates

    @functools.cached_property
    def waf_profile(self):
        return self.raw_data.get('waf-profile')

    @functools.cached_property
    def waf_profile_obj(self):
        query = ObjectQuery(
            key='name',
            operator='Eq',
            value=self.waf_profile
        )
        candidates = list(self.config.waf_profiles(query=query))
        waf_profile = self.first_candidate_or_none(candidates=candidates)
        return waf_profile


class FortiAdcRealServer(FortiAdcCustomObject):
    _attributes = FortiAdcCustomObject._attributes + [
        'type',
        'ip',
    ]

    @functools.cached_property
    def type(self):
        return self.raw_data.get('type')

    @functools.cached_property
    def ip(self):
        ip = self.raw_data.get('ip')
        if ip is not None:
            ip = ipaddress.IPv4Address(ip)
            return ip


class FortiAdcRealServerPoolMember(FortiAdcCustomObject):
    _attributes = FortiAdcCustomObject._attributes + [
        'real_server'
    ]

    @functools.cached_property
    def name(self):
        return self.real_server

    @functools.cached_property
    def real_server(self):
        return self.raw_data.get('real-server')

    @functools.cached_property
    def real_server_obj(self):
        query = ObjectQuery(
            key='name',
            operator="Eq",
            value=self.real_server
        )
        candidates = list(self.config.real_servers(query=query))
        real_server = self.first_candidate_or_none(candidates=candidates)
        return real_server


class FortiAdcRealServerPool(FortiAdcCustomObject):

    _attributes = FortiAdcCustomObject._attributes + [
        'members',
        'type',
        'health_check_ctrl',
        'health_check_list',
        'health_check_relation',
        'real_server_ssl_profile'
    ]

    def parse_objects(self):
        pool_config_line = self.re_search_children(regex=compile_regex(pattern=r'config\s+pool_member$'), max_depth=1)
        pool_config_line = self.first_candidate_or_none(candidates=pool_config_line)
        if pool_config_line is None:
            return None
        member_lines = [x for x in pool_config_line.get_children(max_depth=1) if isinstance(x, FortinetGenericObject)]
        for member_line in member_lines:
            self.logger.debug(msg=f"Converting Line #{member_line.number} to {FortiAdcRealServerPoolMember.__name__}")
            member_line = FortiAdcRealServerPoolMember.from_line_obj(line=member_line)
            self.config.lines[member_line.number] = member_line

    def update_refs(self):
        for member in self.members:
            self.add_ref(target=member)
            if member.real_server_obj is not None:
                member.add_ref(target=member.real_server_obj)
                self.add_ref(target=member.real_server_obj)

    @functools.cached_property
    def type(self):
        return self.raw_data.get('type')

    @functools.cached_property
    def health_check_ctrl(self):
        return self.raw_data.get('health-check-ctrl')

    @functools.cached_property
    def health_check_list(self):
        return self.raw_data.get('health-check-list')

    @functools.cached_property
    def health_check_relation(self):
        return self.raw_data.get('health-check-relation')

    @functools.cached_property
    def real_server_ssl_profile(self):
        return self.raw_data.get('real-server-ssl-profile')

    @functools.cached_property
    def members(self) -> List[FortiAdcRealServerPoolMember]:
        return [x for x in self.get_children() if isinstance(x, FortiAdcRealServerPoolMember)]


class FortiAdcContentRouting(FortiAdcCustomObject):

    def update_refs(self):
        if self.load_balance_pool_obj is not None:
            self.add_ref(target=self.load_balance_pool_obj)


    @functools.cached_property
    def load_balance_pool(self):
        return self.raw_data.get('load-balance-pool')

    @functools.cached_property
    def load_balance_pool_obj(self):
        query = ObjectQuery(
            key='name',
            operator="Eq",
            value=self.load_balance_pool
        )
        candidates = list(self.config.real_server_pools(query=query))
        real_server_pool = self.first_candidate_or_none(candidates=candidates)
        return real_server_pool


class FortiAdcWafProfile(FortiAdcCustomObject):
    pass


class FortiAdcVirtualServers(FortinetConfigSection):

    REGEX = compile_regex(pattern=r"config load-balance virtual-server$")
    MEMBER_CLS = FortiAdcVirtualServer


class FortiAdcRealServers(FortinetConfigSection):

    REGEX = compile_regex(pattern=r"config load-balance real-server$")
    MEMBER_CLS = FortiAdcRealServer


class FortiAdcRealServerPools(FortinetConfigSection):

    REGEX = compile_regex(pattern=r"config load-balance pool$")
    MEMBER_CLS = FortiAdcRealServerPool


class FortiAdcContentRoutings(FortinetConfigSection):

    REGEX = compile_regex(pattern=r"config load-balance content-routing$")
    MEMBER_CLS = FortiAdcContentRouting


class FortiAdcWafProfiles(FortinetConfigSection):

    REGEX = compile_regex(pattern=r"config security waf profile$")
    MEMBER_CLS = FortiAdcWafProfile




#################### FortiGate ####################




class FortiGateAddressObject(FortiGateCustomObject):

    _attributes = FortinetGenericObject._attributes + ['address_type', 'subnet', 'fqdn', 'iprange', 'interface']

    _type_regex = compile_regex(pattern=r"^\s+set type (?P<address_type>\S+)$")
    _subnet_regex = compile_regex(pattern=r"^\s+set subnet (?P<address>\S+) (?P<mask>\S+)$")
    _fqdn_regex = compile_regex(pattern=r"^\s+set fqdn (?P<fqdn>\S+)$")
    _iprange_regex = compile_regex(pattern=r"^\s+set (?P<index>start|end)-ip (?P<address>\S+)$")
    _color_regex = compile_regex(pattern=r"^\s+set color (?P<color>\S+)$")
    _uuid_regex = compile_regex(pattern=r"^\s+set uuid (?P<uuid>\S+)$")
    _interface_regex = compile_regex(pattern=r"^\s+set interface (?P<interface>\S+)$")
    _associated_interface_regex = compile_regex(pattern=r"^\s+set associated-interface (?P<interface>\S+)$")

    @functools.cached_property
    def address_type(self):
        candidates = self.re_search_children(regex=self._type_regex, group=1)
        address_type = self.first_candidate_or_none(candidates=candidates)
        if address_type is None:
            address_type = 'ipmask'
        return address_type

    @functools.cached_property
    def color(self):
        candidates = self.re_search_children(regex=self._color_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates)

    @functools.cached_property
    def subnet(self):
        candidates = self.re_search_children(regex=self._subnet_regex, group='ALL')
        subnet_dict = self.first_candidate_or_none(candidates=candidates)
        subnet = None
        if subnet_dict is not None:
            try:
                subnet = ipaddress.IPv4Network(f"{subnet_dict['address']}/{subnet_dict['mask']}")
            except ValueError as e:
                subnet = ipaddress.IPv4Interface(f"{subnet_dict['address']}/{subnet_dict['mask']}")
                subnet = subnet.network
            except Exception as e:
                raise
        if self.object_id == 'all' and self.address_type == 'ipmask':
            subnet = ipaddress.IPv4Network("0.0.0.0/0")
        return subnet

    @functools.cached_property
    def fqdn(self):
        if self.address_type == 'fqdn':
            candidates = self.re_search_children(regex=self._fqdn_regex, group=1)
            fqdn = self.first_candidate_or_none(candidates=candidates)
            if fqdn is not None:
                fqdn = fqdn.strip('"')
            return fqdn
        else:
            return None

    @functools.cached_property
    def iprange(self) -> Union[List[ipaddress.IPv4Address], None]:
        candidates = self.re_search_children(regex=self._iprange_regex, group="ALL")
        iprange = None
        if not len(candidates) == 2:
            pass
        else:
            iprange = [None, None]
            for candidate in candidates:
                if candidate['index'] == 'start':
                    iprange[0] = ipaddress.ip_address(candidate['address'])
                if candidate['index'] == 'end':
                    iprange[1] = ipaddress.ip_address(candidate['address'])
        return iprange

    @functools.cached_property
    def interface(self):
        if self.address_type == 'interface-subnet':
            candidates = self.re_search_children(regex=self._interface_regex, group=1)
            return self.first_candidate_or_none(candidates=candidates)
        else:
            return None
        
    @functools.cached_property
    def address_size(self):
        if self.address_type == "ipmask":
            if self.subnet is None:
                return 0
            else:
                return self.subnet.num_addresses
        if self.address_type == "iprange":
            subnets = ipaddress.summarize_address_range(*self.iprange)
            num_addresses = 0
            for subnet in subnets:
                num_addresses += subnet.num_addresses
            return num_addresses
        return 0

            
        


class FortiGateAddressGroup(FortiGateCustomObject):

    _attributes = FortinetGenericObject._attributes + ['members']
    _member_regex = compile_regex(pattern=r"^\s+set member (?P<members>.+)$")

    def update_refs(self):
        for name in self.members:
            member_obj = self.config.get_firewall_address_or_group(name=name)
            if member_obj is None:
                self.logger.error(msg=f"Could not find {member} of {self.name} in addresses or groups")
            else:
                self.add_ref(target=member_obj)


    @functools.cached_property
    def members(self):
        candidates = self.re_search_children(regex=self._member_regex, group=1)
        members = self.first_candidate_or_none(candidates=candidates)
        if members is not None:
            members = [x.group(1) for x in self._quoted_string_regex.finditer(string=members)]
        return members
    
    @functools.cached_property
    def address_size(self):
        members = [x.target for x in self.refs if isinstance(x.target, FortiGateAddressObject)]
        return sum([x.address_size for x in members])


class FortiGateServiceCustom(FortiGateCustomObject):

    _attributes = FortinetGenericObject._attributes + ['category', 'protocol', 'protocol_number', 'port_range_tcp',
                                                 'port_range_udp']

    _category_regex = compile_regex(pattern=r"^\s+set category (?P<category>.+)$")
    _protocol_regex = compile_regex(pattern=r"^\s+set protocol (?P<protocol>\S+)$")
    _protocol_number_regex = compile_regex(pattern=r"^\s+set protocol-number (?P<protocol_number>\d+)$")
    _tcp_portrange_regex = compile_regex(pattern=r"^\s+set tcp-portrange (?P<tcp_portrange>.+)$")
    _udp_portrange_regex = compile_regex(pattern=r"^\s+set udp-portrange (?P<udp_portrange>.+)$")

    @functools.cached_property
    def category(self):
        candidates = self.re_search_children(regex=self._category_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates)

    @functools.cached_property
    def protocol(self):
        candidates = self.re_search_children(regex=self._protocol_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates)

    @functools.cached_property
    def protocol_number(self):
        candidates = self.re_search_children(regex=self._protocol_number_regex, group=1)
        return self.first_candidate_or_none(candidates=candidates)

    @functools.cached_property
    def port_range_tcp(self):
        candidates = self.re_search_children(regex=self._tcp_portrange_regex, group=1)
        ports = self.first_candidate_or_none(candidates=candidates)
        if ports is not None:
            ports = [x for x in ports.split(' ')]
        return ports

    @functools.cached_property
    def port_range_udp(self):
        candidates = self.re_search_children(regex=self._udp_portrange_regex, group=1)
        ports = self.first_candidate_or_none(candidates=candidates)
        if ports is not None:
            ports = [x for x in ports.split(' ')]
        return ports


class FortiGateServiceGroup(FortiGateCustomObject):

    _attributes = FortinetGenericObject._attributes + ['members']
    _member_regex = compile_regex(pattern=r"^\s+set member (?P<members>.+)$")

    @functools.cached_property
    def members(self):
        candidates = self.re_search_children(regex=self._member_regex, group=1)
        members = self.first_candidate_or_none(candidates=candidates)
        if members is not None:
            members = [x.group(1) for x in self._quoted_string_regex.finditer(string=members)]
        return members


class FortiGatePolicy(FortiGateCustomObject):

    _attributes = FortinetGenericObject._attributes + ['name', 'action', 'nat', 'log_traffic', 'src_interface', 'dest_interface', 'src_address',
                                                 'dest_address', 'service']

    _action_regex = compile_regex(pattern=r"^\s+set action (?P<action>\S+)$")
    _name_regex = compile_regex(pattern=r"^\s+set name (?P<address_type>\S+)$")
    _src_interface_regex = compile_regex(pattern=r"^\s+set srcintf (?P<src_interface>.+)$")
    _dest_interface_regex = compile_regex(pattern=r"^\s+set dstintf (?P<dest_interface>.+)$")
    _src_address_regex = compile_regex(pattern=r"^\s+set srcaddr (?P<src_address>.+)$")
    _dest_address_regex = compile_regex(pattern=r"^\s+set dstaddr (?P<dest_address>.+)$")
    _service_regex = compile_regex(pattern=r"^\s+set service (?P<service>.+)$")
    _nat_regex = compile_regex(pattern=r"^\s+set nat (?P<nat>\S+)$")
    _logtraffic_regex = compile_regex(pattern=r"^\s+set logtraffic (?P<logtraffic>\S+)$")


    def update_refs(self):
        # Source Addresses
        if self.src_address is None:
            self.logger.warning(msg=f"Policy {self.object_id} does not have src_address")
        else:
            for name in self.src_address:
                service_obj = self.config.get_firewall_address_or_group(name=name)
                if service_obj is None:
                    self.logger.error(msg=f"Could not find src_address: {name} of policy {self.name}")
                else:
                    self.add_ref(target=service_obj)
    
        # Destination Addresses
        if self.dest_address is None:
            self.logger.warning(msg=f"Policy {self.object_id} does not have dst_address")
        else:
            for name in self.dest_address:
                service_obj = self.config.get_firewall_address_or_group(name=name)
                if service_obj is None:
                    self.logger.error(msg=f"Could not find dest_address: {name} of policy {self.name}")
                else:
                    self.add_ref(target=service_obj)

        # Services
        if self.service is None:
            self.logger.warning(msg=f"Policy {self.object_id} does not have service")
        else:
            for name in self.service:
                service_obj = self.config.get_firewall_service_or_group(name=name)
                if service_obj is None:
                    self.logger.error(msg=f"Could not find service: {name} of policy {self.name}")
                else:
                    self.add_ref(target=service_obj)

        

    @functools.cached_property
    def name(self) -> Union[str, None]:
        candidates = self.re_search_children(regex=self._name_regex, group=1)
        name = self.first_candidate_or_none(candidates=candidates)
        if name is not None:
            name = name.strip('"')
        return name

    @functools.cached_property
    def action(self) -> Union[Literal['accept', 'deny', 'ipsec'], None]:
        candidates = self.re_search_children(regex=self._action_regex, group=1)
        action = self.first_candidate_or_none(candidates=candidates)
        return action

    @functools.cached_property
    def nat(self) -> bool:
        candidates = self.re_search_children(regex=self._nat_regex, group=1)
        nat = self.first_candidate_or_none(candidates=candidates)
        if nat is not None:
            if nat == 'enable':
                nat = True
        else:
            nat = False
        return nat

    @functools.cached_property
    def log_traffic(self) -> bool:
        candidates = self.re_search_children(regex=self._logtraffic_regex, group=1)
        log_traffic = self.first_candidate_or_none(candidates=candidates)
        return log_traffic

    @functools.cached_property
    def src_interface(self) -> Union[str, None]:
        candidates = self.re_search_children(regex=self._src_interface_regex, group=1)
        src_interfaces = self.first_candidate_or_none(candidates=candidates)
        if src_interfaces is not None:
            src_interfaces = [x.group(1) for x in self._quoted_string_regex.finditer(string=src_interfaces)]
        return src_interfaces

    @functools.cached_property
    def dest_interface(self) -> Union[str, None]:
        candidates = self.re_search_children(regex=self._dest_interface_regex, group=1)
        dest_interfaces = self.first_candidate_or_none(candidates=candidates)
        if dest_interfaces is not None:
            dest_interfaces = [x.group(1) for x in self._quoted_string_regex.finditer(string=dest_interfaces)]
        return dest_interfaces

    @functools.cached_property
    def src_address(self) -> Union[str, None]:
        candidates = self.re_search_children(regex=self._src_address_regex, group=1)
        src_address = self.first_candidate_or_none(candidates=candidates)
        if src_address is not None:
            src_address = [x.group(1) for x in self._quoted_string_regex.finditer(string=src_address)]
        return src_address

    @functools.cached_property
    def dest_address(self) -> Union[str, None]:
        candidates = self.re_search_children(regex=self._dest_address_regex, group=1)
        dest_address = self.first_candidate_or_none(candidates=candidates)
        if dest_address is not None:
            dest_address = [x.group(1) for x in self._quoted_string_regex.finditer(string=dest_address)]
        return dest_address

    @functools.cached_property
    def service(self) -> Union[str, None]:
        candidates = self.re_search_children(regex=self._service_regex, group=1)
        service = self.first_candidate_or_none(candidates=candidates)
        if service is not None:
            service = [x.strip('"') for x in service.split(' ')]
        return service


class FortiGateFirewallVip(FortiGateCustomObject):
    
    _attributes = FortinetGenericObject._attributes + ['name', 'external_ip', 'internal_ip', 'external_interface', 'service']
    
    @functools.cached_property
    def external_ip(self):
        return ipaddress.IPv4Address(self.raw_data.get('extip'))
    
    @functools.cached_property
    def internal_ip(self):
        return ipaddress.IPv4Address(self.raw_data.get('mappedip'))
    
    @functools.cached_property
    def external_interface(self):
        return self.raw_data.get('extintf')
    
    @functools.cached_property
    def service(self):
        return self.raw_data.get('service')
    




class FortinetConfigParser(BaseConfigParser):

    CONFIG_LINE_CLS = FortinetConfigLine
    SECTION_CLASSES: List[FortinetConfigSection] = []

    def __init__(self, config: Union[pathlib.Path, List[str], str], verbosity: int = 4, name: str = "FortinetConfigParser", defaults: Type[ConfigDefaults] = None, **kwargs):
        super().__init__(config=config, verbosity=verbosity, name=name, **kwargs)
        self.DEFAULTS = defaults or ConfigDefaults()

    def parse(self):
        super().parse()
        if len(self.SECTION_CLASSES):
            for section in self.SECTION_CLASSES:
                candidates = self.re_search_lines(regex=section.REGEX)
                for candidate in candidates:
                    if not isinstance(candidate, FortinetConfigSection):
                        self.logger.debug(msg=f"Converting Line #{candidate.number} to {section.__name__}")
                        line = section.from_line_obj(line=candidate)
                        self.lines[line.number] = line
                        line.parse_objects()

    def get_objects(self, cls: Type[FortinetGenericObject]):
        for line in self.lines:
            if not isinstance(line, cls):
                continue
            yield line

    def update_refs(self):
        for line in self.get_objects(cls=FortinetGenericObject):
            line.update_refs()

class FortiAdcConfigParser(FortinetConfigParser):

    SECTION_CLASSES = [
        FortiAdcVirtualServers,
        FortiAdcRealServers,
        FortiAdcRealServerPools,
        FortiAdcContentRoutings,
        FortiAdcWafProfiles
    ]

    def __init__(self, config: Union[pathlib.Path, List[str], str], verbosity: int = 4, name: str = "FortiAdcConfigParser", defaults: Type[ConfigDefaults] = None, **kwargs):
        super().__init__(config=config, verbosity=verbosity, name=name, **kwargs)


    def virtual_servers(self, query: ObjectQuery = None):
        return query_filter(self.get_objects(cls=FortiAdcVirtualServer), query)

    def real_servers(self, query: ObjectQuery = None):
        return query_filter(self.get_objects(cls=FortiAdcRealServer), query)

    def real_server_pools(self, query: ObjectQuery = None):
        return query_filter(self.get_objects(cls=FortiAdcRealServerPool), query)

    def content_routings(self, query: ObjectQuery = None):
        return query_filter(self.get_objects(cls=FortiAdcContentRouting), query)

    def waf_profiles(self, query: ObjectQuery = None):
        return query_filter(self.get_objects(cls=FortiAdcWafProfile), query)



class FortiGateAddressObjectSection(FortinetConfigSection):

    REGEX = compile_regex(pattern=r"^config firewall address$")
    MEMBER_CLS = FortiGateAddressObject



class FortiGateAddressGroupSection(FortinetConfigSection):

    REGEX = compile_regex(pattern=r"^config firewall addrgrp$")
    MEMBER_CLS = FortiGateAddressGroup



class FortiGateServiceCustomSection(FortinetConfigSection):

    REGEX = compile_regex(pattern=r"^config firewall service custom$")
    MEMBER_CLS = FortiGateServiceCustom


class FortiGateServiceGroupSection(FortinetConfigSection):

    REGEX = compile_regex(pattern=r"^config firewall service group$")
    MEMBER_CLS = FortiGateServiceGroup



class FortiGatePolicySection(FortinetConfigSection):

    REGEX = compile_regex(pattern=r"^config firewall policy$")
    MEMBER_CLS = FortiGatePolicy

class FortiGateFirewallVipSection(FortinetConfigSection):

    REGEX = compile_regex(r"^config firewall vip$")
    MEMBER_CLS = FortiGateFirewallVip



class FortiGateConfigParser(FortinetConfigParser):

    SECTION_CLASSES = [
        FortiGateAddressObjectSection,
        FortiGateAddressGroupSection,
        FortiGateServiceCustomSection,
        FortiGateServiceGroupSection,
        FortiGatePolicySection,
        FortiGateFirewallVipSection
    ]

    def __init__(self, config: Union[pathlib.Path, List[str], str], verbosity: int = 4, defaults: Type[ConfigDefaults] = None, **kwargs):
        super().__init__(config=config, verbosity=verbosity, name="FortiGateConfigParser", **kwargs)

    # def parse(self):
    #     super(FortiGateConfigParser, self).parse()
    #     self._build_firewall_addresses()
    #     self._build_firewall_address_groups()
    #     self._build_firewall_service_custom()
    #     self._build_firewall_service_group()
    #     self._build_firewall_policy()



    def firewall_addresses(self, query: ObjectQuery = None) -> Generator[FortiGateAddressObject, None, None]:
        return query_filter(self.get_objects(cls=FortiGateAddressObject), query)



    def firewall_address_groups(self, query: ObjectQuery = None) -> Generator[FortiGateAddressGroup, None, None]:
        return query_filter(self.get_objects(cls=FortiGateAddressGroup), query)
    

    def firewall_services_custom(self, query: ObjectQuery = None) -> Generator[FortiGateServiceCustom, None, None]:
        return query_filter(self.get_objects(cls=FortiGateServiceCustom), query)
    
    def firewall_service_groups(self, query: ObjectQuery = None) -> Generator[FortiGateServiceGroup, None, None]:
        return query_filter(self.get_objects(cls=FortiGateServiceGroup), query)
    
    def firewall_service_groups(self, query: ObjectQuery = None) -> Generator[FortiGateServiceGroup, None, None]:
        return query_filter(self.get_objects(cls=FortiGateServiceGroup), query)
    
    def firewall_policies(self, query: ObjectQuery = None) -> Generator[FortiGatePolicy, None, None]:
        return query_filter(self.get_objects(cls=FortiGatePolicy), query)
    
    def get_firewall_address(self, name: str):
        return self.first_candidate_or_none([x for x in self.firewall_addresses if x.object_id == name])
    
    def get_firewall_address_or_group(self, name: str) -> Union[FortiGateAddressObject, FortiGateAddressGroup]:
        if name in self.firewall_addresses_map.keys():
            return self.firewall_addresses_map[name]
        elif name in self.firewall_address_groups_map.keys():
            return self.firewall_address_groups_map[name]
        else:
            return None
    
    def get_firewall_service_or_group(self, name: str) -> Union[FortiGateServiceCustom, FortiGateServiceGroup]:
        if name in self.firewall_services_map.keys():
            return self.firewall_services_map[name]
        elif name in self.firewall_service_groups_map.keys():
            return self.firewall_service_groups_map[name]
        else:
            return None
    
    @functools.cached_property
    def firewall_addresses_map(self):
        return {x.name: x for x in self.firewall_addresses()}

    @functools.cached_property
    def firewall_address_groups_map(self):
        return {x.name: x for x in self.firewall_address_groups()}

    @functools.cached_property
    def firewall_services_map(self):
        return {x.name: x for x in self.firewall_services_custom()}
    
    @functools.cached_property
    def firewall_service_groups_map(self):
        return {x.name: x for x in self.firewall_service_groups()}
