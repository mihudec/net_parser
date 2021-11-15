import ipaddress
from pydantic.typing import Any, Dict, List, Literal, Optional, Type, Union
from pydantic import validator, root_validator, Extra
from pydantic import constr
from net_models.models import BaseNetModel
from net_models.fields import InterfaceName

class BaseOpsModel(BaseNetModel):

    class Config:
        extra = Extra.allow
        validate_assignment = True
        anystr_strip_whitespace = True


class NeighborOpsModel(BaseOpsModel):

    hostname: str
    ipv4_address: Optional[ipaddress.IPv4Address]
    platform: Optional[str]
    capabilities: List[str]
    vendor: Optional[constr(to_lower=True)]
    sw_family: Optional[constr(to_lower=True)]
    sw_version: Optional[str]
    local_interface: InterfaceName
    remote_interface: InterfaceName
    protocol: Optional[Literal['cdp', 'lldp']]

    @validator('capabilities', allow_reuse=True, pre=True)
    def validate_capabilities(cls, value):
        if isinstance(value, str):
            value = value.strip()
            value = [x.strip().lower() for x in value.split(' ')]
        return value


class InterafceOpsModel(BaseOpsModel):

    name: InterfaceName
    description: Optional[str]
    enabled: Optional[bool]
    status: Optional[constr(to_lower=True)]
    protocol_status: Optional[constr(to_lower=True)]

    @validator('status', allow_reuse=True, pre=True)
    def validate_status(cls, value):
        admin_down = [
            "administratively down"
        ]
        if value in admin_down:
            value = 'admin_down'
        return value

    @root_validator(allow_reuse=True)
    def determine_enabled(cls, values):
        enabled = values.get('enabled')
        if enabled is None:
            if values.get('status') == 'admin_down':
                values['enabled'] = False
            elif values.get('status') is not None:
                values['enabled'] = True
        return values