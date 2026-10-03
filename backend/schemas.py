from pydantic import BaseModel,Field,field_validator
from datetime import datetime
from typing import Optional

class FlowIn(BaseModel):
    flow_id:str=Field(min_length=1,max_length=100); timestamp:datetime
    source_ip:str; destination_ip:str
    source_port:int=Field(ge=0,le=65535); destination_port:int=Field(ge=0,le=65535)
    protocol:str; packet_count:int=Field(ge=0); byte_count:int=Field(ge=0)
    duration_seconds:float=Field(ge=0); connection_count:int=Field(ge=0)
    failed_connection_count:int=Field(ge=0); syn_count:int=Field(ge=0); rst_count:int=Field(ge=0)
    label:Optional[str]=None; scenario_type:Optional[str]=None
    @field_validator("protocol")
    @classmethod
    def valid_protocol(cls,v):
        if v not in {"TCP","UDP","ICMP"}: raise ValueError("Unsupported protocol")
        return v

class StatusIn(BaseModel):
    status:str; resolution_notes:Optional[str]=None

class NoteIn(BaseModel):
    note:str=Field(min_length=1,max_length=2000)
