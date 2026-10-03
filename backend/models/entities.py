from sqlalchemy import Column,String,Integer,Float,DateTime,Boolean,Text,ForeignKey,Index
from backend.database import Base

class NetworkFlow(Base):
    __tablename__="network_flows"
    flow_id=Column(String,primary_key=True); timestamp=Column(DateTime,index=True,nullable=False)
    source_ip=Column(String,index=True); destination_ip=Column(String)
    source_port=Column(Integer); destination_port=Column(Integer,index=True); protocol=Column(String,index=True)
    packet_count=Column(Integer); byte_count=Column(Integer); duration=Column(Float)
    connection_count=Column(Integer); failed_connection_count=Column(Integer)
    syn_count=Column(Integer); rst_count=Column(Integer)
    risk_score=Column(Float,index=True); classification=Column(String,index=True)

class Alert(Base):
    __tablename__="alerts"
    alert_id=Column(String,primary_key=True); flow_id=Column(String,index=True)
    rule_id=Column(String,index=True); severity=Column(String,index=True)
    description=Column(Text); risk_score=Column(Float,index=True)
    status=Column(String,index=True); created_at=Column(DateTime,index=True)
    source_ip=Column(String,index=True); destination_ip=Column(String); protocol=Column(String)
    source_port=Column(Integer); destination_port=Column(Integer); alert_type=Column(String)
    anomaly_score=Column(Float); ml_score=Column(Float); classification=Column(String)

class Rule(Base):
    __tablename__="rules"
    rule_id=Column(String,primary_key=True); rule_name=Column(String)
    description=Column(Text); severity=Column(String); threshold=Column(Float)
    enabled=Column(Boolean,default=True)

class IncidentNote(Base):
    __tablename__="incident_notes"
    note_id=Column(Integer,primary_key=True,autoincrement=True)
    alert_id=Column(String,index=True); note=Column(Text,nullable=False)
    created_at=Column(DateTime,index=True)

Index("ix_alert_source_type","alerts.source_ip","alerts.alert_type")
