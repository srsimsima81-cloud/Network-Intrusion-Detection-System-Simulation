import os
from datetime import datetime,timezone
from fastapi import FastAPI,Depends,HTTPException,Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.database import Base,engine,get_db
from backend.models.entities import NetworkFlow,Alert,Rule,IncidentNote
from backend.schemas import FlowIn,StatusIn,NoteIn
from ids.feature_extractor import extract_network_features
from ids.rule_engine import analyze_flow,DEFAULT_RULES
from ids.anomaly_detector import fit_baseline,calculate_anomaly_score
from ids.risk_engine import calculate_risk_score,classification,severity
from ids.alert_engine import generate_alert

Base.metadata.create_all(bind=engine)
app=FastAPI(title="Network IDS Simulation API",version="1.0")
app.add_middleware(CORSMiddleware,allow_origins=os.getenv("CORS_ORIGINS","http://localhost:5173").split(","),
                   allow_methods=["*"],allow_headers=["*"])

def init_rules():
    db=next(get_db())
    try:
        if db.query(Rule).count()==0:
            for r in DEFAULT_RULES:
                db.add(Rule(rule_id=r["rule_id"],rule_name=r["name"],description=r["description"],
                            severity=r["severity"],threshold=r["threshold"],enabled=r["enabled"]))
            db.commit()
    finally: db.close()
init_rules()

def as_flow(f):
    return {"flow_id":f.flow_id,"timestamp":f.timestamp,"source_ip":f.source_ip,
            "destination_ip":f.destination_ip,"source_port":f.source_port,
            "destination_port":f.destination_port,"protocol":f.protocol,
            "packet_count":f.packet_count,"byte_count":f.byte_count,
            "duration_seconds":f.duration,"connection_count":f.connection_count,
            "failed_connection_count":f.failed_connection_count,"syn_count":f.syn_count,"rst_count":f.rst_count}

@app.get("/api/health")
def health(): return {"status":"ok"}

@app.post("/api/flows",status_code=201)
def create_flow(payload:FlowIn,db:Session=Depends(get_db)):
    if db.get(NetworkFlow,payload.flow_id): raise HTTPException(409,"Duplicate flow_id")
    f=payload.model_dump()
    features=extract_network_features(f)
    matches=analyze_flow(f,features)
    rule_risk=min(100,len(matches)*30)
    # The live endpoint uses the single-flow baseline as a safe fallback.
    anomaly=calculate_anomaly_score(features,fit_baseline([f]))
    risk=calculate_risk_score(rule_risk,anomaly,None)
    cls=classification(risk)
    row=NetworkFlow(flow_id=f["flow_id"],timestamp=f["timestamp"],source_ip=f["source_ip"],
      destination_ip=f["destination_ip"],source_port=f["source_port"],destination_port=f["destination_port"],
      protocol=f["protocol"],packet_count=f["packet_count"],byte_count=f["byte_count"],
      duration=f["duration_seconds"],connection_count=f["connection_count"],
      failed_connection_count=f["failed_connection_count"],syn_count=f["syn_count"],rst_count=f["rst_count"],
      risk_score=risk,classification=cls)
    db.add(row)
    alert=generate_alert(f,matches,anomaly,risk)
    if alert:
        db.add(Alert(**{k:alert.get(k) for k in [
          "alert_id","flow_id","rule_id","severity","description","risk_score","status",
          "source_ip","destination_ip","protocol","source_port","destination_port",
          "alert_type","anomaly_score","ml_score","classification"]},
          created_at=datetime.now(timezone.utc)))
    db.commit()
    return {"flow":as_flow(row),"risk_score":risk,"classification":cls,
            "anomaly_score":anomaly,"matched_rules":matches,"alert":alert}

@app.get("/api/flows")
def flows(limit:int=Query(100,ge=1,le=1000),db:Session=Depends(get_db)):
    return [as_flow(x) for x in db.query(NetworkFlow).order_by(NetworkFlow.timestamp.desc()).limit(limit)]

@app.get("/api/flows/{flow_id}")
def flow(flow_id:str,db:Session=Depends(get_db)):
    x=db.get(NetworkFlow,flow_id)
    if not x: raise HTTPException(404,"Flow not found")
    return as_flow(x)

def alert_json(a):
    return {c.name:getattr(a,c.name) for c in Alert.__table__.columns}

@app.get("/api/alerts")
def alerts(severity:str|None=None,protocol:str|None=None,status:str|None=None,
           alert_type:str|None=None,limit:int=Query(100,ge=1,le=1000),db:Session=Depends(get_db)):
    q=db.query(Alert)
    if severity:q=q.filter(Alert.severity==severity)
    if protocol:q=q.filter(Alert.protocol==protocol)
    if status:q=q.filter(Alert.status==status)
    if alert_type:q=q.filter(Alert.alert_type==alert_type)
    return [alert_json(x) for x in q.order_by(Alert.created_at.desc()).limit(limit)]

@app.get("/api/alerts/{alert_id}")
def alert(alert_id:str,db:Session=Depends(get_db)):
    a=db.get(Alert,alert_id)
    if not a: raise HTTPException(404,"Alert not found")
    notes=db.query(IncidentNote).filter(IncidentNote.alert_id==alert_id).order_by(IncidentNote.created_at).all()
    return {"alert":alert_json(a),"notes":[{"note_id":n.note_id,"note":n.note,"created_at":n.created_at} for n in notes]}

@app.put("/api/alerts/{alert_id}/status")
def status(alert_id:str,payload:StatusIn,db:Session=Depends(get_db)):
    if payload.status not in {"NEW","INVESTIGATING","RESOLVED","FALSE_POSITIVE"}:
        raise HTTPException(400,"Invalid status")
    a=db.get(Alert,alert_id)
    if not a: raise HTTPException(404,"Alert not found")
    a.status=payload.status
    if payload.resolution_notes:
        db.add(IncidentNote(alert_id=alert_id,note=payload.resolution_notes,created_at=datetime.now(timezone.utc)))
    db.commit(); return alert_json(a)

@app.post("/api/alerts/{alert_id}/notes")
def note(alert_id:str,payload:NoteIn,db:Session=Depends(get_db)):
    if not db.get(Alert,alert_id): raise HTTPException(404,"Alert not found")
    n=IncidentNote(alert_id=alert_id,note=payload.note,created_at=datetime.now(timezone.utc))
    db.add(n);db.commit();db.refresh(n)
    return {"note_id":n.note_id,"alert_id":n.alert_id,"note":n.note,"created_at":n.created_at}

@app.get("/api/dashboard/stats")
def stats(db:Session=Depends(get_db)):
    total=db.query(func.count(NetworkFlow.flow_id)).scalar() or 0
    normal=db.query(func.count(NetworkFlow.flow_id)).filter(NetworkFlow.classification=="NORMAL").scalar() or 0
    open_=db.query(func.count(Alert.alert_id)).filter(Alert.status.in_(["NEW","INVESTIGATING"])).scalar() or 0
    critical=db.query(func.count(Alert.alert_id)).filter(Alert.severity=="CRITICAL").scalar() or 0
    avg=db.query(func.avg(NetworkFlow.risk_score)).scalar() or 0
    return {"total_flows":total,"normal_flows":normal,"suspicious_flows":total-normal,
            "open_alerts":open_,"critical_alerts":critical,"average_risk_score":round(float(avg),2)}

@app.get("/api/dashboard/traffic")
def traffic(limit:int=100,db:Session=Depends(get_db)):
    rows=db.query(NetworkFlow).order_by(NetworkFlow.timestamp.desc()).limit(limit).all()
    return [{"timestamp":x.timestamp,"packets_per_second":x.packet_count/max(x.duration,.001),
             "bytes_per_second":x.byte_count/max(x.duration,.001),"risk_score":x.risk_score,
             "classification":x.classification} for x in reversed(rows)]

@app.get("/api/dashboard/alerts")
def analytics(db:Session=Depends(get_db)):
    def pairs(q): return [{"name":a,"value":b} for a,b in q]
    return {
      "severity":pairs(db.query(Alert.severity,func.count(Alert.alert_id)).group_by(Alert.severity).all()),
      "alert_types":pairs(db.query(Alert.alert_type,func.count(Alert.alert_id)).group_by(Alert.alert_type).all()),
      "protocols":pairs(db.query(NetworkFlow.protocol,func.count(NetworkFlow.flow_id)).group_by(NetworkFlow.protocol).all()),
      "ports":pairs(db.query(NetworkFlow.destination_port,func.count(NetworkFlow.flow_id)).group_by(NetworkFlow.destination_port).limit(10).all())
    }

@app.get("/api/rules")
def rules(db:Session=Depends(get_db)):
    return [{c.name:getattr(r,c.name) for c in Rule.__table__.columns} for r in db.query(Rule).all()]
