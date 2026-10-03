from datetime import datetime,timezone
from ids.risk_engine import severity,classification

def generate_alert(flow,matches,anomaly_score,risk_score,ml_score=None):
    if not matches and risk_score<=20: return None
    r=matches[0] if matches else {
      "rule_id":"ANOMALY-001","name":"Behavioral Anomaly",
      "description":"Flow deviated from its statistical baseline."
    }
    return {
      "alert_id":f"ALT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
      "timestamp":datetime.now(timezone.utc).isoformat(),
      "flow_id":flow["flow_id"],"source_ip":flow["source_ip"],
      "destination_ip":flow["destination_ip"],"protocol":flow["protocol"],
      "source_port":flow["source_port"],"destination_port":flow["destination_port"],
      "rule_id":r["rule_id"],"alert_type":r["name"],"severity":severity(risk_score),
      "risk_score":risk_score,"classification":classification(risk_score),
      "description":r["description"],"status":"NEW",
      "anomaly_score":anomaly_score,"ml_score":ml_score
    }
