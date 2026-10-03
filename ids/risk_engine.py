def classification(score):
    if score<=20:return "NORMAL"
    if score<=40:return "LOW RISK"
    if score<=60:return "SUSPICIOUS"
    if score<=80:return "HIGH RISK"
    return "CRITICAL INVESTIGATION"

def severity(score):
    if score<=20:return "INFO"
    if score<=40:return "LOW"
    if score<=60:return "MEDIUM"
    if score<=80:return "HIGH"
    return "CRITICAL"

def calculate_risk_score(rule_risk, anomaly_score, ml_probability=None, weights=None):
    if ml_probability is None:
        w=weights or {"rule":.6,"anomaly":.4}
        score=rule_risk*w["rule"]+anomaly_score*w["anomaly"]
    else:
        w=weights or {"rule":.4,"anomaly":.3,"ml":.3}
        score=rule_risk*w["rule"]+anomaly_score*w["anomaly"]+(ml_probability*100)*w["ml"]
    return round(max(0,min(100,score)),2)
