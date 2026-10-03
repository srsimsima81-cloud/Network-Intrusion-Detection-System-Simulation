DEFAULT_RULES=[
 {"rule_id":"IDS-001","name":"High Connection Rate","severity":"HIGH","threshold":20.0,
  "description":"Connection rate exceeded configured baseline.","enabled":True},
 {"rule_id":"IDS-002","name":"Repeated Failed Connections","severity":"HIGH","threshold":0.35,
  "description":"Failure ratio exceeded configured baseline.","enabled":True},
 {"rule_id":"IDS-003","name":"Destination Port Diversity","severity":"MEDIUM","threshold":12,
  "description":"Destination-port diversity exceeded configured baseline.","enabled":True},
 {"rule_id":"IDS-004","name":"SYN-Heavy Pattern","severity":"HIGH","threshold":0.65,
  "description":"SYN ratio exceeded configured statistical baseline.","enabled":True},
 {"rule_id":"IDS-005","name":"Unusual Service Port","severity":"MEDIUM","threshold":1,
  "description":"Traffic used a monitored uncommon service port.","enabled":True},
 {"rule_id":"IDS-006","name":"High Traffic Volume","severity":"HIGH","threshold":1000000,
  "description":"Byte rate exceeded configured baseline.","enabled":True}
]
UNUSUAL={21,23,25,110,139,445,3389}

def analyze_flow(flow, features, rules=None):
    matches=[]
    for r in rules or DEFAULT_RULES:
        if not r["enabled"]: continue
        value=0; hit=False
        if r["rule_id"]=="IDS-001": value=features["connection_rate"]; hit=value>r["threshold"]
        elif r["rule_id"]=="IDS-002": value=features["failure_ratio"]; hit=value>r["threshold"]
        elif r["rule_id"]=="IDS-003": value=features["unique_destination_ports"]; hit=value>r["threshold"]
        elif r["rule_id"]=="IDS-004": value=features["syn_ratio"]; hit=value>r["threshold"]
        elif r["rule_id"]=="IDS-005": value=flow["destination_port"]; hit=value in UNUSUAL
        elif r["rule_id"]=="IDS-006": value=features["bytes_per_second"]; hit=value>r["threshold"]
        if hit:
            matches.append({**r,"observed_value":round(float(value),4)})
    return matches
