import statistics
FEATURES=["packets_per_second","bytes_per_second","connection_rate",
          "failure_ratio","unique_destination_ports"]

def feature_value(f,name):
    d=max(float(f.get("duration_seconds",0)),.001)
    return {
      "packets_per_second":f["packet_count"]/d,
      "bytes_per_second":f["byte_count"]/d,
      "connection_rate":f["connection_count"]/d,
      "failure_ratio":f["failed_connection_count"]/max(f["connection_count"],1),
      "unique_destination_ports":f.get("unique_destination_ports",1)
    }[name]

def fit_baseline(flows):
    out={}
    for name in FEATURES:
        values=[float(feature_value(f,name)) for f in flows]
        out[name]={"mean":statistics.mean(values) if values else 0,
                   "std":statistics.pstdev(values) if len(values)>1 else 1}
    return out

def calculate_anomaly_score(features,baseline):
    zs=[]
    for name in FEATURES:
        b=baseline.get(name,{"mean":0,"std":1})
        zs.append(abs((features[name]-b["mean"])/max(b["std"],1e-9)))
    return round(min(100,(max(zs,default=0)/6)*100),2)
