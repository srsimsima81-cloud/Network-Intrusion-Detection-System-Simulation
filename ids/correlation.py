from collections import defaultdict
from datetime import datetime

def correlate_alerts(alerts,window_seconds=60):
    groups=defaultdict(list)
    for a in sorted(alerts,key=lambda x:x["timestamp"]):
        groups[(a["source_ip"],a["alert_type"])].append(a)
    result=[]
    for (src,typ),items in groups.items():
        bucket=[items[0]]
        for item in items[1:]:
            a=datetime.fromisoformat(bucket[-1]["timestamp"].replace("Z","+00:00"))
            b=datetime.fromisoformat(item["timestamp"].replace("Z","+00:00"))
            if (b-a).total_seconds()<=window_seconds: bucket.append(item)
            else:
                result.append({"source_ip":src,"alert_type":typ,"count":len(bucket),
                                "alert_ids":[x["alert_id"] for x in bucket]})
                bucket=[item]
        result.append({"source_ip":src,"alert_type":typ,"count":len(bucket),
                       "alert_ids":[x["alert_id"] for x in bucket]})
    return result
