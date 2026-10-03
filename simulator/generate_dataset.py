import argparse, csv, random, ipaddress
from datetime import datetime, timedelta
from pathlib import Path

SRC = ipaddress.ip_network("192.0.2.0/24")
DST = ipaddress.ip_network("198.51.100.0/24")

def ip(net):
    return str(random.choice(list(net.hosts())))

def make_flow(ts, scenario):
    src, dst = ip(SRC), ip(DST)
    normal = scenario.startswith("NORMAL_")
    protocol, dport = {
        "NORMAL_WEB": ("TCP",443), "NORMAL_DNS":("UDP",53),
        "NORMAL_SSH":("TCP",22), "NORMAL_EMAIL":("TCP",587),
        "NORMAL_DATABASE":("TCP",5432)
    }.get(scenario, ("TCP",443))

    if normal:
        packets=random.randint(5,80); duration=random.uniform(.5,8)
        connections=random.randint(1,5); failed=random.choice([0,0,0,1])
        syn=random.randint(1,max(1,packets//4)); rst=random.choice([0,0,1])
        avg=random.randint(300,1400)
    elif scenario=="HIGH_CONNECTION_RATE":
        packets=random.randint(200,700); duration=random.uniform(1,5)
        connections=random.randint(80,250); failed=random.randint(0,5)
        syn=random.randint(100,500); rst=random.randint(0,20); avg=random.randint(300,1200)
    elif scenario=="REPEATED_FAILED_CONNECTIONS":
        packets=random.randint(20,100); duration=random.uniform(.5,5)
        connections=random.randint(20,80); failed=random.randint(15,70)
        syn=random.randint(5,20); rst=random.randint(5,25); avg=random.randint(200,900)
    elif scenario=="MULTI_PORT_PROBING_PATTERN":
        packets=random.randint(10,60); duration=random.uniform(.2,4)
        connections=random.randint(20,90); failed=random.randint(0,10)
        syn=random.randint(5,40); rst=random.randint(1,20); avg=random.randint(200,1200)
        dport=random.randint(1,65535)
    elif scenario=="SYN_HEAVY_PATTERN":
        packets=random.randint(40,200); duration=random.uniform(.5,5)
        connections=random.randint(20,100); failed=random.randint(0,10)
        syn=random.randint(35,max(35,packets)); rst=random.randint(10,60); avg=random.randint(100,800)
    elif scenario=="UNUSUAL_PORT_ACTIVITY":
        dport=random.choice([21,23,25,110,139,445,3389])
        packets=random.randint(10,80); duration=random.uniform(.2,8)
        connections=random.randint(1,10); failed=random.randint(0,5)
        syn=random.randint(1,15); rst=random.randint(0,8); avg=random.randint(200,1200)
    else:
        packets=random.randint(1000,5000); duration=random.uniform(1,10)
        connections=random.randint(20,100); failed=random.randint(0,5)
        syn=random.randint(5,30); rst=random.randint(0,10); avg=random.randint(1200,2000)

    return {
        "flow_id": f"FLOW-{random.getrandbits(48):012x}",
        "timestamp": ts.isoformat(),
        "source_ip":src,"destination_ip":dst,
        "source_port":random.randint(1024,65535),"destination_port":dport,
        "protocol":protocol,"packet_count":packets,"byte_count":packets*avg,
        "duration_seconds":round(duration,3),"connection_count":connections,
        "failed_connection_count":failed,"syn_count":syn,"rst_count":rst,
        "average_packet_size":round((packets*avg)/max(packets,1),2),
        "label":"NORMAL" if normal else "SUSPICIOUS",
        "scenario_type":scenario
    }

def generate(rows=5000, output="data/network_traffic.csv", seed=42):
    random.seed(seed)
    scenarios=["NORMAL_WEB","NORMAL_DNS","NORMAL_SSH","NORMAL_EMAIL","NORMAL_DATABASE",
               "HIGH_CONNECTION_RATE","REPEATED_FAILED_CONNECTIONS",
               "MULTI_PORT_PROBING_PATTERN","SYN_HEAVY_PATTERN",
               "UNUSUAL_PORT_ACTIVITY","HIGH_TRAFFIC_VOLUME"]
    start=datetime.now().replace(microsecond=0)-timedelta(hours=4)
    records=[]
    for i in range(rows):
        scenario=random.choice(scenarios) if random.random()<.22 else random.choice(scenarios[:5])
        records.append(make_flow(start+timedelta(seconds=i*3),scenario))
    Path(output).parent.mkdir(parents=True,exist_ok=True)
    with open(output,"w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=records[0].keys()); w.writeheader(); w.writerows(records)
    return output

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--rows",type=int,default=5000)
    ap.add_argument("--output",default="data/network_traffic.csv")
    args=ap.parse_args()
    print(generate(args.rows,args.output))
