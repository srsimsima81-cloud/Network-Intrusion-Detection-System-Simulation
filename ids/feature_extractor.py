import ipaddress

ALLOWED={"TCP","UDP","ICMP"}

def validate_flow(f):
    for k in ("source_ip","destination_ip"):
        try: ipaddress.ip_address(f[k])
        except Exception as e: raise ValueError(f"Invalid {k}") from e
    for k in ("source_port","destination_port"):
        if not isinstance(f.get(k),int) or not 0<=f[k]<=65535:
            raise ValueError(f"Invalid {k}")
    if f.get("protocol") not in ALLOWED: raise ValueError("Unsupported protocol")
    if f.get("packet_count") is None or f.get("byte_count") is None:
        raise ValueError("Missing packet/byte count")

def extract_network_features(f, context=None):
    validate_flow(f)
    d=max(float(f.get("duration_seconds",0)),.001)
    packets=max(int(f.get("packet_count",0)),0)
    bytes_=max(int(f.get("byte_count",0)),0)
    con=max(int(f.get("connection_count",0)),0)
    failed=max(int(f.get("failed_connection_count",0)),0)
    syn=max(int(f.get("syn_count",0)),0)
    rst=max(int(f.get("rst_count",0)),0)
    c=context or {}
    return {
        "packet_count":packets,"byte_count":bytes_,"duration":d,
        "bytes_per_second":bytes_/d,"packets_per_second":packets/d,
        "average_packet_size":bytes_/max(packets,1),"connection_count":con,
        "failed_connection_count":failed,"failure_ratio":failed/max(con,1),
        "syn_count":syn,"rst_count":rst,"syn_ratio":syn/max(packets,1),
        "unique_destination_ports":c.get("unique_destination_ports",1),
        "unique_destination_ips":c.get("unique_destination_ips",1),
        "connection_rate":con/d
    }
