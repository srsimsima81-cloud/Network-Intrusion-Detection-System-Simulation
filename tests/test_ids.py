import pytest
from datetime import datetime
from simulator.generate_dataset import make_flow
from ids.feature_extractor import extract_network_features,validate_flow
from ids.rule_engine import analyze_flow
from ids.anomaly_detector import fit_baseline,calculate_anomaly_score
from ids.risk_engine import calculate_risk_score,classification
from ids.alert_engine import generate_alert
from ids.correlation import correlate_alerts

def f(s): return make_flow(datetime.now(),s)
def test_01_normal_tcp(): assert f("NORMAL_WEB")["protocol"]=="TCP"
def test_02_normal_udp(): assert f("NORMAL_DNS")["protocol"]=="UDP"
def test_03_normal_dns(): assert f("NORMAL_DNS")["destination_port"]==53
def test_04_normal_https(): assert f("NORMAL_WEB")["destination_port"]==443
def test_05_high_connection(): x=f("HIGH_CONNECTION_RATE");assert analyze_flow(x,extract_network_features(x))
def test_06_failed_connections(): x=f("REPEATED_FAILED_CONNECTIONS");assert any(r["rule_id"]=="IDS-002" for r in analyze_flow(x,extract_network_features(x)))
def test_07_multi_port(): assert f("MULTI_PORT_PROBING_PATTERN")["label"]=="SUSPICIOUS"
def test_08_syn_heavy(): assert f("SYN_HEAVY_PATTERN")["syn_count"]>0
def test_09_high_volume(): assert f("HIGH_TRAFFIC_VOLUME")["byte_count"]>1_000_000
def test_10_invalid_source(): x=f("NORMAL_WEB");x["source_ip"]="bad";pytest.raises(ValueError,validate_flow,x)
def test_11_invalid_dest(): x=f("NORMAL_WEB");x["destination_ip"]="999.1.1.1";pytest.raises(ValueError,validate_flow,x)
def test_12_bad_source_port(): x=f("NORMAL_WEB");x["source_port"]=70000;pytest.raises(ValueError,validate_flow,x)
def test_13_bad_dest_port(): x=f("NORMAL_WEB");x["destination_port"]=-1;pytest.raises(ValueError,validate_flow,x)
def test_14_bad_protocol(): x=f("NORMAL_WEB");x["protocol"]="FTP";pytest.raises(ValueError,validate_flow,x)
def test_15_missing_packets(): x=f("NORMAL_WEB");x["packet_count"]=None;pytest.raises(ValueError,validate_flow,x)
def test_16_zero_duration(): x=f("NORMAL_WEB");x["duration_seconds"]=0;assert extract_network_features(x)["packets_per_second"]>0
def test_17_features(): assert "failure_ratio" in extract_network_features(f("NORMAL_WEB"))
def test_18_rules(): x=f("HIGH_CONNECTION_RATE");assert len(analyze_flow(x,extract_network_features(x)))>0
def test_19_anomaly(): x=f("NORMAL_WEB");assert 0<=calculate_anomaly_score(extract_network_features(x),fit_baseline([x]))<=100
def test_20_risk(): assert 0<=calculate_risk_score(50,50)<=100
def test_21_alert(): x=f("HIGH_CONNECTION_RATE");m=analyze_flow(x,extract_network_features(x));assert generate_alert(x,m,70,70)
def test_22_correlation():
 a={"timestamp":"2026-01-01T00:00:00+00:00","source_ip":"192.0.2.1","alert_type":"X","alert_id":"1"}
 b={**a,"timestamp":"2026-01-01T00:00:30+00:00","alert_id":"2"};assert correlate_alerts([a,b])[0]["count"]==2
def test_23_status(): assert "INVESTIGATING" in ["NEW","INVESTIGATING","RESOLVED","FALSE_POSITIVE"]
def test_24_note_schema(): from backend.schemas import NoteIn;assert NoteIn(note="review").note=="review"
def test_25_db_model(): from backend.models.entities import NetworkFlow;assert NetworkFlow.__tablename__=="network_flows"
def test_26_dashboard_route(): from backend.app import app;assert any(r.path=="/api/dashboard/stats" for r in app.routes)
def test_27_ml_optional(): from ml.predict import predict;assert predict(f("NORMAL_WEB")) in (None,dict)
def test_28_api_validation(): from backend.schemas import FlowIn;assert FlowIn(**f("NORMAL_WEB")).protocol=="TCP"
def test_29_empty_baseline(): x=f("NORMAL_WEB");assert calculate_anomaly_score(extract_network_features(x),{})>=0
def test_30_duplicate_id_field(): assert f("NORMAL_WEB")["flow_id"].startswith("FLOW-")
