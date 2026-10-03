from pathlib import Path
import joblib
from ids.feature_extractor import extract_network_features
MODEL=Path("models/random_forest.joblib")

def predict(flow):
    if not MODEL.exists(): return None
    bundle=joblib.load(MODEL)
    f=extract_network_features(flow)
    x=[[f[k] for k in bundle["features"]]]
    p=float(bundle["model"].predict_proba(x)[0][1])
    return {"prediction":"SUSPICIOUS" if p>=.5 else "NORMAL","probability":round(p,4)}
