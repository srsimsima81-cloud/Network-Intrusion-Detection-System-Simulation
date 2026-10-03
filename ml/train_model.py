from pathlib import Path
import joblib,pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score,confusion_matrix
from ids.feature_extractor import extract_network_features

FEATURES=["packet_count","byte_count","duration","bytes_per_second","packets_per_second",
          "connection_count","failed_connection_count","syn_count","rst_count",
          "average_packet_size"]

def prepare(path):
    df=pd.read_csv(path); X=[]
    for _,row in df.iterrows():
        f=extract_network_features(row.to_dict())
        X.append([f[x] for x in FEATURES])
    return X,(df.label=="SUSPICIOUS").astype(int)

def train(path="data/network_traffic.csv",output="models/random_forest.joblib"):
    X,y=prepare(path)
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)
    model=make_pipeline(StandardScaler(),RandomForestClassifier(
        n_estimators=150,random_state=42,class_weight="balanced"))
    model.fit(Xtr,ytr); pred=model.predict(Xte)
    metrics={
      "accuracy":accuracy_score(yte,pred),
      "precision":precision_score(yte,pred,zero_division=0),
      "recall":recall_score(yte,pred,zero_division=0),
      "f1":f1_score(yte,pred,zero_division=0),
      "confusion_matrix":confusion_matrix(yte,pred).tolist()
    }
    Path(output).parent.mkdir(exist_ok=True)
    joblib.dump({"model":model,"features":FEATURES},output)
    return metrics

if __name__=="__main__": print(train())
