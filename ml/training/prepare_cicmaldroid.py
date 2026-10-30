"""Convert the supplied CICMalDroid CSV bundle into a compact permission dataset.

The static CSV is ~600 MB and has no explicit Class column. CICMalDroid's CSV
rows align with the labelled syscall CSV, so labels are joined by row index.
Only canonical android.permission.* columns are retained.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import argparse, json, re, zipfile
from pathlib import Path
import numpy as np
import pandas as pd

LABELS = {1: "ADWARE", 2: "BANKING", 3: "SMS", 4: "RISKWARE", 5: "BENIGN"}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("zip_path"); ap.add_argument("--out", default="ml/data/cicmaldroid_permissions.npz"); args=ap.parse_args()
    z=zipfile.ZipFile(args.zip_path)
    static_name="CSV/feature_vectors_static.csv"
    label_name="CSV/feature_vectors_syscalls_frequency_5_Cat.csv"
    with z.open(static_name) as f:
        header=pd.read_csv(f,nrows=0).columns.tolist()
    permissions=[c for c in header[1:] if re.fullmatch(r"android\.permission\.[A-Z0-9_]+", str(c))]
    with z.open(static_name) as f:
        X=pd.read_csv(f,usecols=permissions,dtype=np.float32).fillna(0).clip(0,1).to_numpy(dtype=np.uint8)
    with z.open(label_name) as f:
        y_raw=pd.read_csv(f,usecols=["Class"]).iloc[:,0].astype(int).to_numpy()
    if len(X)!=len(y_raw): raise ValueError(f"row mismatch: static={len(X)} labels={len(y_raw)}")
    labels=np.array([LABELS[int(v)] for v in y_raw])
    out=Path(args.out); out.parent.mkdir(parents=True,exist_ok=True)
    np.savez_compressed(out, X=X, y=y_raw, labels=labels, vocabulary=np.array(permissions,dtype=object))
    meta=out.with_suffix('.json'); meta.write_text(json.dumps({"n_samples":len(X),"n_permissions":len(permissions),"labels":LABELS},indent=2))
    print(f"wrote {out}: {X.shape}")

if __name__=='__main__': main()
