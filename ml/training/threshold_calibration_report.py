"""Threshold selection + calibration + complementarity report for Person 1's
scoring subsystem. Uses ONLY already-trained model artifacts in ml/models/ --
no retraining. Split is reconstructed identically to ml/training/train_scoring_models.py
(same random_state=42), so this is a faithful re-scoring of the existing
train/val/test partition.

Experimental discipline:
  - Threshold selection happens on VALIDATION only.
  - Test is scored exactly once, at the thresholds chosen on validation.

Run from the repo root:
    python ml/training/threshold_calibration_report.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier # type: ignore

from backend.scoring import bayesian as bayesian_mod
from backend.scoring import aggregator as aggregator_mod
from backend.scoring.aggregator import ScalarFeatures, aggregate
from backend.scoring.knowledge_graph import InMemoryKnowledgeGraph
from backend.scoring.rgcn import embed_subgraph, load_model as load_rgcn

DATA = ROOT / "ml" / "data" / "cicmaldroid_permissions.npz"
MODELS = ROOT / "ml" / "models"
OUT = ROOT / "ml" / "results" / "threshold_calibration_report.json"

SENSITIVE = {
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG", "android.permission.CALL_PHONE",
}


def load_split():
    data = np.load(DATA, allow_pickle=True)
    X = data["X"].astype(np.float32)
    malware = data["y"].astype(np.int64)
    y = (malware != 5).astype(np.int64)
    vocab = data["vocabulary"].tolist()
    idx = np.arange(len(y))
    train, valtest = train_test_split(idx, test_size=0.30, stratify=y, random_state=42)
    val, test = train_test_split(valtest, test_size=0.50, stratify=y[valtest], random_state=42)
    return X, y, vocab, train, val, test


def full_ensemble_probs(X, vocab, idxs):
    """Re-derive the deployed (bayesian + rgcn + xgboost) score per row using
    the SAME production code path score_static() uses -- category=None since
    no independent app-category metadata exists yet (see project status)."""
    kg = InMemoryKnowledgeGraph()
    probs = np.zeros(len(idxs), dtype=np.float64)
    for k, i in enumerate(idxs):
        perms = [vocab[j] for j in np.flatnonzero(X[i])]
        subgraph = kg.induced_subgraph(perms, None)
        embedding = embed_subgraph(subgraph)
        prior = bayesian_mod.prior_p_high(perms, None)
        perm_set = set(perms)

        def has(p):
            return 1.0 if p in perm_set else 0.0

        scalar = ScalarFeatures(
            sms_api_count=has("android.permission.READ_SMS") + has("android.permission.RECEIVE_SMS") + has("android.permission.SEND_SMS"), # type: ignore
            accessibility_api_count=has("android.permission.BIND_ACCESSIBILITY_SERVICE"), # type: ignore
            overlay_api_count=has("android.permission.SYSTEM_ALERT_WINDOW"), # type: ignore
            network_api_count=has("android.permission.INTERNET"), # type: ignore
            telephony_api_count=has("android.permission.READ_PHONE_STATE"), # type: ignore
            permission_count=len(perms),
            sensitive_permission_count=sum(1 for p in perms if p in SENSITIVE),
        )
        probs[k] = aggregate(embedding, prior, scalar).score
    return probs


def sweep_thresholds(y_true, probs):
    rows = []
    for t in np.arange(0.01, 1.0, 0.01):
        pred = (probs >= t).astype(int)
        tp = int(((pred == 1) & (y_true == 1)).sum())
        fp = int(((pred == 1) & (y_true == 0)).sum())
        fn = int(((pred == 0) & (y_true == 1)).sum())
        tn = int(((pred == 0) & (y_true == 0)).sum())
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1_pos = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        # macro-F1 over {benign, malware} classes
        precision_neg = tn / (tn + fn) if (tn + fn) else 0.0
        recall_neg = tn / (tn + fp) if (tn + fp) else 0.0
        f1_neg = 2 * precision_neg * recall_neg / (precision_neg + recall_neg) if (precision_neg + recall_neg) else 0.0
        macro_f1 = (f1_pos + f1_neg) / 2
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        rows.append({"threshold": round(float(t), 2), "precision": precision, "recall": recall,
                      "macro_f1": macro_f1, "fpr": fpr, "tp": tp, "fp": fp, "fn": fn, "tn": tn})
    return rows


def pick_thresholds(val_sweep):
    best_f1 = max(val_sweep, key=lambda r: r["macro_f1"])
    under_fpr = [r for r in val_sweep if r["fpr"] <= 0.05]
    best_recall_at_fpr5 = max(under_fpr, key=lambda r: r["recall"]) if under_fpr else best_f1
    return {"max_macro_f1": best_f1["threshold"], "recall_at_fpr<=5%": best_recall_at_fpr5["threshold"]}


def metrics_at(y_true, probs, threshold):
    pred = (probs >= threshold).astype(int)
    tp = int(((pred == 1) & (y_true == 1)).sum())
    fp = int(((pred == 1) & (y_true == 0)).sum())
    fn = int(((pred == 0) & (y_true == 1)).sum())
    tn = int(((pred == 0) & (y_true == 0)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    macro_f1 = next(r["macro_f1"] for r in [{"macro_f1": None}])  # placeholder unused
    precision_neg = tn / (tn + fn) if (tn + fn) else 0.0
    recall_neg = tn / (tn + fp) if (tn + fp) else 0.0
    f1_pos = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    f1_neg = 2 * precision_neg * recall_neg / (precision_neg + recall_neg) if (precision_neg + recall_neg) else 0.0
    macro_f1 = (f1_pos + f1_neg) / 2
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"threshold": threshold, "precision": precision, "recall": recall, "macro_f1": macro_f1,
            "fpr": fpr, "confusion_matrix": [[tn, fp], [fn, tp]]}, pred


def brier_and_reliability(y_true, probs, n_bins=10):
    brier = float(np.mean((probs - y_true) ** 2))
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    table = []
    for b in range(n_bins):
        lo, hi = bins[b], bins[b + 1]
        mask = (probs >= lo) & (probs < hi if b < n_bins - 1 else probs <= hi)
        n = int(mask.sum())
        if n == 0:
            table.append({"bin": f"{lo:.1f}-{hi:.1f}", "n": 0, "mean_predicted": None, "observed_rate": None})
            continue
        table.append({
            "bin": f"{lo:.1f}-{hi:.1f}", "n": n,
            "mean_predicted": float(probs[mask].mean()),
            "observed_rate": float(y_true[mask].mean()),
        })
    return brier, table


def main():
    X, y, vocab, train, val, test = load_split()

    lr_payload = joblib.load(MODELS / "permission_lr.joblib")
    lr = lr_payload["model"]

    xgb = XGBClassifier()
    xgb.load_model(MODELS / "permission_xgb.json")

    nb_payload = joblib.load(MODELS / "bayesian.joblib")
    nb = nb_payload["model"]

    # Load production components for the full ensemble path (same code score_static() uses).
    load_rgcn(MODELS / "rgcn.pt")
    bayesian_mod.load_model(MODELS / "bayesian.joblib")
    aggregator_mod.load_model(MODELS / "xgboost.json")

    model_probs = {
        "permission_lr": {"val": lr.predict_proba(X[val])[:, 1], "test": lr.predict_proba(X[test])[:, 1]},
        "permission_xgboost": {"val": xgb.predict_proba(X[val])[:, 1], "test": xgb.predict_proba(X[test])[:, 1]},
        "bayesian_nb": {"val": nb.predict_proba(X[val])[:, 1], "test": nb.predict_proba(X[test])[:, 1]},
        "full_ensemble_rgcn_bayesian_xgboost": {
            "val": full_ensemble_probs(X, vocab, val),
            "test": full_ensemble_probs(X, vocab, test),
        },
    }

    report = {"note": "Thresholds selected on validation only; test scored once at those thresholds.",
              "split_sizes": {"train": len(train), "val": len(val), "test": len(test)},
              "models": {}}

    for name, probs in model_probs.items():
        val_sweep = sweep_thresholds(y[val], probs["val"])
        chosen = pick_thresholds(val_sweep)
        test_at_maxf1, _ = metrics_at(y[test], probs["test"], chosen["max_macro_f1"])
        test_at_fpr5, _ = metrics_at(y[test], probs["test"], chosen["recall_at_fpr<=5%"])
        test_at_05, _ = metrics_at(y[test], probs["test"], 0.5)
        brier, reliability = brier_and_reliability(y[test], probs["test"])
        report["models"][name] = {
            "chosen_thresholds": chosen,
            "test_at_chosen_max_macro_f1_threshold": test_at_maxf1,
            "test_at_chosen_recall_fpr5_threshold": test_at_fpr5,
            "test_at_naive_0.5_threshold_for_comparison": test_at_05,
            "brier_score_test": brier,
            "reliability_table_test": reliability,
        }
        print(f"\n=== {name} ===")
        print(f"  chosen thresholds (from validation): {chosen}")
        print(f"  test @ max-macro-F1 threshold : {test_at_maxf1}")
        print(f"  test @ naive 0.5 threshold    : {test_at_05}")
        print(f"  Brier score (test, lower=better calibrated): {brier:.4f}")

    # Complementarity: permission XGBoost vs full ensemble, both at their own
    # validation-chosen max-macro-F1 threshold.
    xgb_t = report["models"]["permission_xgboost"]["chosen_thresholds"]["max_macro_f1"]
    ens_t = report["models"]["full_ensemble_rgcn_bayesian_xgboost"]["chosen_thresholds"]["max_macro_f1"]
    xgb_pred = (model_probs["permission_xgboost"]["test"] >= xgb_t).astype(int)
    ens_pred = (model_probs["full_ensemble_rgcn_bayesian_xgboost"]["test"] >= ens_t).astype(int)
    y_test = y[test]
    xgb_correct = xgb_pred == y_test
    ens_correct = ens_pred == y_test
    both_right = int((xgb_correct & ens_correct).sum())
    both_wrong = int((~xgb_correct & ~ens_correct).sum())
    only_xgb_right = int((xgb_correct & ~ens_correct).sum())
    only_ens_right = int((~xgb_correct & ens_correct).sum())
    complementarity = {
        "both_right": both_right, "both_wrong": both_wrong,
        "only_xgboost_right": only_xgb_right, "only_ensemble_right": only_ens_right,
        "agreement_rate": float((xgb_pred == ens_pred).mean()),
        "interpretation": "only_ensemble_right > 0 means the graph/bayesian ensemble catches some "
                           "cases permission-XGBoost alone misses -- that's the complementarity evidence, "
                           "not aggregate macro-F1.",
    }
    report["complementarity_xgboost_vs_full_ensemble"] = complementarity
    print("\n=== complementarity (XGBoost vs full ensemble, test set) ===")
    print(json.dumps(complementarity, indent=2))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nFull report written to {OUT}")


if __name__ == "__main__":
    main()