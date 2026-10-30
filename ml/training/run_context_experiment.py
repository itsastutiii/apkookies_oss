"""Run the context-awareness experiment with external app-category metadata.

The experiment compares the same relation-aware model with and without category
nodes, using identical train/validation/test rows. It deliberately requires
external application-category metadata so malware labels cannot leak into the
context variable.

CSV format:
    row_index,category
    0,Banking
    1,Communication
    ...
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argparse
import json
import numpy as np
import torch

from ml.training.train_scoring_models import (
    binary_metrics,
    embeddings,
    load_categories,
    make_node_vocab,
    train_rgcn,
)
from backend.scoring.knowledge_graph import InMemoryKnowledgeGraph


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="ml/data/cicmaldroid_permissions.npz")
    ap.add_argument("--category-csv", required=True)
    ap.add_argument("--out", default="ml/results/context_experiment.json")
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--train-max", type=int, default=4000)
    args = ap.parse_args()

    data = np.load(args.data, allow_pickle=True)
    X = data["X"].astype(np.float32)
    malware = data["y"].astype(np.int64)
    y = (malware != 5).astype(np.int64)
    vocab_names = data["vocabulary"].tolist()
    categories = load_categories(args.category_csv, len(y))

    # Reuse the deterministic split from the training script.
    from sklearn.model_selection import train_test_split
    idx = np.arange(len(y))
    train, valtest = train_test_split(idx, test_size=.30, stratify=y, random_state=42)
    val, test = train_test_split(valtest, test_size=.50, stratify=y[valtest], random_state=42)

    kg = InMemoryKnowledgeGraph()
    rng = np.random.default_rng(42)
    if len(train) > args.train_max:
        per = max(args.train_max // 2, 1)
        neg, pos = train[y[train] == 0], train[y[train] == 1]
        train_idx = np.sort(np.concatenate([
            rng.choice(neg, min(per, len(neg)), replace=False),
            rng.choice(pos, min(per, len(pos)), replace=False),
        ]))
    else:
        train_idx = train

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    temp = out.parent / "_context_rgcn_tmp.pt"

    # Context model: real category nodes/edges.
    context_model, context_vocab = train_rgcn(
        X, y, vocab_names, categories, train_idx, val, kg, temp, epochs=args.epochs
    )
    z = embeddings(context_model, context_vocab, X, vocab_names, categories, test, kg)
    p_context = torch.softmax(context_model.classifier(torch.tensor(z)), dim=1)[:, 1].detach().numpy()

    # Counterfactual no-context model: identical rows and labels, category removed.
    no_context_categories = [None] * len(categories)
    no_context_model, no_context_vocab = train_rgcn(
        X, y, vocab_names, no_context_categories, train_idx, val, kg, temp, epochs=args.epochs
    )
    z0 = embeddings(no_context_model, no_context_vocab, X, vocab_names, no_context_categories, test, kg)
    p_no_context = torch.softmax(no_context_model.classifier(torch.tensor(z0)), dim=1)[:, 1].detach().numpy()

    result = {
        "dataset": {"n": len(y), "test_n": len(test), "random_state": 42},
        "context_model": binary_metrics(y[test], p_context),
        "no_context_model": binary_metrics(y[test], p_no_context),
        "context_gain_macro_f1": float(binary_metrics(y[test], p_context)["macro_f1"] - binary_metrics(y[test], p_no_context)["macro_f1"]),
        "context_gain_roc_auc": float(binary_metrics(y[test], p_context)["roc_auc"] - binary_metrics(y[test], p_no_context)["roc_auc"]),
        "note": "This is valid only when category-csv contains application categories independent of the CIC malware Class label.",
    }
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    temp.unlink(missing_ok=True)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
