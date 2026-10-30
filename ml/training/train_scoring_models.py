"""Train the scoring stack from the canonical CICMalDroid representation.

Important distinction:
- CICMalDroid ``Class`` is a malware label and MUST NOT be reused as the
  application's contextual category.
- A true context-aware R-GCN run therefore accepts an optional external
  ``--category-csv`` containing application-category metadata.

Without that metadata the script still trains reproducible permission baselines
and a relation-aware permission R-GCN, but it records that category context was
not available. This prevents accidental label leakage.

CURRENT STATE / PLANNED (AndroZoo retraining):
- Current: these models (ml/models/) are trained on CICMalDroid 2020's PERMISSION
  flags, not on APKs analysed by our pipeline; they back scoring_mode "model"
  (experimental). See ARCHITECTURE.md, "Honest model note".
- Planned: train on ml/data/androzoo/features.jsonl.gz (built by
  ml/data/build_androzoo_dataset.py with the live static-analysis code), with a
  time-aware split and per-class metrics against the shipped model; write the
  result to ml/models/retrained/, which scoring_mode "retrained" loads. Not
  started: waits for the AndroZoo features.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argparse
import json
import joblib
import numpy as np
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import BernoulliNB
from xgboost import XGBClassifier # type: ignore

from backend.scoring.knowledge_graph import InMemoryKnowledgeGraph
from backend.scoring.rgcn import EMBED_DIM, RELATIONS, REL_TO_ID, TorchRGCN
from torch import nn


class TorchGCN(nn.Module):
    """Relation-agnostic ablation baseline: identical shape/self-loop/pooling
    to TorchRGCN but a single shared weight matrix regardless of edge type.
    Isolates how much of R-GCN's gain (if any) comes specifically from
    *relation-typed* message passing vs. graph structure in general."""
    def __init__(self, num_nodes: int, hidden: int = 64, out: int = EMBED_DIM, num_classes: int = 2):
        super().__init__()
        self.emb = nn.Embedding(num_nodes, hidden)
        self.w1 = nn.Parameter(torch.empty(hidden, hidden))
        self.w2 = nn.Parameter(torch.empty(hidden, out))
        self.self1 = nn.Linear(hidden, hidden, bias=False)
        self.self2 = nn.Linear(hidden, out, bias=False)
        self.bias1 = nn.Parameter(torch.zeros(hidden))
        self.bias2 = nn.Parameter(torch.zeros(out))
        self.gate = nn.Linear(out, 1)
        self.classifier = nn.Linear(out, num_classes)
        nn.init.xavier_uniform_(self.w1)
        nn.init.xavier_uniform_(self.w2)

    def _layer(self, x, edge_index, weight, self_lin, bias):
        out = self_lin(x)
        if edge_index.numel():
            src, dst = edge_index[0], edge_index[1]
            msg = x[src] @ weight
            deg = torch.bincount(dst, minlength=x.size(0)).float().clamp_min(1.0).unsqueeze(1)
            out.index_add_(0, dst, msg / deg[dst])
        return out + bias

    def encode(self, node_ids, edge_index, edge_type):
        x = self.emb(node_ids)
        x = torch.relu(self._layer(x, edge_index, self.w1, self.self1, self.bias1))
        x = self._layer(x, edge_index, self.w2, self.self2, self.bias2)
        w = torch.softmax(self.gate(x).squeeze(-1), dim=0)
        return (x * w.unsqueeze(1)).sum(dim=0)

    def forward(self, node_ids, edge_index, edge_type):
        z = self.encode(node_ids, edge_index, edge_type)
        return self.classifier(z), z

SENSITIVE = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.CALL_PHONE",
}


def binary_metrics(y_true, probabilities, threshold: float = 0.5):
    pred = (probabilities >= threshold).astype(np.int64)
    return {
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "macro_f1": float(f1_score(y_true, pred, average="macro", zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, probabilities)),
        "pr_auc": float(average_precision_score(y_true, probabilities)),
        "confusion_matrix": confusion_matrix(y_true, pred).tolist(),
    }


def load_categories(path: str | None, n: int) -> list[str | None]:
    if not path:
        return [None] * n
    import csv

    rows: dict[int, str] = {}
    with Path(path).open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fields = set(reader.fieldnames or [])
        id_field = "row_index" if "row_index" in fields else "sample_id" if "sample_id" in fields else None
        if id_field is None or "category" not in fields:
            raise ValueError("category CSV must contain row_index (or sample_id) and category columns")
        for row in reader:
            rows[int(row[id_field])] = row["category"].strip()
    missing = sorted(set(range(n)) - set(rows))
    if missing:
        raise ValueError(f"category CSV is missing {len(missing)} dataset rows; first missing={missing[0]}")
    return [rows[i] for i in range(n)]


def graph_for(perms, kg, category=None):
    return kg.induced_subgraph(perms, category)


def graph_tensors(subgraph, vocab):
    ids = [n["id"] for n in subgraph["nodes"]] or ["__EMPTY__"]
    local = {node: i for i, node in enumerate(ids)}
    node_ids = torch.tensor([vocab[node] for node in ids], dtype=torch.long)
    edges, types = [], []
    for edge in subgraph["edges"]:
        if edge["src"] in local and edge["dst"] in local:
            edges.append((local[edge["src"]], local[edge["dst"]]))
            types.append(REL_TO_ID[edge["rel"]])
    if edges:
        edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
        edge_type = torch.tensor(types, dtype=torch.long)
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)
        edge_type = torch.empty((0,), dtype=torch.long)
    return node_ids, edge_index, edge_type


def make_node_vocab(permission_names, kg):
    nodes = set(permission_names) | {"__EMPTY__"}
    nodes.update(kg._categories)
    for cap, spec in kg._caps.items():
        nodes.add(cap)
        nodes.update(spec.get("enabled_by", []))
        nodes.update(spec.get("mitre", []))
        if spec.get("indicates"):
            nodes.add(spec["indicates"])
        # Category nodes are already in kg._categories; edges are {category, source} dicts.
    return {name: i for i, name in enumerate(sorted(nodes))}


def train_rgcn(X, y, vocab_names, categories, train_idx, val_idx, kg, out_path, epochs=8, model_cls=TorchRGCN):
    vocab = make_node_vocab(vocab_names, kg)
    model = model_cls(len(vocab), hidden=64, out=EMBED_DIM, num_classes=2)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.003, weight_decay=1e-5)
    counts = np.bincount(y[train_idx], minlength=2)
    weights = torch.tensor([1 / max(counts[0], 1), 1 / max(counts[1], 1)], dtype=torch.float32)
    weights = weights / weights.mean()
    loss_fn = torch.nn.CrossEntropyLoss(weight=weights)

    best_loss = float("inf")
    best_state = None
    train_order = list(map(int, train_idx))
    for epoch in range(epochs):
        model.train()
        rng = np.random.default_rng(1000 + epoch)
        rng.shuffle(train_order)
        total = 0.0
        for i in train_order:
            perms = [vocab_names[j] for j in np.flatnonzero(X[i])]
            graph = graph_for(perms, kg, categories[i])
            node_ids, edge_index, edge_type = graph_tensors(graph, vocab)
            logits, _ = model(node_ids, edge_index, edge_type)
            target = torch.tensor([int(y[i])])
            loss = loss_fn(logits.unsqueeze(0), target)
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 2.0) # type: ignore
            optimizer.step()
            total += float(loss.detach())

        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for i in val_idx:
                perms = [vocab_names[j] for j in np.flatnonzero(X[i])]
                graph = graph_for(perms, kg, categories[i])
                node_ids, edge_index, edge_type = graph_tensors(graph, vocab)
                logits, _ = model(node_ids, edge_index, edge_type)
                val_loss += float(loss_fn(logits.unsqueeze(0), torch.tensor([int(y[i])])).detach())
        val_loss /= max(len(val_idx), 1)
        print(f"RGCN epoch {epoch + 1}/{epochs} train_loss={total / max(len(train_order), 1):.4f} val_loss={val_loss:.4f}")
        if val_loss < best_loss:
            best_loss = val_loss
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}

    if best_state is None:
        raise RuntimeError("R-GCN training did not produce a checkpoint")
    model.load_state_dict(best_state)
    torch.save(
        {
            "state_dict": model.state_dict(),
            "num_nodes": len(vocab),
            "hidden": 64,
            "embed_dim": EMBED_DIM,
            "num_classes": 2,
            "node_to_idx": vocab,
            "metadata": {
                "relations": RELATIONS,
                "category_context_trained": any(c is not None for c in categories),
                "category_source": "external_metadata" if any(c is not None for c in categories) else None,
            },
        },
        out_path,
    )
    return model, vocab


def embeddings(model, vocab, X, permission_names, categories, idxs, kg):
    out = np.zeros((len(idxs), EMBED_DIM), dtype=np.float32)
    model.eval()
    for k, i in enumerate(idxs):
        perms = [permission_names[j] for j in np.flatnonzero(X[i])]
        graph = graph_for(perms, kg, categories[i])
        node_ids, edge_index, edge_type = graph_tensors(graph, vocab)
        with torch.no_grad():
            out[k] = model.encode(node_ids, edge_index, edge_type).cpu().numpy()
    return out


def deployment_scalars(X, vocab_names):
    def col(name):
        return X[:, vocab_names.index(name)] if name in vocab_names else np.zeros(len(X), dtype=np.float32)
    sensitive_cols = [vocab_names.index(p) for p in SENSITIVE if p in vocab_names]
    sensitive_count = X[:, sensitive_cols].sum(1) if sensitive_cols else np.zeros(len(X))
    return np.column_stack([
        np.zeros(len(X)), np.zeros(len(X)), np.zeros(len(X)),
        np.zeros(len(X)), np.zeros(len(X)), np.zeros(len(X)),
        col("android.permission.READ_SMS") + col("android.permission.RECEIVE_SMS") + col("android.permission.SEND_SMS"),
        col("android.permission.BIND_ACCESSIBILITY_SERVICE"),
        col("android.permission.SYSTEM_ALERT_WINDOW"),
        col("android.permission.INTERNET"),
        col("android.permission.READ_PHONE_STATE"),
        np.zeros(len(X)), np.zeros(len(X)), np.zeros(len(X)),
        np.zeros(len(X)), np.zeros(len(X)), np.zeros(len(X)),
        X.sum(1), sensitive_count,
    ])


def save_native_xgb(model, path: Path, feature_names: list[str]):
    model.save_model(path)
    path.with_suffix(".meta.json").write_text(
        json.dumps({"feature_names": feature_names}, indent=2), encoding="utf-8"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="ml/data/cicmaldroid_permissions.npz")
    ap.add_argument("--category-csv", default=None, help="Optional row_index/category metadata; never use CIC malware Class as category")
    ap.add_argument("--models", default="ml/models")
    ap.add_argument("--results", default="ml/results")
    ap.add_argument("--rgcn-epochs", type=int, default=8)
    ap.add_argument("--rgcn-train-max", type=int, default=4000)
    args = ap.parse_args()

    data = np.load(args.data, allow_pickle=True)
    X = data["X"].astype(np.float32)
    malware_label = data["y"].astype(np.int64)
    y = (malware_label != 5).astype(np.int64)
    vocab_names = data["vocabulary"].tolist()
    categories = load_categories(args.category_csv, len(y))

    idx = np.arange(len(y))
    train, valtest = train_test_split(idx, test_size=0.30, stratify=y, random_state=42)
    val, test = train_test_split(valtest, test_size=0.50, stratify=y[valtest], random_state=42)

    outm = Path(args.models)
    outr = Path(args.results)
    outm.mkdir(parents=True, exist_ok=True)
    outr.mkdir(parents=True, exist_ok=True)

    results = {
        "dataset": {
            "n": len(y),
            "malware": int(y.sum()),
            "benign": int((y == 0).sum()),
            "class_counts": {str(k): int(v) for k, v in zip(*np.unique(malware_label, return_counts=True))},
        },
        "context": {
            "category_metadata_supplied": args.category_csv is not None,
            "warning": None if args.category_csv else "R-GCN was trained without application-category context; CIC malware Class was not reused as category.",
        },
        "split": {"train": len(train), "validation": len(val), "test": len(test), "random_state": 42},
    }

    lr = LogisticRegression(max_iter=1000, class_weight="balanced", solver="liblinear")
    lr.fit(X[train], y[train])
    save_lr = {"model": lr, "vocab": vocab_names}
    joblib.dump(save_lr, outm / "permission_lr.joblib")
    results["permission_logistic_regression"] = binary_metrics(y[test], lr.predict_proba(X[test])[:, 1])

    xgb = XGBClassifier(
        n_estimators=350, max_depth=5, learning_rate=0.05, subsample=0.85,
        colsample_bytree=0.8, eval_metric="logloss", tree_method="hist", random_state=42,
    )
    xgb.fit(X[train], y[train], eval_set=[(X[val], y[val])], verbose=False)
    save_native_xgb(xgb, outm / "permission_xgb.json", vocab_names)
    results["permission_xgboost"] = binary_metrics(y[test], xgb.predict_proba(X[test])[:, 1])

    nb = BernoulliNB(alpha=1.0)
    nb.fit(X[train], y[train])
    joblib.dump({"model": nb, "vocab": vocab_names}, outm / "bayesian.joblib")
    results["bayesian_prior"] = binary_metrics(y[test], nb.predict_proba(X[test])[:, 1])

    kg = InMemoryKnowledgeGraph()
    if len(train) > args.rgcn_train_max:
        rng = np.random.default_rng(42)
        per = max(args.rgcn_train_max // 2, 1)
        neg, pos = train[y[train] == 0], train[y[train] == 1]
        train_rgcn_idx = np.sort(np.concatenate([
            rng.choice(neg, min(per, len(neg)), replace=False),
            rng.choice(pos, min(per, len(pos)), replace=False),
        ]))
    else:
        train_rgcn_idx = train

    # Relation-agnostic GCN ablation -- same graph, self-loop, and pooling, but
    # a single shared weight instead of per-relation weights. Trained on the
    # identical train/val split so the comparison isolates relation-typing.
    gcn, gcn_vocab = train_rgcn(
        X, y, vocab_names, categories, train_rgcn_idx, val, kg, outm / "gcn.pt", args.rgcn_epochs, model_cls=TorchGCN # type: ignore
    )
    z_test_gcn = embeddings(gcn, gcn_vocab, X, vocab_names, categories, test, kg)
    gcn_probs = torch.softmax(gcn.classifier(torch.tensor(z_test_gcn)), dim=1)[:, 1].detach().numpy()
    results["gcn"] = binary_metrics(y[test], gcn_probs)

    rgcn, node_vocab = train_rgcn(
        X, y, vocab_names, categories, train_rgcn_idx, val, kg, outm / "rgcn.pt", args.rgcn_epochs, model_cls=TorchRGCN
    )
    z_train = embeddings(rgcn, node_vocab, X, vocab_names, categories, train_rgcn_idx, kg)
    z_test = embeddings(rgcn, node_vocab, X, vocab_names, categories, test, kg)
    rgcn_probs = torch.softmax(rgcn.classifier(torch.tensor(z_test)), dim=1)[:, 1].detach().numpy()
    results["rgcn"] = binary_metrics(y[test], rgcn_probs)

    # p_train = nb.predict_proba(X[train_rgcn_idx])[:, 1]
    # p_test = nb.predict_proba(X[test])[:, 1]
    # s_train = deployment_scalars(X[train_rgcn_idx], vocab_names)
    # s_test = deployment_scalars(X[test], vocab_names)
    # F_train = np.column_stack([p_train, z_train, s_train])
    # F_test = np.column_stack([p_test, z_test, s_test])
    # feature_names = ["bayesian_prior"] + [f"rgcn_{i}" for i in range(EMBED_DIM)] + [f"scalar_{i}" for i in range(s_train.shape[1])]

    # agg = XGBClassifier(
    #     n_estimators=300, max_depth=4, learning_rate=0.05, subsample=0.9,
    #     colsample_bytree=0.8, eval_metric="logloss", tree_method="hist", random_state=42,
    # )
    # agg.fit(F_train, y[train_rgcn_idx], eval_set=[(F_test, y[test])], verbose=False)

    # --- AFTER ---
    p_train = nb.predict_proba(X[train_rgcn_idx])[:, 1]
    p_val = nb.predict_proba(X[val])[:, 1]
    p_test = nb.predict_proba(X[test])[:, 1]
    s_train = deployment_scalars(X[train_rgcn_idx], vocab_names)
    s_val = deployment_scalars(X[val], vocab_names)
    s_test = deployment_scalars(X[test], vocab_names)
    # Aggregator eval_set MUST be validation, never test -- test is scored exactly
    # once, after training/model-selection is fully finished (see README/experimental
    # principles). z_val uses the already-trained rgcn/node_vocab from above.
    z_val = embeddings(rgcn, node_vocab, X, vocab_names, categories, val, kg)
    F_train = np.column_stack([p_train, z_train, s_train])
    F_val = np.column_stack([p_val, z_val, s_val])
    F_test = np.column_stack([p_test, z_test, s_test])
    feature_names = ["bayesian_prior"] + [f"rgcn_{i}" for i in range(EMBED_DIM)] + [f"scalar_{i}" for i in range(s_train.shape[1])]

    agg = XGBClassifier(
        n_estimators=300, max_depth=4, learning_rate=0.05, subsample=0.9,
        colsample_bytree=0.8, eval_metric="logloss", tree_method="hist", random_state=42,
    )
    agg.fit(F_train, y[train_rgcn_idx], eval_set=[(F_val, y[val])], verbose=False)

    
    save_native_xgb(agg, outm / "xgboost.json", feature_names)
    results["rgcn_bayesian_xgboost"] = binary_metrics(y[test], agg.predict_proba(F_test)[:, 1])
    # This is the deployed model: bayesian prior + rgcn embedding + static scalar
    # features, aggregated by XGBoost -- i.e. the "full_model" row of the ablation.
    results["full_model"] = results["rgcn_bayesian_xgboost"]

    (outr / "metrics.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()