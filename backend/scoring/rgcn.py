"""Relation-aware graph encoder used by the risk scorer.

CHANGES vs. the original implementation (see PR notes / experiment writeup):

1. `_layer` now always applies a per-layer self-transform (`self1`/`self2`) to
   every node's own features, in addition to relational messages. The
   original implementation returned only `bias` (broadcast, input-independent)
   for any node with zero incident edges -- for CICMalDroid this was the
   majority of samples, because the ontology's `enabled_by` sets require every
   listed permission simultaneously. That is fixed jointly with the
   knowledge_graph.py change that adds PARTIALLY_ENABLES edges on partial
   overlap, but the self-loop fix here is the one that matters even for
   genuinely edgeless graphs (e.g. a permission set that touches no
   capability at all): the model can now still tell such graphs apart from
   each other based on which permissions are present, instead of collapsing
   every edgeless input to one constant embedding.

2. Readout is now a learned gated (attention) pooling over nodes instead of
   an unweighted mean across all node types (Permission, Capability,
   AppCategory, MITRETechnique, ThreatIntent mixed together).

3. RELATIONS gains PARTIALLY_ENABLES to match the updated knowledge graph.
   This changes the relation-weight tensor shape, so existing model
   checkpoints trained under the old 5-relation schema are NOT compatible and
   must be retrained (`load_model` will raise a clear shape-mismatch error
   rather than silently mis-loading weights).

PyTorch Geometric is used when available. A small CPU-only relation-aware
implementation is kept as a dependency-light fallback so the scoring service
still works in the project's minimal environment. Both paths implement the
same relation-specific message-passing idea and expose the same inference API.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
# import torch
# from torch import nn
try:
    import torch
    from torch import nn
    _HAS_TORCH = True
except ImportError:
    torch = None      # type: ignore
    nn = None          # type: ignore
    _HAS_TORCH = False

try:
    from torch_geometric.nn import RGCNConv # type: ignore
    _HAS_PYG = True
except ImportError:
    RGCNConv = None
    _HAS_PYG = False


RELATIONS = ["ENABLES", "PARTIALLY_ENABLES", "NORMAL_FOR", "ANOMALOUS_FOR", "MAPS_TO_MITRE", "INDICATES"]
REL_TO_ID = {r: i for i, r in enumerate(RELATIONS)}
EMBED_DIM = 32

@dataclass
class GraphEmbedding:
    vector: list[float]
    source: str

if _HAS_TORCH:
    class TorchRGCN(nn.Module):
        """Relation-aware graph network with a self-loop term and gated pooling."""
        def __init__(self, num_nodes: int, hidden: int = 64, out: int = EMBED_DIM, num_classes: int = 2):
            super().__init__()
            self.emb = nn.Embedding(num_nodes, hidden)
            self.w1 = nn.Parameter(torch.empty(len(RELATIONS), hidden, hidden))
            self.w2 = nn.Parameter(torch.empty(len(RELATIONS), hidden, out))
            self.self1 = nn.Linear(hidden, hidden, bias=False)
            self.self2 = nn.Linear(hidden, out, bias=False)
            self.bias1 = nn.Parameter(torch.zeros(hidden))
            self.bias2 = nn.Parameter(torch.zeros(out))
            self.gate = nn.Linear(out, 1)
            self.classifier = nn.Linear(out, num_classes)
            nn.init.xavier_uniform_(self.w1)
            nn.init.xavier_uniform_(self.w2)

        def _layer(self, x: torch.Tensor, edge_index: torch.Tensor, edge_type: torch.Tensor,
                weights: torch.Tensor, self_lin: nn.Linear, bias: torch.Tensor) -> torch.Tensor:
            out = self_lin(x)  # self-loop: node's own signal always survives, even with 0 edges
            if edge_index.numel():
                for rel in range(len(RELATIONS)):
                    mask = edge_type == rel
                    if mask.any():
                        src = edge_index[0, mask]
                        dst = edge_index[1, mask]
                        msg = x[src] @ weights[rel]
                        deg = torch.bincount(dst, minlength=x.size(0)).float().clamp_min(1.0).unsqueeze(1)
                        out.index_add_(0, dst, msg / deg[dst])
            return out + bias

        def encode(self, node_ids: torch.Tensor, edge_index: torch.Tensor, edge_type: torch.Tensor) -> torch.Tensor:
            x = self.emb(node_ids)
            x = torch.relu(self._layer(x, edge_index, edge_type, self.w1, self.self1, self.bias1))
            x = self._layer(x, edge_index, edge_type, self.w2, self.self2, self.bias2)
            gate_logits = self.gate(x).squeeze(-1)
            weights = torch.softmax(gate_logits, dim=0)
            return (x * weights.unsqueeze(1)).sum(dim=0)

        def forward(self, node_ids, edge_index, edge_type):
            z = self.encode(node_ids, edge_index, edge_type)
            return self.classifier(z), z
else:
    TorchRGCN = None

if _HAS_PYG:
    class PyGRGCNEncoder(nn.Module):  # pragma: no cover - optional dependency path
        def __init__(self, num_nodes: int, hidden: int = 64, out: int = EMBED_DIM):
            super().__init__()
            self.emb = nn.Embedding(num_nodes, hidden)
            # root_weight=True (default) gives RGCNConv its own self-loop term,
            # so this path did not have the same bug as the fallback.
            self.conv1 = RGCNConv(hidden, hidden, num_relations=len(RELATIONS)) # type: ignore
            self.conv2 = RGCNConv(hidden, out, num_relations=len(RELATIONS)) # type: ignore
        def encode(self, node_ids, edge_index, edge_type):
            x = self.emb(node_ids)
            x = torch.relu(self.conv1(x, edge_index, edge_type))
            return self.conv2(x, edge_index, edge_type).mean(dim=0)

class RGCNModel:
    def __init__(self, model: nn.Module, node_to_idx: dict[str, int], metadata: dict | None = None):
        self.model = model.eval()
        self.node_to_idx = node_to_idx
        self.metadata = metadata or {}

    def embedding(self, subgraph: dict) -> GraphEmbedding:
        ids = [n["id"] for n in subgraph.get("nodes", [])]
        if not ids:
            # Match training: an empty permission graph is routed through the
            # model's own learned "_EMPTY_" placeholder node, not a hardcoded
            # zero vector (see ml/training/train_scoring_models.py::make_node_vocab).
            if "_EMPTY_" in self.node_to_idx:
                ids = ["_EMPTY_"]
            else:
                return GraphEmbedding([0.0] * EMBED_DIM, "rgcn")
        node_ids = torch.tensor([self.node_to_idx.get(i, 0) for i in ids], dtype=torch.long)

    # def embedding(self, subgraph: dict) -> GraphEmbedding:
    #     ids = [n["id"] for n in subgraph.get("nodes", [])]
    #     if not ids:
    #         return GraphEmbedding([0.0] * EMBED_DIM, "rgcn")
    #     node_ids = torch.tensor([self.node_to_idx.get(i, 0) for i in ids], dtype=torch.long)
        
        local = {node_id: i for i, node_id in enumerate(ids)}
        edges = []
        types = []
        for e in subgraph.get("edges", []):
            if e["src"] not in local or e["dst"] not in local:
                continue
            edges.append((local[e["src"]], local[e["dst"]]))
            types.append(REL_TO_ID.get(e["rel"], 0))
        if edges:
            edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
            edge_type = torch.tensor(types, dtype=torch.long)
        else:
            edge_index = torch.empty((2, 0), dtype=torch.long)
            edge_type = torch.empty((0,), dtype=torch.long)
        with torch.no_grad():
            z = self.model.encode(node_ids, edge_index, edge_type)
        return GraphEmbedding(z.cpu().tolist(), "rgcn")

_MODEL: RGCNModel | None = None

def load_model(path: str | Path) -> RGCNModel | None:
    if not _HAS_TORCH:
        return None
    global _MODEL
    path = Path(path)
    if not path.exists():
        return None
    payload = torch.load(path, map_location="cpu", weights_only=False)
    model = TorchRGCN(payload["num_nodes"], payload.get("hidden", 64), payload.get("embed_dim", EMBED_DIM), payload.get("num_classes", 2))
    model.load_state_dict(payload["state_dict"])  # raises on shape mismatch vs. old checkpoints -- retrain, don't ignore
    _MODEL = RGCNModel(model, payload["node_to_idx"], payload.get("metadata", {}))
    return _MODEL

def set_model(model: RGCNModel | None) -> None:
    global _MODEL
    _MODEL = model

def embed_subgraph(subgraph: dict, model_path: str | Path | None = None) -> GraphEmbedding:
    global _MODEL
    if _MODEL is None and model_path:
        _MODEL = load_model(model_path)
    if _MODEL is not None:
        return _MODEL.embedding(subgraph)
    return _fallback_embedding(subgraph)

def _fallback_embedding(subgraph: dict) -> GraphEmbedding:
    # Stable, deterministic representation for an untrained checkout.
    import hashlib
    vec = [0.0] * EMBED_DIM
    for node in subgraph.get("nodes", []):
        h = int(hashlib.md5(node["id"].encode()).hexdigest(), 16)  # noqa: S324
        vec[h % EMBED_DIM] += 1.0
    for edge in subgraph.get("edges", []):
        idx = REL_TO_ID.get(edge.get("rel", ""), 0)
        vec[idx] += 0.5
    norm = sum(v * v for v in vec) ** 0.5 or 1.0
    return GraphEmbedding([v / norm for v in vec], "fallback_features")