"""
continual_detector.py

CPU-only continual anomaly detection module that:
- Loads your trained encoder and FAISS normal index (faiss_index.idx).
- Computes embeddings for incoming preprocessed logs.
- Uses a normal index + thresholds to mark anomalies.
- Maintains a separate anomaly index to "remember" zero-day / previously-seen attacks.
- Supports adding verified normal logs to the normal memory (and index) and adding anomalies
  automatically to anomaly memory so repeated attacks are flagged as known.
- Periodic maintenance updates thresholds and optionally prunes memory.

Required files (place in same dir or provide paths):
- encoder_for_inference.pth
- faiss_index.idx         (your current normal index or prototype index)
- thresholds.joblib       (optional: if missing, will compute from train_embeddings.pt)
- train_embeddings.pt     (used to compute thresholds if thresholds.joblib missing)
- (optional) kmeans.joblib / prototypes.npy - not required here

Outputs persisted by this module:
- normal_memory.npy       (growing memory of normal embeddings)
- anomaly_memory.npy      (growing memory of anomaly embeddings)
- faiss_normal.idx        (persisted copy of normal FAISS index)
- faiss_anomaly.idx       (persisted anomaly FAISS index)
- thresholds.joblib       (updated adaptive thresholds)

Usage:
  detector = ContinualDetector(config)
  result = detector.process_single(preprocessed_features)  # returns dict with score, flags
  # periodically call detector.maintenance() or run as background job
"""

import os
import time
import numpy as np
import joblib
import faiss
import torch
import torch.nn as nn
from pathlib import Path
from typing import Optional, Tuple, Dict

# -----------------------
# Configuration defaults
# -----------------------
DEFAULTS = {
    "ENCODER_PATH": "encoder_for_inference.pth",
    "FAISS_NORMAL_PATH": "faiss_index.idx",      # provided by you (normal prototypes/index)
    "FAISS_NORMAL_PERSIST": "faiss_normal.idx",  # persisted (updated) normal index
    "FAISS_ANOMALY_PERSIST": "faiss_anomaly.idx",
    "THRESH_PATH": "thresholds.joblib",
    "TRAIN_EMB_PATH": "train_embeddings.pt",     # used to init thresholds if missing
    "NORMAL_MEMORY_NPY": "normal_memory.npy",
    "ANOMALY_MEMORY_NPY": "anomaly_memory.npy",
    "ANOMALY_SIM_THRESHOLD": None,               # set later relative to normal thresholds
    "EMBED_BATCH": 128,
    "MAINTENANCE_INTERVAL_SEC": 3600,            # recompute thresholds every hour by default
    "MAX_NORMAL_MEMORY": 200000,                 # maximum number of normal embeddings to keep
    "MAX_ANOMALY_MEMORY": 20000,
    "ANOMALY_ADD_AUTOMATIC": True,               # whether to automatically remember new anomalies
    "ANOMALY_KNOWN_SIMILE_RATIO": 0.5,           # how strict "known anomaly" matching is vs normal threshold
}


# -----------------------
# Encoder (same architecture you used)
# -----------------------
class Encoder(nn.Module):
    def __init__(self, input_dim: int, hidden=(256, 128), embed_dim=64):
        super().__init__()
        layers = []
        prev = input_dim
        for h in hidden:
            layers.append(nn.Linear(prev, h))
            layers.append(nn.ReLU())
            layers.append(nn.BatchNorm1d(h))
            prev = h
        layers.append(nn.Linear(prev, embed_dim))
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x)


# -----------------------
# Utility helpers
# -----------------------
def ensure_dir(d: str):
    Path(d).parent.mkdir(parents=True, exist_ok=True)


def load_or_create_faiss_index(path: str, dim: int):
    """
    Load index if exists, else create an empty IndexFlatL2 with given dim.
    """
    if os.path.exists(path):
        idx = faiss.read_index(path)
        return idx
    else:
        idx = faiss.IndexFlatL2(dim)
        return idx


# -----------------------
# Main Continual Detector class
# -----------------------
class ContinualDetector:
    def __init__(self, config: dict = None):
        cfg = DEFAULTS.copy()
        if config:
            cfg.update(config)
        self.cfg = cfg

        # device cpu only
        self.device = torch.device("cpu")

        # load encoder placeholder (we will init after knowing input dim)
        self.encoder: Optional[Encoder] = None
        self.input_dim = None
        self.embed_dim = None

        # load normal FAISS index (provided)
        self.faiss_normal = None
        self.faiss_anomaly = None

        # memory bags
        self.normal_memory = None   # np.ndarray (N, D)
        self.anomaly_memory = None  # np.ndarray (M, D)

        # thresholds
        self.thresholds = {"low": None, "high": None}
        self.last_maintenance = 0.0

        # init core components
        self._init_from_files()

    # -----------------------
    # Initialization and loading
    # -----------------------
    def _init_from_files(self):
        # Ensure persistence directory exists
        ensure_dir(self.cfg["THRESH_PATH"])

        # 1) Load thresholds if present, else compute from train embeddings
        if os.path.exists(self.cfg["THRESH_PATH"]):
            try:
                self.thresholds = joblib.load(self.cfg["THRESH_PATH"])
                print("[init] loaded thresholds:", self.thresholds)
            except Exception as e:
                print("[init] failed loading thresholds, will recompute. error:", e)
                self._compute_thresholds_from_train()
        else:
            self._compute_thresholds_from_train()

        # 2) Load provided normal FAISS index if exists
        if os.path.exists(self.cfg["FAISS_NORMAL_PATH"]):
            self.faiss_normal = faiss.read_index(self.cfg["FAISS_NORMAL_PATH"])
            print("[init] loaded provided FAISS normal index from", self.cfg["FAISS_NORMAL_PATH"])
        else:
            # If not provided, try to create one from train embeddings if available
            if os.path.exists(self.cfg["TRAIN_EMB_PATH"]):
                print("[init] No normal FAISS index provided; creating one from train embeddings.")
                train_emb = self._load_train_embeddings(self.cfg["TRAIN_EMB_PATH"])
                d = train_emb.shape[1]
                self.faiss_normal = faiss.IndexFlatL2(d)
                self.faiss_normal.add(train_emb.astype('float32'))
                faiss.write_index(self.faiss_normal, self.cfg["FAISS_NORMAL_PERSIST"])
                print("[init] created and saved faiss_normal.idx")
            else:
                raise FileNotFoundError("No FAISS normal index or train embeddings found. Provide faiss_index.idx or train_embeddings.pt")

        # 3) Determine embedding dimensionality
        # read index.d if possible (faiss IndexFlatL2 doesn't have .d attribute, so infer from index.ntotal and vectors)
        if isinstance(self.faiss_normal, faiss.IndexFlatL2):
            # try to infer dims: if ntotal>0, search a dummy vector to get dimension via index.reconstruct maybe not available.
            # We'll use train_embeddings to infer dim if available.
            if os.path.exists(self.cfg["TRAIN_EMB_PATH"]):
                train_emb = self._load_train_embeddings(self.cfg["TRAIN_EMB_PATH"])
                d = train_emb.shape[1]
            elif os.path.exists(self.cfg["FAISS_NORMAL_PERSIST"]):
                # fallback
                d = None
            else:
                d = None
            if d is None:
                raise RuntimeError("Cannot infer embedding dim. Provide train_embeddings.pt or set dim manually in config.")
            self.embed_dim = d
        else:
            # For other index types, try to get dimension by reconstructing first vector
            self.embed_dim = None
            if self.faiss_normal.ntotal > 0:
                vec = np.zeros(self.faiss_normal.d, dtype='float32') if hasattr(self.faiss_normal, 'd') else None
            # fallback raise
            if self.embed_dim is None:
                raise RuntimeError("Unable to infer embed_dim from FAISS index.")

        # 4) Load or create anomaly FAISS index with same dim
        self.faiss_anomaly = load_or_create_faiss_index(self.cfg["FAISS_ANOMALY_PERSIST"], self.embed_dim)
        print("[init] anomaly FAISS index ready. ntotal:", self.faiss_anomaly.ntotal)

        # 5) Load or initialize memory arrays
        if os.path.exists(self.cfg["NORMAL_MEMORY_NPY"]):
            self.normal_memory = np.load(self.cfg["NORMAL_MEMORY_NPY"])
            print("[init] loaded normal memory shape:", self.normal_memory.shape)
        else:
            # try to seed from train embeddings if present
            if os.path.exists(self.cfg["TRAIN_EMB_PATH"]):
                self.normal_memory = self._load_train_embeddings(self.cfg["TRAIN_EMB_PATH"]).astype('float32')
                np.save(self.cfg["NORMAL_MEMORY_NPY"], self.normal_memory)
                print("[init] created normal_memory from train embeddings shape:", self.normal_memory.shape)
            else:
                # seed with contents of normal FAISS index if possible (not trivial). Start empty
                self.normal_memory = np.empty((0, self.embed_dim), dtype='float32')
                np.save(self.cfg["NORMAL_MEMORY_NPY"], self.normal_memory)
                print("[init] started empty normal_memory")

        if os.path.exists(self.cfg["ANOMALY_MEMORY_NPY"]):
            self.anomaly_memory = np.load(self.cfg["ANOMALY_MEMORY_NPY"])
            print("[init] loaded anomaly memory shape:", self.anomaly_memory.shape)
        else:
            self.anomaly_memory = np.empty((0, self.embed_dim), dtype='float32')
            np.save(self.cfg["ANOMALY_MEMORY_NPY"], self.anomaly_memory)
            print("[init] started empty anomaly_memory")

        # 6) Set anomaly similarity threshold if not provided
        if self.cfg["ANOMALY_SIM_THRESHOLD"] is None:
            # default: anomalies considered 'known' if distance to known anomaly < 0.5 * high_threshold
            if self.thresholds["high"] is not None:
                self.cfg["ANOMALY_SIM_THRESHOLD"] = max(1e-6, self.thresholds["high"] * self.cfg["ANOMALY_KNOWN_SIMILE_RATIO"])
            else:
                self.cfg["ANOMALY_SIM_THRESHOLD"] = 1.0  # fallback
        print("[init] anomaly similarity threshold:", self.cfg["ANOMALY_SIM_THRESHOLD"])

        # 7) Load encoder architecture placeholder; actual input_dim must be set when processing the first log
        print("[init] initialization done.")

    def _load_train_embeddings(self, path: str) -> np.ndarray:
        if path.endswith(".pt"):
            emb = torch.load(path)
            if isinstance(emb, torch.Tensor):
                emb = emb.cpu().numpy()
            return emb.astype('float32')
        else:
            return np.load(path).astype('float32')

    def _compute_thresholds_from_train(self):
        # If thresholds missing, compute using train embeddings
        if os.path.exists(self.cfg["TRAIN_EMB_PATH"]):
            train_emb = self._load_train_embeddings(self.cfg["TRAIN_EMB_PATH"]).astype('float32')
            # load or create temp index using prototypes? We'll compute distances to nearest vector in train_emb itself
            d = train_emb.shape[1]
            temp_idx = faiss.IndexFlatL2(d)
            temp_idx.add(train_emb)
            D, _ = temp_idx.search(train_emb, 2)  # first neighbor is itself distance 0, take second nearest
            # take second column
            if D.shape[1] >= 2:
                second_nn = D[:, 1]
            else:
                second_nn = D[:, 0]
            low = float(np.percentile(second_nn, 90))
            high = float(np.percentile(second_nn, 99))
            self.thresholds = {"low": low, "high": high}
            joblib.dump(self.thresholds, self.cfg["THRESH_PATH"])
            print("[init] computed thresholds from train embeddings:", self.thresholds)
            return
        else:
            # can't compute; set defaults
            self.thresholds = {"low": 0.5, "high": 1.0}
            joblib.dump(self.thresholds, self.cfg["THRESH_PATH"])
            print("[init] used fallback thresholds:", self.thresholds)

    # -----------------------
    # Encoder bootstrap (called on first use when we know input dim)
    # -----------------------
    def _ensure_encoder(self, input_dim: int, hidden=(256,128), embed_dim=64):
        if self.encoder is None:
            self.input_dim = input_dim
            self.embed_dim = embed_dim
            self.encoder = Encoder(input_dim=input_dim, hidden=hidden, embed_dim=embed_dim)
            ck = self.cfg["ENCODER_PATH"]
            if os.path.exists(ck):
                # load with cpu mapping
                state = torch.load(ck, map_location=self.device)
                try:
                    self.encoder.load_state_dict(state)
                except Exception as e:
                    print("[encoder] warning: load_state_dict failed:", e)
                    # try to load partial states if shapes mismatch (best effort)
                    self.encoder.load_state_dict(state, strict=False)
                print("[encoder] loaded weights from", ck)
            else:
                raise FileNotFoundError("Encoder file not found at {}".format(ck))
            self.encoder.to(self.device)
            self.encoder.eval()

    # -----------------------
    # Embedding computation
    # -----------------------
    def embed_batch(self, X: np.ndarray, batch_size: Optional[int] = None) -> np.ndarray:
        if batch_size is None:
            batch_size = self.cfg["EMBED_BATCH"]
        if self.encoder is None:
            # lazy init encoder: assume embedding dim same as self.embed_dim and infer input dim
            raise RuntimeError("Encoder not initialized. Call process_single or process_batch with known input_dim first.")
        self.encoder.eval()
        embs = []
        with torch.no_grad():
            for i in range(0, len(X), batch_size):
                xb = torch.tensor(X[i:i+batch_size], dtype=torch.float32, device=self.device)
                z = self.encoder(xb).cpu().numpy()
                embs.append(z.astype('float32'))
        return np.vstack(embs)

    # -----------------------
    # Core inference logic
    # -----------------------
    def infer_scores(self, embeddings: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Return:
          - normal_distances: np.ndarray shape (N,) distances to nearest in normal index
          - anomaly_distances: np.ndarray shape (N,) distances to nearest in anomaly index (if any)
        """
        if embeddings.ndim == 1:
            embeddings = embeddings.reshape(1, -1)
        embeddings = embeddings.astype('float32')
        # search normal
        Dn, In = self.faiss_normal.search(embeddings, 1)
        normal_scores = Dn.ravel()
        # anomaly index may be empty
        if self.faiss_anomaly.ntotal > 0:
            Da, Ia = self.faiss_anomaly.search(embeddings, 1)
            anomaly_scores = Da.ravel()
        else:
            anomaly_scores = np.full(len(normal_scores), np.inf, dtype='float32')
        return normal_scores, anomaly_scores

    def classify(self, normal_scores: np.ndarray, anomaly_scores: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Decide:
         - is_anomaly: normal_score > high threshold
         - is_known_attack: anomaly_score < anomaly_sim_threshold
         - action: 0 normal, 1 anomaly_new, 2 anomaly_known
        """
        high = self.thresholds.get("high", np.inf)
        anomaly_flag = (normal_scores > high).astype(int)
        known_flag = (anomaly_scores < self.cfg["ANOMALY_SIM_THRESHOLD"]).astype(int)
        # If known_flag true, treat as known anomaly regardless of normal_score
        action = np.zeros_like(anomaly_flag, dtype=np.int32)
        for i in range(len(action)):
            if known_flag[i]:
                action[i] = 2  # known anomaly
            elif anomaly_flag[i]:
                action[i] = 1  # new anomaly
            else:
                action[i] = 0  # normal
        return anomaly_flag, known_flag, action

    # -----------------------
    # Public process functions
    # -----------------------
    def process_single(self, features: np.ndarray, verify_normal: Optional[bool] = None) -> Dict:
        """
        Process a single preprocessed flow feature vector (1D numpy array).
        verify_normal: If True, treat this log as verified normal and add to memory; if False and anomaly, add to anomaly memory.
                       If None, follow automatic rules (add anomaly to anomaly memory if ANOMALY_ADD_AUTOMATIC True).
        Returns a dict with keys:
            embedding, normal_score, anomaly_score, is_anomaly, is_known_attack, action, timestamp
        """
        X = np.asarray(features, dtype='float32')
        if X.ndim != 1:
            raise ValueError("process_single expects a 1D feature vector")
        # lazy init encoder if needed
        if self.encoder is None:
            # assume we can infer input_dim from X
            input_dim = X.shape[0]
            # default embed_dim set from existing info (if not, use 64)
            embed_dim = getattr(self, "embed_dim", 64)
            self._ensure_encoder(input_dim=input_dim, embed_dim=embed_dim)

        emb = self.embed_batch(X.reshape(1, -1), batch_size=1)[0]  # shape (D,)
        normal_scores, anomaly_scores = self.infer_scores(emb.reshape(1, -1))
        normal_score = float(normal_scores[0])
        anomaly_score = float(anomaly_scores[0])
        anomaly_flag, known_flag, action = self.classify(np.array([normal_score]), np.array([anomaly_score]))
        action_code = int(action[0])
        result = {
            "embedding": emb,
            "normal_score": normal_score,
            "anomaly_score": anomaly_score,
            "is_anomaly": bool(anomaly_flag[0]),
            "is_known_attack": bool(known_flag[0]),
            "action": action_code,  # 0 normal, 1 new anomaly, 2 known anomaly
            "timestamp": time.time(),
        }

        # persist decisions: if normal & verified or if automatic add normal? default: only add if verified explicitly
        if result["action"] == 0 and verify_normal:
            self.add_normals(np.expand_dims(emb, axis=0))
        elif result["action"] == 1:
            # new anomaly
            if self.cfg["ANOMALY_ADD_AUTOMATIC"] or (verify_normal is False):
                # add to anomaly memory so next time it's recognized
                self.add_anomalies(np.expand_dims(emb, axis=0))
        elif result["action"] == 2:
            # known anomaly -> nothing new to add (already known)
            pass

        # Optionally persist minimal log if desired (left to user)
        return result

    def process_batch(self, X: np.ndarray, verify_normals: Optional[np.ndarray] = None) -> Dict:
        """
        X: (N, input_dim) numpy array of preprocessed features
        verify_normals: optional boolean array of length N indicating that corresponding logs are verified normal
        Returns dict with arrays for each field.
        """
        X = np.asarray(X, dtype='float32')
        if X.ndim != 2:
            raise ValueError("process_batch expects 2D array")
        if self.encoder is None:
            input_dim = X.shape[1]
            embed_dim = getattr(self, "embed_dim", 64)
            self._ensure_encoder(input_dim=input_dim, embed_dim=embed_dim)

        embs = self.embed_batch(X, batch_size=self.cfg["EMBED_BATCH"])
        normal_scores, anomaly_scores = self.infer_scores(embs)
        anomaly_flag, known_flag, action = self.classify(normal_scores, anomaly_scores)

        # Prepare result dict
        res = {
            "embeddings": embs,
            "normal_scores": normal_scores,
            "anomaly_scores": anomaly_scores,
            "is_anomaly": anomaly_flag,
            "is_known_attack": known_flag,
            "action": action,  # 0 normal, 1 new anomaly, 2 known anomaly
            "timestamp": time.time(),
        }

        # Persist additions depending on verify_normals or automatic rules
        if verify_normals is None:
            verify_normals = np.zeros(len(X), dtype=bool)
        for i in range(len(X)):
            if res["action"][i] == 0 and verify_normals[i]:
                self.add_normals(embs[i:i+1])
            elif res["action"][i] == 1:
                if self.cfg["ANOMALY_ADD_AUTOMATIC"] or (verify_normals[i] is False):
                    self.add_anomalies(embs[i:i+1])

        return res

    # -----------------------
    # Memory update helpers
    # -----------------------
    def add_normals(self, new_embs: np.ndarray):
        new_embs = np.asarray(new_embs, dtype='float32')
        # append to memory
        if self.normal_memory.size == 0:
            self.normal_memory = new_embs.copy()
        else:
            self.normal_memory = np.vstack([self.normal_memory, new_embs])
        # cap memory
        if len(self.normal_memory) > self.cfg["MAX_NORMAL_MEMORY"]:
            # drop oldest
            excess = len(self.normal_memory) - self.cfg["MAX_NORMAL_MEMORY"]
            self.normal_memory = self.normal_memory[excess:]
        np.save(self.cfg["NORMAL_MEMORY_NPY"], self.normal_memory)
        # add to FAISS normal index
        self.faiss_normal.add(new_embs)
        # persist index
        faiss.write_index(self.faiss_normal, self.cfg["FAISS_NORMAL_PERSIST"])
        print("[memory] added normals:", new_embs.shape[0], "normal_memory shape:", self.normal_memory.shape)

    def add_anomalies(self, new_embs: np.ndarray):
        new_embs = np.asarray(new_embs, dtype='float32')
        if self.anomaly_memory.size == 0:
            self.anomaly_memory = new_embs.copy()
        else:
            self.anomaly_memory = np.vstack([self.anomaly_memory, new_embs])
        # cap memory
        if len(self.anomaly_memory) > self.cfg["MAX_ANOMALY_MEMORY"]:
            excess = len(self.anomaly_memory) - self.cfg["MAX_ANOMALY_MEMORY"]
            self.anomaly_memory = self.anomaly_memory[excess:]
        np.save(self.cfg["ANOMALY_MEMORY_NPY"], self.anomaly_memory)
        # add to anomaly FAISS index
        self.faiss_anomaly.add(new_embs)
        faiss.write_index(self.faiss_anomaly, self.cfg["FAISS_ANOMALY_PERSIST"])
        print("[memory] added anomalies:", new_embs.shape[0], "anomaly_memory shape:", self.anomaly_memory.shape)

    # -----------------------
    # Maintenance tasks
    # -----------------------
    def maintenance(self, force: bool = False):
        """
        Periodic tasks:
          - Recompute thresholds from current normal_memory (sliding window)
          - Optionally prune old memory
        """
        now = time.time()
        if not force and (now - self.last_maintenance) < self.cfg["MAINTENANCE_INTERVAL_SEC"]:
            return
        self.last_maintenance = now

        if len(self.normal_memory) < 10:
            print("[maintenance] not enough normal memory to recompute thresholds.")
            return

        # compute distances of normal_memory to nearest in normal index (excluding itself not possible easily,
        # but good enough for windowed sliding set)
        D, _ = self.faiss_normal.search(self.normal_memory.astype('float32'), 1)
        distances = D.ravel()
        low = float(np.percentile(distances, 90))
        high = float(np.percentile(distances, 99))
        self.thresholds = {"low": low, "high": high}
        joblib.dump(self.thresholds, self.cfg["THRESH_PATH"])
        # update anomaly sim threshold relative to new high
        self.cfg["ANOMALY_SIM_THRESHOLD"] = max(1e-6, high * self.cfg["ANOMALY_KNOWN_SIMILE_RATIO"])
        print("[maintenance] recomputed thresholds:", self.thresholds, "anomaly_sim_thresh:", self.cfg["ANOMALY_SIM_THRESHOLD"])

        # Optionally prune old memory (FIFO already enforced on add)
        # Optionally rebuild faiss index from normal_memory if ntotal grows and becomes inefficient; omitted for simplicity.

    # -----------------------
    # Save state (manual)
    # -----------------------
    def save_state(self):
        np.save(self.cfg["NORMAL_MEMORY_NPY"], self.normal_memory)
        np.save(self.cfg["ANOMALY_MEMORY_NPY"], self.anomaly_memory)
        joblib.dump(self.thresholds, self.cfg["THRESH_PATH"])
        faiss.write_index(self.faiss_normal, self.cfg["FAISS_NORMAL_PERSIST"])
        faiss.write_index(self.faiss_anomaly, self.cfg["FAISS_ANOMALY_PERSIST"])
        print("[save] state saved.")

# -----------------------
# Example usage snippet
# -----------------------
if __name__ == "__main__":
    # when running as script
    config = {
        # override defaults if needed
        "ENCODER_PATH": "encoder_for_inference.pth",
        "FAISS_NORMAL_PATH": "faiss_index.idx",
        "THRESH_PATH": "thresholds.joblib",
        "TRAIN_EMB_PATH": "train_embeddings.pt",
        "NORMAL_MEMORY_NPY": "normal_memory.npy",
        "ANOMALY_MEMORY_NPY": "anomaly_memory.npy",
        "FAISS_NORMAL_PERSIST": "faiss_normal.idx",
        "FAISS_ANOMALY_PERSIST": "faiss_anomaly.idx",
        "EMBED_BATCH": 64,
        "ANOMALY_ADD_AUTOMATIC": True,
        "MAX_NORMAL_MEMORY": 100000,
        "MAX_ANOMALY_MEMORY": 20000,
    }

    detector = ContinualDetector(config=config)

    # Example: simulate a single preprocessed flow (replace with real features)
    dummy = [
    3.5528493, 3.1619408, 2.8944726, 2.4929457, 0.55570745, 2.294258,
    -0.26921436, 0.23977916, 0.4819299, 0.87948656, 1.3528618,
    -0.22360651, 3.572857, 3.7197673, 0.50586927, 11.469458,
    1.2630873, 1.2843541, 179.0095, 3.4197965, 0.49042776, 5.7716136,
    0.13124256, 0.1248575, 1, 1, 0, 0, 0.000385282, 0, 113, 0, 4,
    7, 4, 1, 1, 70, 147, 173, 0, 0
]

    # if running for first time, ensure your dummy has the right input dimension
    try:
        out = detector.process_single(dummy, verify_normal=False)
        print("Result:", out)
    except Exception as e:
        print("Example error (likely due to wrong input_dim):", e)

    # call maintenance periodically
    detector.maintenance(force=True)
    detector.save_state()
