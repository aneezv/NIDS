# Archived training scripts

These scripts are **not** part of the canonical pipeline. They are kept here for reference only.

| File | Why it's archived |
|---|---|
| `train_legacy.py` | Live-capture trainer (tshark). Uses 4 dot-named columns (`frame.len`, `port`, `ip.proto`, `tcp.flags`) — incompatible with the current 6-feature detector schema. Output (`model.pkl`) is not used at runtime. |
| `create_model.py` | Synthetic-data trainer with the same 4-column schema as `train_legacy.py`. Superseded by `../train.py`. |
| `train_feedback.py` | Periodic-retraining stub for CSV feedback data. Same 4-column schema. Idea is sound but the implementation is incompatible with the current detector. |
| `train_hybrid_model.py` | RandomForest + IsolationForest hybrid. Functional, but **off-message**: the project's core pitch is unsupervised anomaly detection of *unknown* attacks. A supervised RF only catches labeled patterns, which weakens that claim. Kept only as a "we explored this but rejected it" reference. |

The canonical trainer is **`../train.py`** (formerly `train_better_model.py`): pure Isolation Forest, realistic synthetic normal + attack data, RobustScaler in the sklearn Pipeline, n_estimators=300. Output: `model_advanced.pkl`.

Do not import from this directory at runtime.
