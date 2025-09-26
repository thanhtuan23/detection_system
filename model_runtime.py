import os
import json
import numpy as np
import joblib
import tensorflow as tf
import sys

# ==============================================================
# Compatibility shim: ReducedPreprocessorWrapper
# --------------------------------------------------------------
# Các pipeline đã lưu trong notebook có thể chứa lớp
# ReducedPreprocessorWrapper (được pickle với __module__='__main__').
# Khi chạy ở runtime (app.py), __main__ là app.py và không có lớp này => lỗi:
#   Can't get attribute 'ReducedPreprocessorWrapper' ...
# Ta định nghĩa lại lớp tối thiểu và gắn vào sys.modules['__main__']
# để joblib có thể unpickle an toàn.
# ==============================================================

class ReducedPreprocessorWrapper:
    """Wrapper cắt giảm số cột sau transform.

    Kỳ vọng các thuộc tính có thể đã được pickle:
        - base: ColumnTransformer gốc
        - selected_indices hoặc selected_indices_sorted: danh sách/array chỉ số giữ lại
        - (tùy chọn) full_order_desc, importances_full, importances_full_desc
    """
    def __init__(self, base_preprocessor=None, selected_indices=None, selected_indices_sorted=None, *args, **kwargs):
        self.base = base_preprocessor
        # Chấp nhận cả hai tên thuộc tính
        indices = selected_indices_sorted if selected_indices_sorted is not None else selected_indices
        try:
            if indices is not None:
                self.selected_indices = np.array(indices)
            else:
                self.selected_indices = None
        except Exception:
            self.selected_indices = indices

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        if self.base is None:
            raise RuntimeError("ReducedPreprocessorWrapper thiếu thuộc tính 'base'.")
        Xt = self.base.transform(X)
        if self.selected_indices is None:
            return Xt
        try:
            import scipy.sparse as sp  # type: ignore
            if sp.issparse(Xt):
                return Xt[:, self.selected_indices]
        except Exception:
            pass
        return Xt[:, self.selected_indices]

    def fit_transform(self, X, y=None):
        return self.fit(X, y).transform(X)

# Gắn vào module __main__ nếu chưa có để hỗ trợ pickle cũ
_main_mod = sys.modules.get('__main__')
if _main_mod is not None and not hasattr(_main_mod, 'ReducedPreprocessorWrapper'):
    setattr(_main_mod, 'ReducedPreprocessorWrapper', ReducedPreprocessorWrapper)


def load_model_and_preprocess(preprocess_path: str, model_path: str):
    """
    Load pipeline (.pkl) và mô hình (DL .h5 Keras hoặc ML .pkl sklearn) dựa vào metrics_summary.json nếu có.
    - Hỗ trợ cả khi model_path trỏ trực tiếp đến file (.h5 hoặc .pkl) hoặc chỉ là một file bất kỳ trong thư mục models/.
    Trả về: (preprocess, model, model_type: 'ml'|'dl', info dict)
    info = { 'path': str, 'winner_type': str|None, 'best_ml_name': str|None }
    """
    if not os.path.exists(preprocess_path):
        raise FileNotFoundError(f"Preprocess file not found: {preprocess_path}")
    preprocess = joblib.load(preprocess_path)

    # Suy ra thư mục chứa model và metrics
    model_dir = os.path.dirname(model_path) or '.'
    metrics_path = os.path.join(model_dir, 'metrics_summary.json')

    # Ứng viên mặc định
    dl_candidate = os.path.join(model_dir, 'best_model_dl.h5')
    ml_candidate = os.path.join(model_dir, 'best_model_ml.pkl')

    # Nếu model_path đã chỉ rõ đuôi
    if model_path.lower().endswith('.h5'):
        dl_candidate = model_path
    elif model_path.lower().endswith('.pkl'):
        ml_candidate = model_path

    prefer_ml = False
    best_ml_name = None
    winner_type = None
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, 'r', encoding='utf-8') as f:
                metrics_summary = json.load(f)
            winner_type = str(metrics_summary.get('winner_type', '')).lower() or None
            prefer_ml = winner_type == 'ml'
            best_ml_name = metrics_summary.get('best_ml_name')
        except Exception:
            prefer_ml = False
            winner_type = None

    # Ưu tiên theo metrics: ML nếu được chọn và có file
    if prefer_ml and os.path.exists(ml_candidate):
        model = joblib.load(ml_candidate)
        return preprocess, model, 'ml', {'path': ml_candidate, 'winner_type': winner_type, 'best_ml_name': best_ml_name}

    # Nếu không, thử DL nếu có
    if os.path.exists(dl_candidate):
        try:
            model = tf.keras.models.load_model(dl_candidate)
            return preprocess, model, 'dl', {'path': dl_candidate, 'winner_type': winner_type, 'best_ml_name': best_ml_name}
        except Exception:
            # Nếu file không phải Keras hợp lệ, tiếp tục thử ML
            pass

    # Cuối cùng, thử ML nếu có
    if os.path.exists(ml_candidate):
        model = joblib.load(ml_candidate)
        return preprocess, model, 'ml', {'path': ml_candidate, 'winner_type': winner_type, 'best_ml_name': best_ml_name}

    raise FileNotFoundError("No model file found (expected best_model_dl.h5 or best_model_ml.pkl)")


def predict_probabilities(model, model_type: str, X) -> np.ndarray:
    """Trả về xác suất tấn công (lớp 1) cho cả Keras (DL) và sklearn (ML)."""
    import numpy as _np
    if model_type == 'dl':
        # Keras cần dense float32
        try:
            X_nn = X.toarray().astype('float32')
        except Exception:
            X_nn = _np.asarray(X, dtype='float32')
        probs = model.predict(X_nn, verbose=0)
        return _np.asarray(probs).reshape(-1)

    est = model
    if hasattr(est, 'predict_proba'):
        try:
            proba = est.predict_proba(X)
            if proba.ndim == 2 and proba.shape[1] == 2:
                return proba[:, 1]
            return _np.asarray(proba).reshape(-1)
        except Exception:
            pass
    if hasattr(est, 'decision_function'):
        try:
            scores = est.decision_function(X)
            scores = _np.asarray(scores).reshape(-1)
            scores = _np.clip(scores, -50, 50)
            return 1.0 / (1.0 + _np.exp(-scores))
        except Exception:
            pass
    try:
        preds = est.predict(X)
        return _np.asarray(preds).astype(float).reshape(-1)
    except Exception:
        return _np.zeros((X.shape[0],), dtype=float)
