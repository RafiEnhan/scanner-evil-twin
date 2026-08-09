import os
import sys
import numpy as np


class ONNXModelWrapper:
    """
    Wrapper tipis di atas onnxruntime.InferenceSession untuk menyeragamkan
    antarmuka prediksi agar kompatibel dengan API sklearn (predict / predict_proba).
    """

    def __init__(self, onnx_path):
        """
        Memuat model ONNX dari file dan mengekstrak metadata input/output.

        Args:
            onnx_path (str): Path absolut ke file model .onnx.
        """
        import onnxruntime as rt
        self.session = rt.InferenceSession(onnx_path)
        self.input_name = self.session.get_inputs()[0].name
        self.output_names = [o.name for o in self.session.get_outputs()]

    def predict_proba(self, X):
        """
        Menjalankan inferensi dan mengembalikan probabilitas per kelas.
        Mendukung tiga format output ONNX: list of dict, ndarray, atau label saja.

        Args:
            X (array-like): Fitur input, shape (n_samples, n_features) atau (n_features,).

        Returns:
            np.ndarray: Array shape (n_samples, 2) berisi [prob_kelas_0, prob_kelas_1].
        """
        X = np.array(X, dtype=np.float32)
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
        outputs = self.session.run(self.output_names, {self.input_name: X})
        if len(outputs) > 1 and isinstance(outputs[1], list) and isinstance(outputs[1][0], dict):
            probs = [[d.get(0, 0.0), d.get(1, 0.0)] for d in outputs[1]]
            return np.array(probs)
        elif len(outputs) > 1 and isinstance(outputs[1], np.ndarray):
            return outputs[1]
        else:
            pred = outputs[0]
            return np.column_stack([1.0 - pred, pred])

    def predict(self, X):
        """
        Menjalankan inferensi dan mengembalikan label prediksi (kelas).

        Args:
            X (array-like): Fitur input, shape (n_samples, n_features) atau (n_features,).

        Returns:
            np.ndarray: Array label prediksi, shape (n_samples,).
        """
        X = np.array(X, dtype=np.float32)
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
        outputs = self.session.run(self.output_names, {self.input_name: X})
        return outputs[0]


def load_trained_model():
    """
    Memuat model ML yang sudah dilatih dari lokasi yang diprioritaskan:
    .onnx (utama) → .joblib → .pkl. Mendukung mode bundled (PyInstaller _MEIPASS)
    maupun mode development biasa.

    Returns:
        tuple[ONNXModelWrapper | Any, str]: Pasangan (model, path) dari model
        yang berhasil dimuat.

    Raises:
        RuntimeError: Jika tidak ada file model yang ditemukan di semua kandidat path.
    """
    base_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    candidate_paths = [
        "purifier_rf_model.onnx",
        os.path.join(base_dir, "purifier_rf_model.onnx"),
        os.path.join(os.path.dirname(base_dir), "purifier_rf_model.onnx"),
        "purifier_rf_model.joblib",
        "purifier_rf_model.pkl"
    ]
    for model_path in candidate_paths:
        if os.path.exists(model_path):
            try:
                if model_path.endswith('.onnx'):
                    model = ONNXModelWrapper(model_path)
                    return model, model_path
                elif model_path.endswith('.joblib'):
                    import joblib
                    model = joblib.load(model_path)
                    return model, model_path
                else:
                    import pickle
                    with open(model_path, 'rb') as f:
                        model = pickle.load(f)
                    return model, model_path
            except Exception as e:
                print(f"Failed to load '{model_path}': {e}", file=sys.stderr)

    raise RuntimeError("Error: ONNX model file 'purifier_rf_model.onnx' not found.")
