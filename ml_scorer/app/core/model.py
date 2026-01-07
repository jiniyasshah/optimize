import os
import joblib
import sys

class WAFModel:
    def __init__(self, model_path: str = "waf_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.load()

    def load(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                print(f"✅ ML Model Loaded: {self.model_path}")
            except Exception as e:
                print(f"❌ Failed to load model: {e}")
                sys.exit(1)
        else:
            print(f"❌ Critical: Model file not found at {self.model_path}")
            # In production, you might want to exit or raise an error
            # sys.exit(1) 

    def predict(self, content: str):
        if not self.model:
            raise RuntimeError("Model is not loaded")
        
        # Scikit-learn expect list of inputs
        pred_label = self.model.predict([content])[0]
        probs = self.model.predict_proba([content])[0]
        
        # Get confidence of the predicted label
        confidence = probs[list(self.model.classes_).index(pred_label)]
        return pred_label, confidence