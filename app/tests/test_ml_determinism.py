import unittest
import sys
sys.path.append('/app')
from app.services.ml_service import InferenceEngine, FeatureExtractor, DeterministicRuleEngine
import pandas as pd

class TestMLDeterminism(unittest.TestCase):
    
    def test_preprocess_determinism(self):
        """
        Verify that InferenceEngine.preprocess_payload() always produces 
        bitwise identical outputs for the same packet_data, avoiding np.random
        or other non-deterministic behaviour.
        """
        packet = {
            "dest_port": 22,
            "packet_size": 450,
            "flow_duration": 1500,
            "total_fwd_packets": 3
        }
        
        # Generate 10 outputs and verify they are all identical to the first
        results = [FeatureExtractor.preprocess_payload(packet) for _ in range(10)]
        baseline = results[0].values.tolist()
        
        for idx, result in enumerate(results[1:], start=1):
            self.assertEqual(
                baseline, 
                result.values.tolist(),
                f"Non-deterministic ML preprocessing detected on iteration {idx}"
            )

    def test_fallback_rule_engine(self):
        """
        Verify that DeterministicRuleEngine deterministic logic is stable.
        """
        # Brute force match
        res1 = DeterministicRuleEngine.classify({"dest_port": 22, "packet_size": 200})
        self.assertEqual(res1["label"], "Brute Force")
        
        # Exfiltration match
        res2 = DeterministicRuleEngine.classify({"dest_port": 53, "packet_size": 1500})
        self.assertEqual(res2["label"], "Exfiltration")
        self.assertEqual(res2["risk_score"], 70)  # 65 + 5 for packet > 1400
        
        # BENIGN fallback
        res3 = DeterministicRuleEngine.classify({"dest_port": 443})
        self.assertEqual(res3["label"], "BENIGN")

    def test_model_absent_fallback(self):
        """
        Verify that InferenceEngine.predict() routes to DeterministicRuleEngine 
        when the model is absent, rather than returning 'Unknown'.
        """
        original_model = InferenceEngine._model
        
        try:
            # Simulate absent/corrupt model
            InferenceEngine._model = None
            
            # Predict against port 3389 (RDP) -> Rule engine maps to Brute Force
            res = FeatureExtractor.predict({"dest_port": 3389, "packet_size": 0})
            
            self.assertEqual(res["label"], "Brute Force")
            self.assertTrue(res["confidence"] > 0)
            self.assertTrue(res["risk_score"] > 0)
            self.assertNotEqual(res["label"], "Unknown")
            
        finally:
            InferenceEngine._model = original_model

if __name__ == '__main__':
    unittest.main()
