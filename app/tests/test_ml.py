import pytest
from app.services.detector import RiskAssessmentEngine
from app.services.ml_service import InferenceEngine, FeatureExtractor

def test_entropy_calculation():
    probs_high_confidence = [0.95, 0.05]
    probs_low_confidence = [0.5, 0.5]
    
    ent_high = RiskAssessmentEngine.calculate_entropy_score(probs_high_confidence)
    ent_low = RiskAssessmentEngine.calculate_entropy_score(probs_low_confidence)
    
    assert ent_low > ent_high, "Entropy should be higher for uniform distributions"

def test_severity_index_bounds():
    # Test valid bounds
    score = RiskAssessmentEngine.compute_severity_index(0.99, "Brute Force")
    assert 0 <= score <= 100
    
    # Test edge cases
    score_low = RiskAssessmentEngine.compute_severity_index(0.01, "Normal")
    assert 0 <= score_low <= 100
    
    score_high = RiskAssessmentEngine.compute_severity_index(1.0, "DDoS")
    assert 0 <= score_high <= 100

def test_classifier_fallback():
    # FeatureExtractor.predict() delegates to InferenceEngine for model state,
    # then falls back to DeterministicRuleEngine when the model is absent.
    assert hasattr(FeatureExtractor, 'predict'), "FeatureExtractor must expose .predict()"
    result = FeatureExtractor.predict({"dest_port": 22, "packet_size": 200})
    assert "label" in result
    assert "confidence" in result
    assert "risk_score" in result
