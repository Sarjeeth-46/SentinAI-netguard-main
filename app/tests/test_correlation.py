import pytest
import time
from unittest.mock import patch
from app.domain.correlation_service import CorrelationEngine

@pytest.fixture
def engine():
    # Run with small window for testing
    return CorrelationEngine(window_seconds=2)

def test_correlation_duplicate_suppression(engine):
    # Test memory-based correlation creation
    log_event = {"id": "log1", "source_ip": "10.0.0.1", "metadata": {"source": "HIDS"}}
    packet_event = {"id": "pkt1", "source_ip": "10.0.0.1", "metadata": {"source": "NIDS"}}
    
    alert1 = engine.process_event(log_event)
    assert alert1 is None
    
    alert2 = engine.process_event(packet_event)
    assert alert2 is not None
    assert alert2["severity"] == "Critical"
    assert "log_evidence" in alert2["metadata"]

@patch("time.time")
def test_correlation_expiry(mock_time, engine):
    log_event = {"id": "log1", "source_ip": "10.0.0.5", "metadata": {"source": "HIDS"}}
    packet_event = {"id": "pkt1", "source_ip": "10.0.0.5", "metadata": {"source": "NIDS"}}
    
    # Event 1 at t=100
    mock_time.return_value = 100.0
    engine.process_event(log_event)
    
    # Event 2 at t=105 (>2s window expired)
    mock_time.return_value = 105.0
    alert = engine.process_event(packet_event)
    
    assert alert is None  # Should expire log_event because it's too old

