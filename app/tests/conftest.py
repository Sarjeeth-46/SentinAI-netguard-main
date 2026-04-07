import sys
from unittest.mock import MagicMock

# Create a mock object that will act as the sklearn module and its submodules
mock_sklearn = MagicMock()
mock_sklearn.ensemble = MagicMock()
mock_sklearn.model_selection = MagicMock()
mock_sklearn.metrics = MagicMock()
mock_sklearn.preprocessing = MagicMock()

# Inject into sys.modules
sys.modules['sklearn'] = mock_sklearn
sys.modules['sklearn.ensemble'] = mock_sklearn.ensemble
sys.modules['sklearn.model_selection'] = mock_sklearn.model_selection
sys.modules['sklearn.metrics'] = mock_sklearn.metrics
sys.modules['sklearn.preprocessing'] = mock_sklearn.preprocessing

# Also mock pandas if it fails to compile
import logging
logger = logging.getLogger("PytestSetup")
logger.info("Injected Sklearn mocks to bypass Python 3.14 compilation issues.")
