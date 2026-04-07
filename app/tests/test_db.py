import pytest
import os
import json
import asyncio
from unittest.mock import AsyncMock, patch
from app.db.connection import db

@pytest.fixture
def clean_db():
    if os.path.exists("backend/test_fallback.json"):
        os.remove("backend/test_fallback.json")
    from app.core.config import config
    config.JSON_DB_PATH = "backend/test_fallback.json"
    yield
    if os.path.exists("backend/test_fallback.json"):
        os.remove("backend/test_fallback.json")

@pytest.mark.asyncio
async def test_database_fallback_save_and_read(clean_db):
    test_event = {"id": "test-123", "label": "Normal", "timestamp": "2024-01-01T00:00:00Z"}
    
    # Switch to fallback mode for testing
    db.set_mode(True)
    await db.dal.save_event(test_event)
    
    events = await db.dal.query_security_events()
    assert len(events) == 1
    assert events[0]["id"] == "test-123"

@pytest.mark.asyncio
async def test_database_fallback_time_range(clean_db):
    db.set_mode(True)
    e1 = {"id": "1", "timestamp": "2024-01-01T10:00:00Z"}
    e2 = {"id": "2", "timestamp": "2024-01-01T12:00:00Z"}
    e3 = {"id": "3", "timestamp": "2024-01-01T14:00:00Z"}
    
    await db.dal.save_event(e1)
    await db.dal.save_event(e2)
    await db.dal.save_event(e3)
    
    start = "2024-01-01T11:00:00Z"
    end = "2024-01-01T13:00:00Z"
    result = await db.dal.query_security_events_by_timerange(start, end)
    
    assert len(result) == 1
    assert result[0]["id"] == "2"

@pytest.mark.asyncio
async def test_synchronize_state(clean_db):
    from unittest.mock import patch, MagicMock

    # Set LOCAL mode first so save_event writes to local JSON
    db.set_mode(True)
    await db.dal.save_event({"id": "local-1"})

    # Simulate cloud-connected mode without touching a real MongoDB
    db.dal._is_local_mode = False
    orig_collection = db.dal._collection

    # Motor cursor: find/sort/limit are synchronous chain methods;
    # only to_list is awaitable.
    mock_to_list = AsyncMock(return_value=[{"id": "mongo-1"}])
    mock_cursor = MagicMock()
    mock_cursor.sort.return_value = mock_cursor
    mock_cursor.limit.return_value = mock_cursor
    mock_cursor.to_list = mock_to_list

    mock_collection = MagicMock()
    mock_collection.find.return_value = mock_cursor
    mock_collection.insert_many = AsyncMock()
    db.dal._collection = mock_collection

    # Skip _ensure_connection so no real MongoDB call is made
    with patch.object(db.dal, '_ensure_connection', new=AsyncMock()):
        await db.dal.synchronize_state()

    # Expect the fallback cache to have both now
    cache = await db.dal._read_local_data()
    ids = [c["id"] for c in cache]
    assert "mongo-1" in ids
    assert "local-1" in ids

    # Restore
    db.dal._collection = orig_collection
    db.dal._is_local_mode = True
