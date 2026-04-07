import structlog
from typing import List
from fastapi import WebSocket, WebSocketDisconnect

logger = structlog.get_logger("websocket")

class ConnectionManager:
    """Manages active WebSocket connections to push realtime telemetry updates."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("ws_client_connected", active_clients=len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("ws_client_disconnected", active_clients=len(self.active_connections))

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
            
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except WebSocketDisconnect:
                disconnected.append(connection)
            except Exception as e:
                logger.error("ws_broadcast_failed", error=str(e))
                disconnected.append(connection)

        # Cleanup dead connections lazily
        for d in disconnected:
            self.disconnect(d)

manager = ConnectionManager()
