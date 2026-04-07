import time
import json
import traceback
import asyncio
import aiohttp
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from app.core.config import config
from app.utils.metrics import PACKETS_PROCESSED_TOTAL, PACKETS_DROPPED_TOTAL
from app.core.logging import setup_logging

# Configure Logging
logger = setup_logging("PacketSniffer")

class LivePacketSniffer:
    """
    Captures live network traffic, extracts relevant features, 
    and forwards structured data to the internal API webhook for analysis.
    Uses async IO and backpressure dropping under heavy load.
    """
    def __init__(self, interface=None, target_ip=None, notify_endpoint="http://localhost:8000/api/internal/notify"):
        self.interface = interface
        self.target_ip = target_ip or config.TARGET_SERVER_IP
        self.notify_endpoint = notify_endpoint
        self.is_running = False
        self.packet_queue = None
        self.dropped_packets = 0
        self.loop = None
        self.session = None

    def _extract_features(self, packet):
        try:
            if IP not in packet:
                return None

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            packet_size = len(packet)

            protocol = "UNKNOWN"
            src_port = 0
            dst_port = 0
            flags = ""

            if TCP in packet:
                protocol = "TCP"
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags = str(tcp_layer.flags)
            elif UDP in packet:
                protocol = "UDP"
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
            elif ICMP in packet:
                protocol = "ICMP"

            telemetry = {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "protocol": protocol,
                "packet_size": packet_size,
                "dest_port": dst_port,
                "flags": flags,
                "metadata": {
                    "source": "SNIFFER",
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "length": packet_size
                }
            }
            return telemetry
        except Exception as e:
            logger.error(f"Error extracting features: {traceback.format_exc()}")
            return None

    def _put_telemetry(self, telemetry):
        if not self.packet_queue: return
        try:
            self.packet_queue.put_nowait(telemetry)
            PACKETS_PROCESSED_TOTAL.inc()
        except asyncio.QueueFull:
            self.dropped_packets += 1
            PACKETS_DROPPED_TOTAL.inc()
            if self.dropped_packets % 100 == 1:
                logger.warning(f"Packet queue full! Dropped payload. Total Drops: {self.dropped_packets}")

    def _packet_callback(self, packet):
        telemetry = self._extract_features(packet)
        if telemetry and self.loop:
            self.loop.call_soon_threadsafe(self._put_telemetry, telemetry)

    async def _process_queue(self):
        batch = []
        batch_size = 50
        flush_interval = 1.0
        last_flush = time.time()

        while self.is_running:
            try:
                telemetry = await asyncio.wait_for(self.packet_queue.get(), timeout=0.5)
                batch.append(telemetry)
                self.packet_queue.task_done()
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                logger.error(f"Queue processing error: {traceback.format_exc()}")

            now = time.time()
            if len(batch) >= batch_size or (batch and (now - last_flush) > flush_interval):
                await self._dispatch_batch(batch)
                batch = []
                last_flush = now

    async def _dispatch_batch(self, batch):
        if not self.session:
            self.session = aiohttp.ClientSession()
        try:
            headers = {"X-API-Key": getattr(config, "TELEMETRY_API_KEY", "secure-telemetry-key-123")}
            async with self.session.post(
                "http://localhost:8000/api/telemetry", 
                json=batch, 
                headers=headers,
                timeout=2.0
            ) as response:
                response.raise_for_status()
                logger.debug(f"Dispatched batch of {len(batch)} packets.")
        except asyncio.TimeoutError:
            logger.error(f"Timeout dispatching batch. Dropping {len(batch)} items.")
        except Exception as e:
            logger.error(f"Failed to dispatch batch: {e}. Dropping {len(batch)} items.")

    def _sniff_sync(self, bpf_filter):
        try:
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self._packet_callback,
                store=False
            )
        except Exception as e:
             logger.error(f"Fatal sniffing error inner loop: {e}", exc_info=True)

    async def start(self):
        logger.info(f"Starting Live Packet Sniffer. Monitoring Target: {self.target_ip}")
        from prometheus_client import start_http_server
        start_http_server(9001)

        self.is_running = True
        self.loop = asyncio.get_running_loop()
        self.packet_queue = asyncio.Queue(maxsize=10000)
        
        dispatcher_task = asyncio.create_task(self._process_queue())
        bpf_filter = f"host {self.target_ip}" if self.target_ip else "ip"

        try:
            await asyncio.to_thread(self._sniff_sync, bpf_filter)
        except Exception as e:
            logger.error(f"Fatal sniffing error: {traceback.format_exc()}")
        finally:
            await self.stop()
            dispatcher_task.cancel()

    async def stop(self):
        logger.info("Stopping sniffer...")
        self.is_running = False
        if self.session:
            await self.session.close()
            self.session = None

if __name__ == "__main__":
    sniffer = LivePacketSniffer()
    try:
        asyncio.run(sniffer.start())
    except KeyboardInterrupt:
        logger.info("Interrupted. Shutting down.")
