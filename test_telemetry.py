"""
Quick smoke test for /api/telemetry endpoint.
"""
import asyncio
import aiohttp
import json

async def test():
    async with aiohttp.ClientSession() as s:
        # Login
        r = await s.post('http://127.0.0.1:8000/api/auth/login',
                         json={'username': 'admin', 'password': 'password'})
        d = await r.json()
        print('Login status:', r.status)
        if 'access_token' not in d:
            print('No token:', d)
            return
        api_key_h = {'X-API-Key': 'secure-telemetry-key-123'}

        # Test telemetry
        payload = [{'id': 'tel-1', 'source_ip': '5.5.5.5', 'destination_ip': '10.0.0.5',
                    'dest_port': 80, 'packet_size': 1500, 'total_fwd_packets': 100,
                    'flow_duration': 5000, 'label': 'DDoS', 'metadata': {'source': 'NIDS'}}]
        r2 = await s.post('http://127.0.0.1:8000/api/telemetry', json=payload, headers=api_key_h)
        txt = await r2.text()
        print('Telemetry status:', r2.status, txt[:500])

asyncio.run(test())
