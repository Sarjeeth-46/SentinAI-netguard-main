import asyncio, sys, os
sys.path.insert(0, 'c:/SentinAI-netguard')
os.environ['MONGO_URI'] = 'mongodb://localhost:27017'
os.environ['INITIAL_ADMIN_PASSWORD'] = 'password'

from app.services.auth_service import AuthService
svc = AuthService()

async def test():
    print('--- ensure_admin_user (sync password) ---')
    await svc.ensure_admin_user()

    print('--- authenticate with "password" ---')
    t1 = await svc.authenticate_user('admin', 'password')
    print('password OK:', bool(t1))

    print('--- authenticate with "changeme_in_prod!" ---')
    t2 = await svc.authenticate_user('admin', 'changeme_in_prod!')
    print('changeme_in_prod! OK (should be False):', bool(t2))

    print('--- authenticate with wrong password ---')
    t3 = await svc.authenticate_user('admin', 'wrongpass')
    print('wrongpass OK (should be False):', bool(t3))

asyncio.run(test())
