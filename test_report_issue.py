import asyncio
from app.services.reporting_service import reporting_service

async def test():
    date_str = "2024-05-10"
    print("Generating report...")
    res = await reporting_service.generate_report(date_str)
    print("Generate output metadata:", res.get("metadata"))
    
    print("Fetching report...")
    get_res = reporting_service.get_report(date_str)
    print("Fetch output error:", get_res.get("error"))
    print("Fetch output metadata:", get_res.get("metadata"))

if __name__ == "__main__":
    asyncio.run(test())
