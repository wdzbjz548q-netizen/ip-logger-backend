from fastapi import FastAPI, APIRouter, Request, Response, Query
from fastapi.responses import StreamingResponse, RedirectResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import io
import json
import csv
import httpx

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")

TRACKING_PIXEL = bytes([
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00,
    0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
    0x01, 0x00, 0x3b
])

class IPLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    isp: Optional[str] = None
    user_agent: Optional[str] = None
    browser: Optional[str] = None
    os: Optional[str] = None
    device: Optional[str] = None
    referrer: Optional[str] = None
    notes: Optional[str] = None
    source: str = "api"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class IPLogCreate(BaseModel):
    ip: str
    notes: Optional[str] = None

def parse_user_agent(ua: str) -> dict:
    browser = "Unknown"
    os_name = "Unknown"
    device = "Desktop"
    if not ua:
        return {"browser": browser, "os": os_name, "device": device}
    ua_lower = ua.lower()
    if "firefox" in ua_lower:
        browser = "Firefox"
    elif "edg" in ua_lower:
        browser = "Edge"
    elif "chrome" in ua_lower:
        browser = "Chrome"
    elif "safari" in ua_lower:
        browser = "Safari"
    elif "opera" in ua_lower or "opr" in ua_lower:
        browser = "Opera"
    if "windows" in ua_lower:
        os_name = "Windows"
    elif "mac os" in ua_lower or "macos" in ua_lower:
        os_name = "macOS"
    elif "linux" in ua_lower:
        os_name = "Linux"
    elif "android" in ua_lower:
        os_name = "Android"
    elif "iphone" in ua_lower or "ipad" in ua_lower:
        os_name = "iOS"
    if "mobile" in ua_lower or "android" in ua_lower or "iphone" in ua_lower:
        device = "Mobile"
    elif "tablet" in ua_lower or "ipad" in ua_lower:
        device = "Tablet"
    return {"browser": browser, "os": os_name, "device": device}

async def get_geo_info(ip: str) -> dict:
    try:
        if ip in ["127.0.0.1", "localhost", "::1"] or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return {"country": "Local", "city": "Local", "region": "Local", "isp": "Local Network"}
        async with httpx.AsyncClient(timeout=5.0) as http_client:
            response = await http_client.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,regionName,isp")
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "region": data.get("regionName", "Unknown"),
                        "isp": data.get("isp", "Unknown")
                    }
    except Exception as e:
        logging.error(f"Geo lookup failed: {e}")
    return {"country": "Unknown", "city": "Unknown", "region": "Unknown", "isp": "Unknown"}

def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip
    return request.client.host if request.client else "Unknown"

@api_router.get("/")
async def root():
    return {"message": "IP Logger API"}

@api_router.get("/logs", response_model=List[IPLog])
async def get_logs(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0), search: Optional[str] = None, country: Optional[str] = None, source: Optional[str] = None):
    query = {}
    if search:
        query["$or"] = [{"ip": {"$regex": search, "$options": "i"}}, {"city": {"$regex": search, "$options": "i"}}, {"country": {"$regex": search, "$options": "i"}}, {"notes": {"$regex": search, "$options": "i"}}]
    if country:
        query["country"] = {"$regex": country, "$options": "i"}
    if source:
        query["source"] = source
    logs = await db.ip_logs.find(query, {"_id": 0}).sort("timestamp", -1).skip(offset).limit(limit).to_list(limit)
    for log in logs:
        if isinstance(log.get('timestamp'), str):
            log['timestamp'] = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
    return logs

@api_router.post("/logs", response_model=IPLog)
async def create_log(input: IPLogCreate):
    geo = await get_geo_info(input.ip)
    log = IPLog(ip=input.ip, country=geo["country"], city=geo["city"], region=geo["region"], isp=geo["isp"], notes=input.notes, source="manual")
    doc = log.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.ip_logs.insert_one(doc)
    return log

@api_router.post("/track")
async def track_api(request: Request):
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    referrer = request.headers.get("referer", "")
    geo = await get_geo_info(ip)
    ua_info = parse_user_agent(user_agent)
    log = IPLog(ip=ip, country=geo["country"], city=geo["city"], region=geo["region"], isp=geo["isp"], user_agent=user_agent, browser=ua_info["browser"], os=ua_info["os"], device=ua_info["device"], referrer=referrer, source="api")
    doc = log.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.ip_logs.insert_one(doc)
    return {"status": "logged", "id": log.id}

@api_router.get("/track/rickroll")
async def tracking_rickroll(request: Request):
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    referrer = request.headers.get("referer", "")
    geo = await get_geo_info(ip)
    ua_info = parse_user_agent(user_agent)
    log = IPLog(ip=ip, country=geo["country"], city=geo["city"], region=geo["region"], isp=geo["isp"], user_agent=user_agent, browser=ua_info["browser"], os=ua_info["os"], device=ua_info["device"], referrer=referrer, source="rickroll", notes="Got Rick Rolled!")
    doc = log.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.ip_logs.insert_one(doc)
    return RedirectResponse(url="https://tinyurl.com/3tn73uwb", status_code=302)

@api_router.get("/track/redirect")
async def tracking_redirect(request: Request, url: str = "https://tinyurl.com/3tn73uwb"):
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    referrer = request.headers.get("referer", "")
    geo = await get_geo_info(ip)
    ua_info = parse_user_agent(user_agent)
    log = IPLog(ip=ip, country=geo["country"], city=geo["city"], region=geo["region"], isp=geo["isp"], user_agent=user_agent, browser=ua_info["browser"], os=ua_info["os"], device=ua_info["device"], referrer=referrer, source="redirect", notes=f"Redirected to: {url[:50]}")
    doc = log.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.ip_logs.insert_one(doc)
    return RedirectResponse(url=url, status_code=302)

@api_router.get("/track/pixel.gif")
async def tracking_pixel(request: Request):
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    referrer = request.headers.get("referer", "")
    geo = await get_geo_info(ip)
    ua_info = parse_user_agent(user_agent)
    log = IPLog(ip=ip, country=geo["country"], city=geo["city"], region=geo["region"], isp=geo["isp"], user_agent=user_agent, browser=ua_info["browser"], os=ua_info["os"], device=ua_info["device"], referrer=referrer, source="pixel")
    doc = log.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.ip_logs.insert_one(doc)
    return Response(content=TRACKING_PIXEL, media_type="image/gif", headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache", "Expires": "0"})

@api_router.get("/stats")
async def get_stats():
    total_logs = await db.ip_logs.count_documents({})
    unique_ips = len(await db.ip_logs.distinct("ip"))
    countries = await db.ip_logs.aggregate([{"$group": {"_id": "$country", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}, {"$limit": 10}]).to_list(10)
    countries = [{"name": c["_id"] or "Unknown", "count": c["count"]} for c in countries]
    browsers = await db.ip_logs.aggregate([{"$group": {"_id": "$browser", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}, {"$limit": 5}]).to_list(5)
    browsers = [{"name": b["_id"] or "Unknown", "count": b["count"]} for b in browsers]
    devices = await db.ip_logs.aggregate([{"$group": {"_id": "$device", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}]).to_list(10)
    devices = [{"name": d["_id"] or "Unknown", "count": d["count"]} for d in devices]
    seven_days_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    daily = await db.ip_logs.aggregate([{"$match": {"timestamp": {"$gte": seven_days_ago}}}, {"$addFields": {"date": {"$substr": ["$timestamp", 0, 10]}}}, {"$group": {"_id": "$date", "count": {"$sum": 1}}}, {"$sort": {"_id": 1}}]).to_list(7)
    daily_activity = [{"date": d["_id"], "count": d["count"]} for d in daily]
    recent = await db.ip_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(5).to_list(5)
    return {"total_logs": total_logs, "unique_ips": unique_ips, "countries": countries, "browsers": browsers, "devices": devices, "hourly_activity": [], "daily_activity": daily_activity, "recent_logs": recent}

@api_router.get("/export")
async def export_logs(format: str = Query("json", regex="^(json|csv)$"), limit: int = Query(1000, ge=1, le=10000)):
    logs = await db.ip_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit).to_list(limit)
    if format == "csv":
        output = io.StringIO()
        if logs:
            writer = csv.DictWriter(output, fieldnames=logs[0].keys())
            writer.writeheader()
            writer.writerows(logs)
        return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=ip_logs.csv"})
    else:
        return StreamingResponse(iter([json.dumps(logs, indent=2, default=str)]), media_type="application/json", headers={"Content-Disposition": "attachment; filename=ip_logs.json"})

@api_router.delete("/logs/{log_id}")
async def delete_log(log_id: str):
    result = await db.ip_logs.delete_one({"id": log_id})
    if result.deleted_count == 0:
        return {"error": "Log not found"}
    return {"status": "deleted"}

@api_router.delete("/logs")
async def clear_logs():
    result = await db.ip_logs.delete_many({})
    return {"status": "cleared", "count": result.deleted_count}

app.include_router(api_router)
app.add_middleware(CORSMiddleware, allow_credentials=True, allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','), allow_methods=["*"], allow_headers=["*"])
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8001))
    uvicorn.run(app, host="0.0.0.0", port=port)
