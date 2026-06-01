from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv
import httpx, ipaddress, os

def validate_public_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Validate that the input is a real, public IP. Raises HTTPException(400) on failure."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"'{ip}' is not a valid IP address",
        )

    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
    ):
        raise HTTPException(
            status_code=400,
            detail=f"'{ip}' is not a public, routable IP address",
        )

    return addr

load_dotenv()   # Load .env into os.environ at startup (local dev only; no-op in Docker

app = FastAPI()

@app.get("/healthz")
def health():
    return {"status": "ok"}


@app.get("/api/shodan/{ip}")
async def shodan_lookup(ip: str):
    validate_public_ip(ip)    # raises 400 if invalid or non-public; safe to proceed otherwise
    
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Could not reach Shodan")

    if response.status_code == 404:
        return {"ip": ip, "found": False, "data": None}
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="Shodan returned an error")

    return {"ip": ip, "found": True, "data": response.json()}

@app.get("/api/abuseipdb/{ip}")
async def abuseipdb_lookup(ip: str):
    validate_public_ip(ip)   # reuses TC-3's helper — DRY in action

    api_key = os.environ.get("ABUSEIPDB_KEY")
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="ABUSEIPDB_KEY is not configured on the server",
        )

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers=headers, params=params)
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Could not reach AbuseIPDB")

    if response.status_code in (401, 403):
        raise HTTPException(status_code=500, detail="AbuseIPDB authentication failed")
    if response.status_code == 429:
        raise HTTPException(status_code=502, detail="AbuseIPDB rate limit reached")
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="AbuseIPDB returned an error")

    return {"ip": ip, "data": response.json().get("data", {})}

