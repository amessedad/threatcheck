from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv
import httpx, ipaddress, os,asyncio

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

async def fetch_shodan(ip: str) -> dict:
    """Query Shodan InternetDB. Returns {"found": bool, "data": dict | None}.
    Raises HTTPException on transport or unexpected upstream errors."""
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Could not reach Shodan")

    if response.status_code == 404:
        return {"found": False, "data": None}
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="Shodan returned an error")

    return {"found": True, "data": response.json()}


async def fetch_abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB. Returns the source-specific data dict.
    Raises HTTPException on transport, auth, or rate-limit failures."""
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

    return response.json().get("data", {})

async def fetch_virustotal(ip: str) -> dict:
    """Query VirusTotal v3 for an IP. Returns {"found": bool, "data": dict | None}.
    Raises HTTPException on transport, auth, or rate-limit failures."""
    api_key = os.environ.get("VIRUSTOTAL_KEY")
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="VIRUSTOTAL_KEY is not configured on the server",
        )

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers=headers)
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Could not reach VirusTotal")

    if response.status_code in (401, 403):
        raise HTTPException(status_code=500, detail="VirusTotal authentication failed")
    if response.status_code == 404:
        return {"found": False, "data": None}
    if response.status_code == 429:
        raise HTTPException(status_code=502, detail="VirusTotal rate limit reached")
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="VirusTotal returned an error")

    return {"found": True, "data": response.json().get("data", {}).get("attributes", {})}

app = FastAPI()

@app.get("/healthz")
def health():
    return {"status": "ok"}


@app.get("/api/shodan/{ip}")
async def shodan_lookup(ip: str):
    validate_public_ip(ip)    # raises 400 if invalid or non-public; safe to proceed otherwise
    result = await fetch_shodan(ip)
    return {"ip": ip, **result}
    
    
@app.get("/api/abuseipdb/{ip}")
async def abuseipdb_lookup(ip: str):
    validate_public_ip(ip)   # reuses TC-3's helper — DRY in action
    data = await fetch_abuseipdb(ip)
    return {"ip": ip, "data": data}

@app.get("/api/virustotal/{ip}")
async def virustotal_lookup(ip: str):
    validate_public_ip(ip)
    result = await fetch_virustotal(ip)
    return {"ip": ip, **result}
@app.get("/api/lookup/{indicator}")
async def unified_lookup(indicator: str):
    addr = validate_public_ip(indicator)
    ioc_type = "ipv4" if isinstance(addr, ipaddress.IPv4Address) else "ipv6"

    shodan_result, abuseipdb_result, virustotal_result = await asyncio.gather(
        fetch_shodan(indicator),
        fetch_abuseipdb(indicator),
        fetch_virustotal(indicator),
        return_exceptions=True,
    )

    def shape(result):
        if isinstance(result, Exception):
            return {"status": "error", "error": getattr(result, "detail", str(result))}
        return {"status": "ok", "result": result}

    return {
        "indicator": indicator,
        "type": ioc_type,
        "sources": {
            "shodan": shape(shodan_result),
            "abuseipdb": shape(abuseipdb_result),
            "virustotal": shape(virustotal_result),
        },
    }
    
@app.get("/api/lookup/{indicator}")
async def unified_lookup(indicator: str):
    addr = validate_public_ip(indicator)
    ioc_type = "ipv4" if isinstance(addr, ipaddress.IPv4Address) else "ipv6"

    shodan_result, abuseipdb_result = await asyncio.gather(
        fetch_shodan(indicator),
        fetch_abuseipdb(indicator),
        return_exceptions=True,
    )

    def shape(result):
        if isinstance(result, Exception):
            return {"status": "error", "error": getattr(result, "detail", str(result))}
        return {"status": "ok", "result": result}

    return {
        "indicator": indicator,
        "type": ioc_type,
        "sources": {
            "shodan": shape(shodan_result),
            "abuseipdb": shape(abuseipdb_result),
        },
    }





