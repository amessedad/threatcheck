from fastapi import FastAPI, HTTPException
import httpx

app = FastAPI()

@app.get("/healthz")
def health():
    return {"status": "ok"}


@app.get("/api/shodan/{ip}")
async def shodan_lookup(ip: str):
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