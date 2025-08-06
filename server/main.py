from fastapi import FastAPI, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import re

# Detectors
from utils.detectors.sql_injection import detect_sql_injection
from utils.detectors.path_traversal import detect_path_traversal
from utils.detectors.bot import detect_bots
from utils.detectors.lfi_rfi import detect_lfi_rfi
from utils.detectors.wp_probe import detect_wp_probe
from utils.detectors.brute_force import detect_brute_force
from utils.detectors.errors import detect_errors
from utils.detectors.internal_ip import detect_internal_ip

app = FastAPI()

# === CORS ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Shared log parser ===
log_pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<timestamp>.*?)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)" '
    r'(?P<host>\S+) (?P<server_ip>\S+)'
)

def parse_log_file(content: bytes) -> pd.DataFrame:
    lines = content.decode('utf-8', errors='ignore').splitlines()
    parsed = [match.groupdict() for line in lines if (match := log_pattern.match(line))]

    df = pd.DataFrame(parsed)

    if df.empty:
        return df

    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
    df['bytes'] = pd.to_numeric(df['bytes'].replace('-', '0'), errors='coerce')
    return df

# === Helper for response slicing ===
def build_response(df: pd.DataFrame, limit: int, offset: int):
    total = len(df)
    sliced = df.iloc[offset:offset + limit]
    return {
        "count": total,
        "is_more": offset + limit < total,
        "results": sliced.to_dict(orient="list")
    }

# === Endpoints ===

@app.post("/api/scan/sql-injection")
async def sql_injection_scan(
    file: UploadFile = File(...),
    limit: int = Query(500, ge=1),
    offset: int = Query(0, ge=0)
):
    df = parse_log_file(await file.read())
    result = detect_sql_injection(df)
    return build_response(result, limit, offset)


@app.post("/api/scan/path-traversal")
async def path_traversal_scan(
    file: UploadFile = File(...),
    limit: int = Query(500, ge=1),
    offset: int = Query(0, ge=0)
):
    df = parse_log_file(await file.read())
    result = detect_path_traversal(df)
    return build_response(result, limit, offset)


@app.post("/api/scan/bots")
async def bot_scan(
    file: UploadFile = File(...),
    limit: int = Query(500, ge=1),
    offset: int = Query(0, ge=0)
):
    df = parse_log_file(await file.read())
    result = detect_bots(df)
    return build_response(result, limit, offset)


@app.post("/api/scan/lfi-rfi")
async def lfi_rfi_scan(
    file: UploadFile = File(...),
    limit: int = Query(500, ge=1),
    offset: int = Query(0, ge=0)
):
    df = parse_log_file(await file.read())
    result = detect_lfi_rfi(df)
    return build_response(result, limit, offset)


@app.post("/api/scan/wp-probe")
async def wp_probe_scan(
    file: UploadFile = File(...),
    limit: int = Query(500, ge=1),
    offset: int = Query(0, ge=0)
):
    df = parse_log_file(await file.read())
    result = detect_wp_probe(df)
    return build_response(result, limit, offset)


@app.post("/api/scan/brute-force")
async def brute_force_scan(
    file: UploadFile = File(...),
    limit: int = Query(500, ge=1),
    offset: int = Query(0, ge=0)
):
    df = parse_log_file(await file.read())
    result = detect_brute_force(df)
    return build_response(result, limit, offset)


@app.post("/api/scan/errors")
async def error_scan(
    file: UploadFile = File(...),
    limit: int = Query(500, ge=1),
    offset: int = Query(0, ge=0)
):
    df = parse_log_file(await file.read())
    result = detect_errors(df)
    return build_response(result, limit, offset)


@app.post("/api/scan/internal-ip")
async def internal_ip_scan(
    file: UploadFile = File(...),
    limit: int = Query(500, ge=1),
    offset: int = Query(0, ge=0)
):
    df = parse_log_file(await file.read())
    result = detect_internal_ip(df)
    return build_response(result, limit, offset)

# === Dev runner ===
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=6969, reload=True)
