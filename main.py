import os
import subprocess
import tempfile
import logging
import httpx

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="kubeseal-ui", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory="templates")

CONTROLLER_URL = os.getenv(
    "SEALED_SECRETS_CONTROLLER_URL",
    "http://sealed-secrets-controller.sealed-secrets.svc.cluster.local:8080/v1/cert.pem",
)
LOCAL_CERT_PATH = os.getenv("LOCAL_CERT_PATH", "")

_cert_cache: str | None = None


async def get_cert() -> str:
    global _cert_cache
    if _cert_cache:
        return _cert_cache

    if LOCAL_CERT_PATH and os.path.exists(LOCAL_CERT_PATH):
        with open(LOCAL_CERT_PATH) as f:
            _cert_cache = f.read()
        logger.info("Loaded cert from local file %s", LOCAL_CERT_PATH)
        return _cert_cache

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(CONTROLLER_URL)
        resp.raise_for_status()
        _cert_cache = resp.text
        logger.info("Fetched cert from controller")
        return _cert_cache


def seal_value(value: str, namespace: str, name: str, cert_path: str) -> str:
    result = subprocess.run(
        [
            "kubeseal", "--raw",
            "--namespace", namespace,
            "--name", name,
            "--cert", cert_path,
            "--from-file", "/dev/stdin",
        ],
        input=value,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise ValueError(result.stderr.strip())
    return result.stdout.strip()


class Entry(BaseModel):
    key: str
    value: str


class EncryptRequest(BaseModel):
    namespace: str
    name: str
    entries: list[Entry]


class EncryptResponse(BaseModel):
    encrypted: dict[str, str]


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/encrypt", response_model=EncryptResponse)
async def encrypt(payload: EncryptRequest):
    if not payload.namespace.strip():
        raise HTTPException(status_code=400, detail="namespace is empty")
    if not payload.name.strip():
        raise HTTPException(status_code=400, detail="name is empty")
    if not payload.entries:
        raise HTTPException(status_code=400, detail="entries list is empty")
    for e in payload.entries:
        if not e.key.strip():
            raise HTTPException(status_code=400, detail="key name cannot be empty")
        if not e.value:
            raise HTTPException(status_code=400, detail=f"value for key '{e.key}' is empty")

    try:
        cert_pem = await get_cert()
    except Exception as e:
        logger.error("Failed to fetch cert: %s", e)
        raise HTTPException(status_code=502, detail=f"Cannot reach sealed-secrets controller: {e}")

    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False, mode="w") as cert_file:
        cert_file.write(cert_pem)
        cert_path = cert_file.name

    try:
        result: dict[str, str] = {}
        for entry in payload.entries:
            try:
                result[entry.key] = seal_value(entry.value, payload.namespace, payload.name, cert_path)
            except ValueError as e:
                raise HTTPException(status_code=422, detail=f"Error encrypting '{entry.key}': {e}")
        return EncryptResponse(encrypted=result)
    finally:
        os.unlink(cert_path)


@app.delete("/cert-cache")
async def clear_cert_cache():
    global _cert_cache
    _cert_cache = None
    return {"status": "cert cache cleared"}
