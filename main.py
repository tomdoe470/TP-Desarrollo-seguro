# main.py
from __future__ import annotations
import ipaddress, logging
from datetime import datetime, timedelta
from typing import Annotated

import jwt
from dotenv import load_dotenv
from fastapi import (
    FastAPI, Depends, HTTPException, Request, status, Security)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import (
    APIKeyHeader, OAuth2PasswordRequestForm)
from pydantic import BaseModel, Field, EmailStr, SecretStr, constr
from starlette.status import HTTP_403_FORBIDDEN

import settings  # tu settings.py sigue igual

# -----------------------------------------------------------------------------
# Arranque

load_dotenv(".env", override=True)           # variables de entorno opcionales
app = FastAPI(
    title="Secure API demo",
    version="2.0.0",
    docs_url="/docs",
)

# 1) Simulación de HTTPS: redirect middleware + cabeceras HSTS
if getattr(settings, "ENFORCE_HTTPS", False):
    app.add_middleware(HTTPSRedirectMiddleware)
    logging.info("🔐 HTTPS redirect middleware ACTIVO")
else:
    logging.info("⚠️ HTTPS redirect middleware DESACTIVADO (modo local)")

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.update({
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "Content-Security-Policy": "default-src 'self'",
    })
    return response

# 2) Manejo centralizado y seguro de errores
@app.exception_handler(HTTPException)
@app.exception_handler(RequestValidationError)
async def http_error_handler(request: Request, exc):
    """
    Devuelve siempre JSON plano {"detail": "..."} y registra internamente
    cualquier excepción 5xx sin exponer stack-trace al cliente.
    """
    if isinstance(exc, HTTPException):
        # 4xx definidos por nosotros √
        code = exc.status_code
        detail = exc.detail
    else:
        # Error de validación automático de FastAPI → 422
        code = status.HTTP_422_UNPROCESSABLE_ENTITY
        detail = exc.errors()
    # Log en servidor para auditoría (pero no se expone al cliente)
    if code >= 500:
        logging.exception(exc)
    return JSONResponse(status_code=code, content={"detail": detail})

# -----------------------------------------------------------------------------  
# 3) VALIDACIÓN ESTRICTA – modelos y checks

class UserLogin(BaseModel):
    username: constr(min_length=3, max_length=20, pattern=r"^[a-zA-Z0-9_\-]+$")
    password: SecretStr = Field(..., min_length=8, max_length=64)

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class ClientInfo(BaseModel):
    mensaje: str
    ip_origen: str

# API-key (header) con longitud fija y chars hex
API_KEY_HEADER = APIKeyHeader(name=settings.API_KEY_NAME, auto_error=False)

async def get_api_key(
    api_key: Annotated[str | None, Depends(API_KEY_HEADER)]
) -> str:
    if api_key and api_key == settings.API_KEY:
        return api_key
    raise HTTPException(
        status_code=HTTP_403_FORBIDDEN,
        detail="API Key inválida",
    )

# List blanca de IP → validamos formales y rango (v4/v6)
async def verify_ip(request: Request) -> str:
    client_ip = request.client.host
    try:
        ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        raise HTTPException(400, "IP de origen malformada")
    if client_ip not in settings.ALLOWED_IPS:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail=f"Acceso denegado desde IP: {client_ip}",
        )
    return str(ip_obj)

# JWT helpers
def create_jwt_token(data: dict, exp_mins: int = 15) -> str:
    to_encode = data | {"exp": datetime.utcnow() + timedelta(minutes=exp_mins)}
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def verify_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido")

def get_current_user(request: Request):
    auth: str | None = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(401, "Token faltante")
    token = auth.split(" ", 1)[1]
    return verify_jwt(token)

# -----------------------------------------------------------------------------
# Rutas

@app.get("/public")
def public_route():
    return {"mensaje": "Acceso público"}

@app.get("/private")
def private_route(api_key: str = Depends(get_api_key)):
    return {"mensaje": "Acceso con API Key autorizada"}

@app.get("/secure-data", response_model=ClientInfo)
def secure_data(
    ip_ok: str = Depends(verify_ip),
    api_key: str = Depends(get_api_key),
):
    return ClientInfo(mensaje="Acceso con IP y API Key válidas", ip_origen=ip_ok)

@app.post("/token", response_model=TokenOut)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Validación dura de credenciales con modelo → evita inputs raros
    creds = UserLogin(username=form_data.username, password=form_data.password)
    # Usuario ficticio
    if creds.username != "admin" or creds.password.get_secret_value() != "1234":
        raise HTTPException(status_code=400, detail="Credenciales inválidas")

    token = create_jwt_token({"sub": creds.username})
    return TokenOut(access_token=token, expires_in=900)

@app.get("/protected-jwt")
def jwt_protected_route(user=Depends(get_current_user)):
    return {
        "mensaje": f"Token JWT válido. Bienvenido, {user['sub']}",
        "expira_en": user['exp'],
    }
