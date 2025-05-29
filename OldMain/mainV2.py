from fastapi import FastAPI, Security, HTTPException, Depends, Request
from fastapi.security.api_key import APIKeyHeader
from starlette.status import HTTP_403_FORBIDDEN
import settings  # Asegurate de tener este archivo correctamente configurado

app = FastAPI()

# Dependencia: API Key en encabezado
api_key_header = APIKeyHeader(name=settings.API_KEY_NAME, auto_error=False)

def get_api_key(api_key: str = Depends(api_key_header)):
    if api_key == settings.API_KEY:
        return api_key
    raise HTTPException(
        status_code=HTTP_403_FORBIDDEN,
        detail="API Key inválida"
    )

# Dependencia: Verificación de IP origen
def verify_ip(request: Request):
    client_ip = request.client.host
    if client_ip not in settings.ALLOWED_IPS:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail=f"Acceso denegado desde IP: {client_ip}"
        )
    return client_ip

# Ruta pública (sin protección)
@app.get("/public")
def public_route():
    return {"mensaje": "Acceso público"}

# Ruta privada protegida solo por API Key
@app.get("/private")
def private_route(api_key: str = Depends(get_api_key)):
    return {"mensaje": "Acceso con API Key autorizada"}

# Ruta segura con verificación por IP y API Key
@app.get("/secure-data")
def secure_data(
    ip_ok: str = Depends(verify_ip),
    api_key: str = Depends(get_api_key)
):
    return {
        "mensaje": "Acceso concedido con IP válida y API Key correcta",
        "ip_origen": ip_ok
    }
